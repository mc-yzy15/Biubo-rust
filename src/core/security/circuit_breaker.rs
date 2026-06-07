use std::collections::HashMap;
use std::time::Instant;

use parking_lot::Mutex;

/// Types of external services that can be protected by the circuit breaker.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
pub enum ServiceKind {
    /// Large Language Model service (e.g. API calls to an LLM provider).
    Llm,
    /// Reputation / IP quality provider (e.g. VirusTotal, AbuseIPDB).
    Reputation,
}

/// The current state of a circuit breaker for a given service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitBreakerState {
    /// Normal operation -- requests pass through, failures are counted.
    Closed,
    /// Circuit is tripped -- requests are rejected immediately.
    Open,
    /// Recovery mode -- a limited number of probe requests are allowed
    /// to verify whether the downstream service has recovered.
    HalfOpen,
}

/// Configuration parameters for the circuit breaker.
///
/// # Defaults
///
/// | Field                   | Default | Description                              |
/// |-------------------------|---------|------------------------------------------|
/// | `failure_threshold`     | `5`     | Consecutive failures before the circuit opens. |
/// | `recovery_timeout_secs` | `30`    | Seconds to wait before transitioning from Open to Half-Open. |
/// | `half_open_max_requests`| `3`     | Maximum probe requests allowed in Half-Open. |
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures after which the circuit opens.
    pub failure_threshold: u64,
    /// Seconds to wait before transitioning from Open to Half-Open.
    pub recovery_timeout_secs: u64,
    /// Maximum number of requests allowed in the Half-Open state.
    pub half_open_max_requests: u64,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            recovery_timeout_secs: 30,
            half_open_max_requests: 3,
        }
    }
}

// ---------------------------------------------------------------------------
// Internal per-service state
// ---------------------------------------------------------------------------

struct ServiceState {
    state: CircuitBreakerState,
    failure_count: u64,
    last_failure_time: Option<Instant>,
    half_open_requests: u64,
}

impl ServiceState {
    fn fresh() -> Self {
        Self {
            state: CircuitBreakerState::Closed,
            failure_count: 0,
            last_failure_time: None,
            half_open_requests: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitBreaker
// ---------------------------------------------------------------------------

/// A thread-safe circuit breaker that protects external service calls.
///
/// The circuit breaker follows the standard three-state pattern:
///
/// * **Closed** -- Normal operation.  Failures are counted; when the count
///   reaches `failure_threshold` the circuit opens.
/// * **Open** -- Requests are rejected without calling the downstream
///   service.  After `recovery_timeout_secs` the circuit transitions to
///   Half-Open automatically (on the next `is_allowed` or `state` check).
/// * **Half-Open** -- A limited number of probe requests
///   (`half_open_max_requests`) are let through.  If any probe fails the
///   circuit re-opens immediately.  If all probes succeed the circuit
///   resets to Closed.
///
/// All public methods are thread-safe (the struct is `Send + Sync`).
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    services: Mutex<HashMap<ServiceKind, ServiceState>>,
}

impl CircuitBreaker {
    /// Creates a new `CircuitBreaker` with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            services: Mutex::new(HashMap::new()),
        }
    }

    /// Returns the current state for the given service.
    ///
    /// This method is re-entrant and may trigger a state transition from
    /// Open to Half-Open if the recovery timeout has elapsed.
    pub fn state(&self, service: ServiceKind) -> CircuitBreakerState {
        let mut services = self.services.lock();
        let entry = services.entry(service).or_insert_with(ServiceState::fresh);
        self.maybe_transition(service, entry);
        entry.state
    }

    /// Returns `true` if a request to the given service should be allowed
    /// to proceed.
    ///
    /// Behaviour per state:
    /// * **Closed** -- always returns `true`.
    /// * **Open** -- returns `false` unless the recovery timeout has elapsed,
    ///   in which case it transitions to Half-Open and allows the request.
    /// * **Half-Open** -- returns `true` if the number of concurrent probe
    ///   requests has not yet reached `half_open_max_requests`.
    pub fn is_allowed(&self, service: ServiceKind) -> bool {
        let mut services = self.services.lock();
        let entry = services.entry(service).or_insert_with(ServiceState::fresh);

        self.maybe_transition(service, entry);

        match entry.state {
            CircuitBreakerState::Closed => true,
            CircuitBreakerState::Open => false,
            CircuitBreakerState::HalfOpen => {
                if entry.half_open_requests < self.config.half_open_max_requests {
                    entry.half_open_requests += 1;
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Records a successful call for the given service.
    ///
    /// Resets the failure count and, if the circuit was Half-Open,
    /// transitions it back to Closed.
    pub fn record_success(&self, service: ServiceKind) {
        let mut services = self.services.lock();
        if let Some(entry) = services.get_mut(&service) {
            entry.failure_count = 0;
            entry.half_open_requests = 0;
            entry.last_failure_time = None;

            if entry.state == CircuitBreakerState::HalfOpen {
                tracing::info!(
                    "[CIRCUIT_BREAKER] {:?} recovered in HalfOpen, state -> Closed",
                    service
                );
                entry.state = CircuitBreakerState::Closed;
            }
        }
    }

    /// Records a failure for the given service.
    ///
    /// Increments the failure counter.  If the circuit is Closed and the
    /// counter reaches `failure_threshold`, it trips to Open.  If the
    /// circuit is Half-Open, it immediately re-opens.
    pub fn record_failure(&self, service: ServiceKind) {
        let mut services = self.services.lock();
        let entry = services.entry(service).or_insert_with(ServiceState::fresh);

        entry.failure_count += 1;
        entry.last_failure_time = Some(Instant::now());
        entry.half_open_requests = 0;

        if entry.state == CircuitBreakerState::HalfOpen {
            tracing::warn!(
                "[CIRCUIT_BREAKER] {:?} failed in HalfOpen, state -> Open",
                service
            );
            entry.state = CircuitBreakerState::Open;
        } else if entry.state == CircuitBreakerState::Closed
            && entry.failure_count >= self.config.failure_threshold
        {
            tracing::warn!(
                "[CIRCUIT_BREAKER] {:?} failure_count={} >= threshold={}, state -> Open",
                service,
                entry.failure_count,
                self.config.failure_threshold
            );
            entry.state = CircuitBreakerState::Open;
        }
    }

    /// Resets the circuit breaker for the given service back to Closed.
    ///
    /// All accumulated failure state is discarded.
    pub fn reset(&self, service: ServiceKind) {
        let mut services = self.services.lock();
        services.remove(&service);
        tracing::info!("[CIRCUIT_BREAKER] {:?} manually reset to Closed", service);
    }

    // -----------------------------------------------------------------------
    // Internal helpers
    // -----------------------------------------------------------------------

    /// Evaluates whether the circuit should transition from Open to
    /// Half-Open based on the recovery timeout.
    fn maybe_transition(&self, service: ServiceKind, entry: &mut ServiceState) {
        if entry.state == CircuitBreakerState::Open {
            if let Some(last_failure) = entry.last_failure_time {
                let elapsed = last_failure.elapsed().as_secs();
                if elapsed >= self.config.recovery_timeout_secs {
                    tracing::info!(
                        "[CIRCUIT_BREAKER] {:?} recovery timeout elapsed ({}s >= {}s), \
                         state -> HalfOpen",
                        service,
                        elapsed,
                        self.config.recovery_timeout_secs
                    );
                    entry.state = CircuitBreakerState::HalfOpen;
                    entry.half_open_requests = 0;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> CircuitBreakerConfig {
        CircuitBreakerConfig {
            failure_threshold: 3,
            recovery_timeout_secs: 30,
            half_open_max_requests: 2,
        }
    }

    #[test]
    fn test_initial_state_is_closed() {
        let cb = CircuitBreaker::new(config());
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Closed);
        assert_eq!(
            cb.state(ServiceKind::Reputation),
            CircuitBreakerState::Closed
        );
    }

    #[test]
    fn test_is_allowed_when_closed() {
        let cb = CircuitBreaker::new(config());
        assert!(cb.is_allowed(ServiceKind::Llm));
        assert!(cb.is_allowed(ServiceKind::Reputation));
    }

    #[test]
    fn test_trips_after_threshold_failures() {
        let cb = CircuitBreaker::new(config());

        // Two failures should not trip the breaker (threshold = 3).
        cb.record_failure(ServiceKind::Llm);
        cb.record_failure(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Closed);

        // Third failure trips it.
        cb.record_failure(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Open);
    }

    #[test]
    fn test_rejects_requests_when_open() {
        let cb = CircuitBreaker::new(config());

        // Trip the breaker.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Reputation);
        }
        assert_eq!(cb.state(ServiceKind::Reputation), CircuitBreakerState::Open);

        // Requests should be rejected.
        assert!(!cb.is_allowed(ServiceKind::Reputation));
    }

    #[test]
    fn test_success_resets_failure_count() {
        let cb = CircuitBreaker::new(config());

        cb.record_failure(ServiceKind::Llm);
        cb.record_failure(ServiceKind::Llm);
        cb.record_success(ServiceKind::Llm);
        // One more failure should not trip (threshold = 3, but success reset the count).
        cb.record_failure(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Closed);

        // Two more failures -> total of 3 since the success reset.
        cb.record_failure(ServiceKind::Llm);
        cb.record_failure(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Open);
    }

    #[test]
    fn test_half_open_allows_limited_requests() {
        let cb = CircuitBreaker::new(config());

        // Trip the breaker.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Llm);
        }

        // Manually force to HalfOpen for testing (simulate timeout).
        {
            let mut services = cb.services.lock();
            if let Some(entry) = services.get_mut(&ServiceKind::Llm) {
                entry.state = CircuitBreakerState::HalfOpen;
                entry.half_open_requests = 0;
            }
        }

        // Should allow up to half_open_max_requests (2) probes.
        assert!(cb.is_allowed(ServiceKind::Llm));
        assert!(cb.is_allowed(ServiceKind::Llm));
        // Third request should be denied.
        assert!(!cb.is_allowed(ServiceKind::Llm));
    }

    #[test]
    fn test_half_open_failure_reopens() {
        let cb = CircuitBreaker::new(config());

        // Trip the breaker.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Llm);
        }

        // Manually force to HalfOpen.
        {
            let mut services = cb.services.lock();
            if let Some(entry) = services.get_mut(&ServiceKind::Llm) {
                entry.state = CircuitBreakerState::HalfOpen;
                entry.half_open_requests = 0;
            }
        }

        // Failure in HalfOpen should immediately re-open.
        cb.record_failure(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Open);
    }

    #[test]
    fn test_half_open_success_recovers() {
        let cb = CircuitBreaker::new(config());

        // Trip the breaker.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Llm);
        }

        // Manually force to HalfOpen.
        {
            let mut services = cb.services.lock();
            if let Some(entry) = services.get_mut(&ServiceKind::Llm) {
                entry.state = CircuitBreakerState::HalfOpen;
                entry.half_open_requests = 0;
            }
        }

        // Success in HalfOpen should recover to Closed.
        cb.record_success(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Closed);
        assert!(cb.is_allowed(ServiceKind::Llm));
    }

    #[test]
    fn test_reset_clears_state() {
        let cb = CircuitBreaker::new(config());

        // Trip the breaker.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Llm);
        }
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Open);

        // Reset should bring it back to Closed.
        cb.reset(ServiceKind::Llm);
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Closed);
        assert!(cb.is_allowed(ServiceKind::Llm));
    }

    #[test]
    fn test_services_are_independent() {
        let cb = CircuitBreaker::new(config());

        // Trip only Llm.
        for _ in 0..3 {
            cb.record_failure(ServiceKind::Llm);
        }
        assert_eq!(cb.state(ServiceKind::Llm), CircuitBreakerState::Open);
        assert_eq!(
            cb.state(ServiceKind::Reputation),
            CircuitBreakerState::Closed
        );

        // Reputation should still accept requests.
        assert!(cb.is_allowed(ServiceKind::Reputation));
        assert!(!cb.is_allowed(ServiceKind::Llm));
    }
}
