use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::LazyLock;
use std::time::Duration;

/// Core metrics for Biubo WAF performance monitoring.
///
/// All counters use `Ordering::Relaxed` for maximum performance -
/// exact precision across threads is not required for observability.
pub struct Metrics {
    // ── Request counters ──
    pub requests_total: AtomicU64,
    pub requests_blocked: AtomicU64,
    pub requests_passed: AtomicU64,
    pub requests_challenged: AtomicU64,

    // ── LLM counters ──
    pub llm_calls_total: AtomicU64,
    pub llm_calls_tier1: AtomicU64,
    pub llm_calls_tier2: AtomicU64,
    pub llm_tokens_total: AtomicU64,
    pub llm_cache_hits: AtomicU64,
    pub llm_cache_misses: AtomicU64,
    pub llm_dedup_hits: AtomicU64,

    // ── WAF counters ──
    pub waf_regex_matches: AtomicU64,
    pub waf_cache_hits: AtomicU64,
    pub waf_cache_misses: AtomicU64,

    // ── Storage counters ──
    pub db_write_ops: AtomicU64,
    pub db_read_ops: AtomicU64,

    // ── Security counters ──
    pub rate_limit_triggers: AtomicU64,
    pub challenge_tokens_issued: AtomicU64,
    pub challenge_tokens_verified: AtomicU64,
    pub reputation_checks: AtomicU64,
    pub reputation_bans: AtomicU64,

    // ── Latency buckets (nanoseconds) ──
    // Each bucket tracks how many operations fell into that range.
    // Bucket boundaries: 0-1ms, 1-5ms, 5-10ms, 10-50ms, 50-200ms, 200ms+
    latency_buckets: [AtomicU64; 6],
}

impl Metrics {
    const fn new() -> Self {
        Self {
            requests_total: AtomicU64::new(0),
            requests_blocked: AtomicU64::new(0),
            requests_passed: AtomicU64::new(0),
            requests_challenged: AtomicU64::new(0),
            llm_calls_total: AtomicU64::new(0),
            llm_calls_tier1: AtomicU64::new(0),
            llm_calls_tier2: AtomicU64::new(0),
            llm_tokens_total: AtomicU64::new(0),
            llm_cache_hits: AtomicU64::new(0),
            llm_cache_misses: AtomicU64::new(0),
            llm_dedup_hits: AtomicU64::new(0),
            waf_regex_matches: AtomicU64::new(0),
            waf_cache_hits: AtomicU64::new(0),
            waf_cache_misses: AtomicU64::new(0),
            db_write_ops: AtomicU64::new(0),
            db_read_ops: AtomicU64::new(0),
            rate_limit_triggers: AtomicU64::new(0),
            challenge_tokens_issued: AtomicU64::new(0),
            challenge_tokens_verified: AtomicU64::new(0),
            reputation_checks: AtomicU64::new(0),
            reputation_bans: AtomicU64::new(0),
            latency_buckets: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }

    /// Record a latency duration into the appropriate bucket.
    pub fn record_latency(&self, duration: Duration) {
        let nanos = duration.as_nanos() as u64;
        let bucket = if nanos < 1_000_000 {
            // < 1ms
            0
        } else if nanos < 5_000_000 {
            // 1-5ms
            1
        } else if nanos < 10_000_000 {
            // 5-10ms
            2
        } else if nanos < 50_000_000 {
            // 10-50ms
            3
        } else if nanos < 200_000_000 {
            // 50-200ms
            4
        } else {
            // 200ms+
            5
        };
        self.latency_buckets[bucket].fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of all counter values at a point in time.
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.load(Ordering::Relaxed),
            requests_blocked: self.requests_blocked.load(Ordering::Relaxed),
            requests_passed: self.requests_passed.load(Ordering::Relaxed),
            requests_challenged: self.requests_challenged.load(Ordering::Relaxed),
            llm_calls_total: self.llm_calls_total.load(Ordering::Relaxed),
            llm_calls_tier1: self.llm_calls_tier1.load(Ordering::Relaxed),
            llm_calls_tier2: self.llm_calls_tier2.load(Ordering::Relaxed),
            llm_tokens_total: self.llm_tokens_total.load(Ordering::Relaxed),
            llm_cache_hits: self.llm_cache_hits.load(Ordering::Relaxed),
            llm_cache_misses: self.llm_cache_misses.load(Ordering::Relaxed),
            llm_dedup_hits: self.llm_dedup_hits.load(Ordering::Relaxed),
            waf_regex_matches: self.waf_regex_matches.load(Ordering::Relaxed),
            waf_cache_hits: self.waf_cache_hits.load(Ordering::Relaxed),
            waf_cache_misses: self.waf_cache_misses.load(Ordering::Relaxed),
            db_write_ops: self.db_write_ops.load(Ordering::Relaxed),
            db_read_ops: self.db_read_ops.load(Ordering::Relaxed),
            rate_limit_triggers: self.rate_limit_triggers.load(Ordering::Relaxed),
            challenge_tokens_issued: self.challenge_tokens_issued.load(Ordering::Relaxed),
            challenge_tokens_verified: self.challenge_tokens_verified.load(Ordering::Relaxed),
            reputation_checks: self.reputation_checks.load(Ordering::Relaxed),
            reputation_bans: self.reputation_bans.load(Ordering::Relaxed),
            latency_buckets: [
                self.latency_buckets[0].load(Ordering::Relaxed),
                self.latency_buckets[1].load(Ordering::Relaxed),
                self.latency_buckets[2].load(Ordering::Relaxed),
                self.latency_buckets[3].load(Ordering::Relaxed),
                self.latency_buckets[4].load(Ordering::Relaxed),
                self.latency_buckets[5].load(Ordering::Relaxed),
            ],
        }
    }

    /// Export metrics in Prometheus text format.
    pub fn prometheus_output(&self) -> String {
        let snap = self.snapshot();
        let mut out = String::with_capacity(2048);

        // Help and type lines
        out.push_str("# HELP biubo_requests_total Total requests processed\n");
        out.push_str("# TYPE biubo_requests_total counter\n");
        out.push_str(&format!("biubo_requests_total {}\n", snap.requests_total));

        out.push_str("# HELP biubo_requests_blocked Total blocked requests\n");
        out.push_str("# TYPE biubo_requests_blocked counter\n");
        out.push_str(&format!("biubo_requests_blocked {}\n", snap.requests_blocked));

        out.push_str("# HELP biubo_requests_passed Total passed requests\n");
        out.push_str("# TYPE biubo_requests_passed counter\n");
        out.push_str(&format!("biubo_requests_passed {}\n", snap.requests_passed));

        out.push_str("# HELP biubo_requests_challenged Total challenged requests\n");
        out.push_str("# TYPE biubo_requests_challenged counter\n");
        out.push_str(&format!(
            "biubo_requests_challenged {}\n",
            snap.requests_challenged
        ));

        out.push_str("# HELP biubo_llm_calls_total Total LLM API calls\n");
        out.push_str("# TYPE biubo_llm_calls_total counter\n");
        out.push_str(&format!("biubo_llm_calls_total {}\n", snap.llm_calls_total));

        out.push_str("# HELP biubo_llm_calls_tier1 Total LLM tier-1 (quick) calls\n");
        out.push_str("# TYPE biubo_llm_calls_tier1 counter\n");
        out.push_str(&format!("biubo_llm_calls_tier1 {}\n", snap.llm_calls_tier1));

        out.push_str("# HELP biubo_llm_calls_tier2 Total LLM tier-2 (deep) calls\n");
        out.push_str("# TYPE biubo_llm_calls_tier2 counter\n");
        out.push_str(&format!("biubo_llm_calls_tier2 {}\n", snap.llm_calls_tier2));

        out.push_str("# HELP biubo_llm_tokens_total Total LLM tokens consumed\n");
        out.push_str("# TYPE biubo_llm_tokens_total counter\n");
        out.push_str(&format!("biubo_llm_tokens_total {}\n", snap.llm_tokens_total));

        out.push_str("# HELP biubo_llm_cache_hits LLM semantic cache hits\n");
        out.push_str("# TYPE biubo_llm_cache_hits counter\n");
        out.push_str(&format!(
            "biubo_llm_cache_hits {}\n",
            snap.llm_cache_hits
        ));

        out.push_str("# HELP biubo_llm_cache_misses LLM semantic cache misses\n");
        out.push_str("# TYPE biubo_llm_cache_misses counter\n");
        out.push_str(&format!(
            "biubo_llm_cache_misses {}\n",
            snap.llm_cache_misses
        ));

        out.push_str("# HELP biubo_llm_dedup_hits LLM in-flight dedup hits\n");
        out.push_str("# TYPE biubo_llm_dedup_hits counter\n");
        out.push_str(&format!(
            "biubo_llm_dedup_hits {}\n",
            snap.llm_dedup_hits
        ));

        out.push_str("# HELP biubo_waf_regex_matches WAF regex match count\n");
        out.push_str("# TYPE biubo_waf_regex_matches counter\n");
        out.push_str(&format!(
            "biubo_waf_regex_matches {}\n",
            snap.waf_regex_matches
        ));

        out.push_str("# HELP biubo_waf_cache_hits WAF detection cache hits\n");
        out.push_str("# TYPE biubo_waf_cache_hits counter\n");
        out.push_str(&format!(
            "biubo_waf_cache_hits {}\n",
            snap.waf_cache_hits
        ));

        out.push_str("# HELP biubo_waf_cache_misses WAF detection cache misses\n");
        out.push_str("# TYPE biubo_waf_cache_misses counter\n");
        out.push_str(&format!(
            "biubo_waf_cache_misses {}\n",
            snap.waf_cache_misses
        ));

        out.push_str("# HELP biubo_db_write_ops Database write operations\n");
        out.push_str("# TYPE biubo_db_write_ops counter\n");
        out.push_str(&format!("biubo_db_write_ops {}\n", snap.db_write_ops));

        out.push_str("# HELP biubo_db_read_ops Database read operations\n");
        out.push_str("# TYPE biubo_db_read_ops counter\n");
        out.push_str(&format!("biubo_db_read_ops {}\n", snap.db_read_ops));

        out.push_str("# HELP biubo_rate_limit_triggers Rate limit trigger count\n");
        out.push_str("# TYPE biubo_rate_limit_triggers counter\n");
        out.push_str(&format!(
            "biubo_rate_limit_triggers {}\n",
            snap.rate_limit_triggers
        ));

        out.push_str("# HELP biubo_challenge_tokens_issued Challenge tokens issued\n");
        out.push_str("# TYPE biubo_challenge_tokens_issued counter\n");
        out.push_str(&format!(
            "biubo_challenge_tokens_issued {}\n",
            snap.challenge_tokens_issued
        ));

        out.push_str(
            "# HELP biubo_challenge_tokens_verified Challenge tokens verified\n",
        );
        out.push_str("# TYPE biubo_challenge_tokens_verified counter\n");
        out.push_str(&format!(
            "biubo_challenge_tokens_verified {}\n",
            snap.challenge_tokens_verified
        ));

        out.push_str("# HELP biubo_reputation_checks Reputation checks performed\n");
        out.push_str("# TYPE biubo_reputation_checks counter\n");
        out.push_str(&format!(
            "biubo_reputation_checks {}\n",
            snap.reputation_checks
        ));

        out.push_str("# HELP biubo_reputation_bans IPs banned by reputation\n");
        out.push_str("# TYPE biubo_reputation_bans counter\n");
        out.push_str(&format!(
            "biubo_reputation_bans {}\n",
            snap.reputation_bans
        ));

        // Latency histogram
        out.push_str("# HELP biubo_request_latency_ns Request latency buckets (ns)\n");
        out.push_str("# TYPE biubo_request_latency_ns histogram\n");
        let bucket_upper = ["1ms", "5ms", "10ms", "50ms", "200ms", "+Inf"];
        for (i, bucket_name) in bucket_upper.iter().enumerate() {
            out.push_str(&format!(
                "biubo_request_latency_ns_bucket{{le=\"{}\"}} {}\n",
                bucket_name, snap.latency_buckets[i]
            ));
        }
        out.push_str(&format!(
            "biubo_request_latency_ns_total {}\n",
            snap.latency_buckets.iter().sum::<u64>()
        ));

        out
    }
}

/// Point-in-time snapshot of all metrics.
#[derive(Debug, Clone)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_blocked: u64,
    pub requests_passed: u64,
    pub requests_challenged: u64,
    pub llm_calls_total: u64,
    pub llm_calls_tier1: u64,
    pub llm_calls_tier2: u64,
    pub llm_tokens_total: u64,
    pub llm_cache_hits: u64,
    pub llm_cache_misses: u64,
    pub llm_dedup_hits: u64,
    pub waf_regex_matches: u64,
    pub waf_cache_hits: u64,
    pub waf_cache_misses: u64,
    pub db_write_ops: u64,
    pub db_read_ops: u64,
    pub rate_limit_triggers: u64,
    pub challenge_tokens_issued: u64,
    pub challenge_tokens_verified: u64,
    pub reputation_checks: u64,
    pub reputation_bans: u64,
    pub latency_buckets: [u64; 6],
}

/// Global metrics instance.
pub static METRICS: LazyLock<Metrics> = LazyLock::new(Metrics::new);

/// Convenience macro to record latency in a block scope.
///
/// Usage:
/// ```ignore
/// record_latency!("rate_limit", {
///     // ... operation ...
/// });
/// ```
#[macro_export]
macro_rules! record_latency {
    ($name:expr, $block:expr) => {{
        let _start = std::time::Instant::now();
        let _result = $block;
        $crate::core::metrics::METRICS.record_latency(_start.elapsed());
        _result
    }};
}
