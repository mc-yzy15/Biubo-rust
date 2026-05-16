#![cfg(feature = "behavior-profiling")]
#![allow(dead_code)]

#[cfg(feature = "behavior-profiling")]
use chrono::{DateTime, Duration, Utc};
#[cfg(feature = "behavior-profiling")]
use dashmap::DashMap;
#[cfg(feature = "behavior-profiling")]
use serde::{Deserialize, Serialize};
#[cfg(feature = "behavior-profiling")]
use std::collections::{HashSet, VecDeque};
#[cfg(feature = "behavior-profiling")]
use std::f64::consts::E;
#[cfg(feature = "behavior-profiling")]
use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "behavior-profiling")]
use std::sync::Arc;
#[cfg(feature = "behavior-profiling")]
use tokio::time::{interval, Duration as TokioDuration};
#[cfg(feature = "behavior-profiling")]
use tracing::{debug, info};

#[cfg(feature = "behavior-profiling")]
use crate::core::models::{BehaviorMetric, BehaviorProfile, BehaviorScore, BehaviorScoreBreakdown};

#[cfg(feature = "behavior-profiling")]
pub mod scoring;

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BehaviorProfilingConfig {
    pub enabled: bool,
    pub window_seconds: u64,
    pub profile_ttl_seconds: u64,
    pub gc_interval_seconds: u64,
    pub max_profiles: usize,
}

#[cfg(feature = "behavior-profiling")]
impl Default for BehaviorProfilingConfig {
    fn default() -> Self {
        BehaviorProfilingConfig {
            enabled: true,
            window_seconds: 300,
            profile_ttl_seconds: 3600,
            gc_interval_seconds: 600,
            max_profiles: 100000,
        }
    }
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone)]
pub struct RequestRecord {
    pub timestamp: DateTime<Utc>,
    pub url: String,
    pub status_code: u16,
    pub user_agent: String,
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug)]
pub struct IPBehaviorMetrics {
    pub requests: VecDeque<RequestRecord>,
    pub unique_paths: HashSet<String>,
    pub error_count: u64,
    pub user_agents: HashSet<String>,
    pub window_start: DateTime<Utc>,
}

#[cfg(feature = "behavior-profiling")]
impl IPBehaviorMetrics {
    fn new(now: DateTime<Utc>) -> Self {
        IPBehaviorMetrics {
            requests: VecDeque::new(),
            unique_paths: HashSet::new(),
            error_count: 0,
            user_agents: HashSet::new(),
            window_start: now,
        }
    }
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug)]
pub struct BehaviorMetricsCollector {
    metrics: DashMap<String, IPBehaviorMetrics>,
    config: BehaviorProfilingConfig,
    total_requests: AtomicU64,
}

#[cfg(feature = "behavior-profiling")]
impl BehaviorMetricsCollector {
    pub fn new(config: BehaviorProfilingConfig) -> Self {
        BehaviorMetricsCollector {
            metrics: DashMap::new(),
            config,
            total_requests: AtomicU64::new(0),
        }
    }

    pub fn track_request(&self, ip: &str, url: &str, status_code: u16, user_agent: &str) {
        let now = Utc::now();
        let record = RequestRecord {
            timestamp: now,
            url: url.to_string(),
            status_code,
            user_agent: user_agent.to_string(),
        };

        let mut ip_metrics = self
            .metrics
            .entry(ip.to_string())
            .or_insert_with(|| IPBehaviorMetrics::new(now));

        self.prune_old_requests(&mut ip_metrics.value_mut(), now);

        ip_metrics.value_mut().requests.push_back(record.clone());
        ip_metrics.value_mut().unique_paths.insert(url.to_string());
        ip_metrics
            .value_mut()
            .user_agents
            .insert(user_agent.to_string());

        if status_code >= 400 {
            ip_metrics.value_mut().error_count += 1;
        }

        self.total_requests.fetch_add(1, Ordering::Relaxed);

        if self.metrics.len() > self.config.max_profiles {
            self.evict_oldest_profile();
        }
    }

    pub fn get_metrics(&self, ip: &str) -> Option<IPBehaviorMetricsSnapshot> {
        let now = Utc::now();
        self.metrics.get(ip).map(|entry| {
            let metrics = entry.value();
            let mut snapshot = IPBehaviorMetricsSnapshot {
                request_count: 0,
                unique_paths: metrics.unique_paths.clone(),
                error_count: metrics.error_count,
                user_agents: metrics.user_agents.iter().cloned().collect(),
                window_start: metrics.window_start,
                requests_per_minute: 0.0,
                error_rate: 0.0,
            };

            let active_requests: Vec<_> = metrics
                .requests
                .iter()
                .filter(|r| {
                    now.signed_duration_since(r.timestamp).num_seconds()
                        <= self.config.window_seconds as i64
                })
                .cloned()
                .collect();

            snapshot.request_count = active_requests.len() as u64;

            let window_minutes = (self.config.window_seconds as f64) / 60.0;
            if window_minutes > 0.0 {
                snapshot.requests_per_minute = snapshot.request_count as f64 / window_minutes;
            }

            if snapshot.request_count > 0 {
                snapshot.error_rate = snapshot.error_count as f64 / snapshot.request_count as f64;
            }

            snapshot
        })
    }

    pub fn cleanup_expired_metrics(&self) -> usize {
        let now = Utc::now();
        let window = self.config.window_seconds;
        let mut expired_count = 0;

        self.metrics.retain(|_ip, metrics| {
            let has_recent = metrics
                .requests
                .iter()
                .any(|r| now.signed_duration_since(r.timestamp).num_seconds() <= window as i64);

            if !has_recent {
                expired_count += 1;
                false
            } else {
                true
            }
        });

        if expired_count > 0 {
            debug!("Cleaned up {} expired IP behavior metrics", expired_count);
        }

        expired_count
    }

    pub fn get_total_requests(&self) -> u64 {
        self.total_requests.load(Ordering::Relaxed)
    }

    pub fn get_active_ip_count(&self) -> usize {
        self.metrics.len()
    }

    fn prune_old_requests(&self, metrics: &mut IPBehaviorMetrics, now: DateTime<Utc>) {
        let cutoff = now - Duration::seconds(self.config.window_seconds as i64);
        while let Some(front) = metrics.requests.front() {
            if front.timestamp < cutoff {
                metrics.requests.pop_front();
            } else {
                break;
            }
        }

        if metrics.requests.is_empty() {
            metrics.unique_paths.clear();
            metrics.error_count = 0;
        }
    }

    fn evict_oldest_profile(&self) {
        let now = Utc::now();
        let mut oldest_ip = None;
        let mut oldest_time = now;

        for entry in self.metrics.iter() {
            if let Some(last_request) = entry.value().requests.back() {
                if last_request.timestamp < oldest_time {
                    oldest_time = last_request.timestamp;
                    oldest_ip = Some(entry.key().clone());
                }
            }
        }

        if let Some(ip) = oldest_ip {
            self.metrics.remove(&ip);
            debug!("Evicted oldest IP profile: {}", ip);
        }
    }
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone)]
pub struct IPBehaviorMetricsSnapshot {
    pub request_count: u64,
    pub unique_paths: HashSet<String>,
    pub error_count: u64,
    pub user_agents: Vec<String>,
    pub window_start: DateTime<Utc>,
    pub requests_per_minute: f64,
    pub error_rate: f64,
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug)]
pub struct BehaviorScoreEngine {
    collector: Arc<BehaviorMetricsCollector>,
    baseline_scores: DashMap<String, f64>,
    score_threshold_high: f64,
    score_threshold_medium: f64,
    decay_half_life_minutes: f64,
}

#[cfg(feature = "behavior-profiling")]
impl BehaviorScoreEngine {
    pub fn new(
        collector: Arc<BehaviorMetricsCollector>,
        threshold_high: f64,
        threshold_medium: f64,
        decay_half_life_minutes: f64,
    ) -> Self {
        BehaviorScoreEngine {
            collector,
            baseline_scores: DashMap::new(),
            score_threshold_high: threshold_high,
            score_threshold_medium: threshold_medium,
            decay_half_life_minutes: decay_half_life_minutes,
        }
    }

    pub fn compute_score(&self, ip: &str) -> BehaviorScore {
        let metrics = match self.collector.get_metrics(ip) {
            Some(m) => m,
            None => {
                return BehaviorScore {
                    ip: ip.to_string(),
                    score: 0.0,
                    velocity_score: 0.0,
                    diversity_score: 0.0,
                    error_rate_score: 0.0,
                    breakdown: BehaviorScoreBreakdown {
                        velocity_score: 0.0,
                        path_diversity_score: 0.0,
                        error_rate_score: 0.0,
                        session_consistency_score: 0.0,
                    },
                    factors: vec![],
                };
            }
        };

        let mut score = 0.0;
        let mut velocity_score = 0.0;
        let mut diversity_score: f64 = 0.0;
        let mut error_rate_score = 0.0;
        let mut factors = Vec::new();

        let unique_paths_count = metrics.unique_paths.len() as u64;

        if unique_paths_count > 30 && metrics.error_rate > 0.4 {
            diversity_score += 40.0;
            score += 40.0;
            factors.push(format!(
                "High path diversity ({} paths) with elevated 404 rate ({:.1}%)",
                unique_paths_count,
                metrics.error_rate * 100.0
            ));
        }

        if metrics.requests_per_minute > 50.0 {
            let velocity_component = ((metrics.requests_per_minute - 50.0) / 50.0) * 20.0;
            velocity_score += 20.0 + velocity_component.min(20.0);
            score += 20.0;
            factors.push(format!(
                "High request velocity: {:.1} requests/minute",
                metrics.requests_per_minute
            ));
        }

        if metrics.error_rate > 0.6 {
            let error_component = ((metrics.error_rate - 0.6) / 0.4) * 30.0;
            error_rate_score += 30.0 + error_component.min(20.0);
            score += 30.0;
            factors.push(format!(
                "Elevated error rate: {:.1}% of requests failed",
                metrics.error_rate * 100.0
            ));
        }

        if metrics.user_agents.len() > 3 {
            let ua_component = ((metrics.user_agents.len() - 3) as f64 / 5.0) * 20.0;
            score += 20.0 + ua_component.min(15.0);
            factors.push(format!(
                "Multiple user agents detected ({})",
                metrics.user_agents.len()
            ));
        }

        let baseline: f64 = self.baseline_scores.get(ip).map(|e| *e).unwrap_or(0.0);
        if score > baseline + 25.0 {
            let deviation = (score - baseline - 25.0) / 100.0;
            score += deviation * 15.0;
            factors.push(format!(
                "Statistical deviation from baseline (+{:.1} points)",
                deviation * 15.0
            ));
        }

        score = score.min(100.0);
        velocity_score = velocity_score.min(100.0);
        diversity_score = diversity_score.min(100.0);
        error_rate_score = error_rate_score.min(100.0);

        let final_score = self.apply_decay(ip, score);

        BehaviorScore {
            ip: ip.to_string(),
            score: final_score,
            velocity_score,
            diversity_score,
            error_rate_score,
            breakdown: BehaviorScoreBreakdown {
                velocity_score,
                path_diversity_score: diversity_score,
                error_rate_score,
                session_consistency_score: 0.0,
            },
            factors,
        }
    }

    pub fn update_baseline(&self, ip: &str, score: f64) {
        let alpha = 0.1;
        let current_baseline = self.baseline_scores.get(ip).map(|e| *e).unwrap_or(0.0);
        let new_baseline = current_baseline * (1.0 - alpha) + score * alpha;
        self.baseline_scores.insert(ip.to_string(), new_baseline);
    }

    pub fn get_risk_level(&self, score: &BehaviorScore) -> &'static str {
        if score.score >= self.score_threshold_high {
            "high"
        } else if score.score >= self.score_threshold_medium {
            "medium"
        } else {
            "low"
        }
    }

    fn apply_decay(&self, ip: &str, raw_score: f64) -> f64 {
        if raw_score <= 0.0 {
            return 0.0;
        }

        let now = Utc::now();
        let metrics = match self.collector.get_metrics(ip) {
            Some(m) => m,
            None => return 0.0,
        };

        let last_activity = metrics.window_start;
        let elapsed_minutes = now.signed_duration_since(last_activity).num_seconds() as f64 / 60.0;

        if elapsed_minutes <= 0.0 {
            return raw_score;
        }

        let decay_factor = E.powf(-elapsed_minutes / self.decay_half_life_minutes);
        let decayed_score = raw_score * decay_factor;

        debug!(
            "Score decay for {}: {:.1} -> {:.1} (elapsed: {:.1}min, factor: {:.3})",
            ip, raw_score, decayed_score, elapsed_minutes, decay_factor
        );

        decayed_score.max(0.0)
    }

    pub fn get_baseline(&self, ip: &str) -> f64 {
        self.baseline_scores.get(ip).map(|e| *e).unwrap_or(0.0)
    }

    pub fn clear_baseline(&self, ip: &str) {
        self.baseline_scores.remove(ip);
    }
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedBehaviorProfile {
    pub ip: String,
    pub request_count: u64,
    pub unique_paths: HashSet<String>,
    pub error_count: u64,
    pub user_agents: Vec<String>,
    pub window_start: DateTime<Utc>,
    pub metrics: Vec<BehaviorMetric>,
    pub current_score: f64,
    pub risk_level: String,
    pub score_factors: Vec<String>,
    pub last_seen: DateTime<Utc>,
    pub created_at: DateTime<Utc>,
}

#[cfg(feature = "behavior-profiling")]
impl EnrichedBehaviorProfile {
    pub fn from_profile_and_score(
        profile: &BehaviorProfile,
        score: &BehaviorScore,
        risk_level: &str,
    ) -> Self {
        EnrichedBehaviorProfile {
            ip: profile.ip.clone(),
            request_count: profile.request_count,
            unique_paths: profile.unique_paths.clone(),
            error_count: profile.error_count,
            user_agents: profile.user_agents.clone(),
            window_start: profile.window_start,
            metrics: profile.metrics.clone(),
            current_score: score.score,
            risk_level: risk_level.to_string(),
            score_factors: score.factors.clone(),
            last_seen: Utc::now(),
            created_at: profile.window_start,
        }
    }
}

#[cfg(feature = "behavior-profiling")]
#[derive(Debug)]
pub struct BehaviorProfileManager {
    profiles: DashMap<String, BehaviorProfile>,
    collector: Arc<BehaviorMetricsCollector>,
    score_engine: Arc<BehaviorScoreEngine>,
    config: BehaviorProfilingConfig,
}

#[cfg(feature = "behavior-profiling")]
impl BehaviorProfileManager {
    pub fn new(
        collector: Arc<BehaviorMetricsCollector>,
        score_engine: Arc<BehaviorScoreEngine>,
        config: BehaviorProfilingConfig,
    ) -> Self {
        BehaviorProfileManager {
            profiles: DashMap::new(),
            collector,
            score_engine,
            config,
        }
    }

    pub fn track_request(&self, ip: &str, url: &str, status_code: u16, user_agent: &str) {
        self.collector
            .track_request(ip, url, status_code, user_agent);
    }

    pub fn get_profile(&self, ip: &str) -> Option<EnrichedBehaviorProfile> {
        self.update_profile_from_collector(ip);

        let profile = match self.profiles.get(ip) {
            Some(entry) => entry.value().clone(),
            None => return None,
        };

        let score = self.score_engine.compute_score(ip);
        let risk_level = self.score_engine.get_risk_level(&score);

        Some(EnrichedBehaviorProfile::from_profile_and_score(
            &profile, &score, risk_level,
        ))
    }

    pub fn get_all_profiles(&self) -> Vec<EnrichedBehaviorProfile> {
        let mut result = Vec::new();

        for entry in self.profiles.iter() {
            let ip = entry.key();
            let profile = entry.value().clone();
            let score = self.score_engine.compute_score(ip);
            let risk_level = self.score_engine.get_risk_level(&score);

            result.push(EnrichedBehaviorProfile::from_profile_and_score(
                &profile, &score, risk_level,
            ));
        }

        result.sort_by(|a, b| {
            b.current_score
                .partial_cmp(&a.current_score)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        result
    }

    pub fn get_high_risk_ips(&self, threshold: f64) -> Vec<EnrichedBehaviorProfile> {
        self.get_all_profiles()
            .into_iter()
            .filter(|p| p.current_score >= threshold)
            .collect()
    }

    pub fn cleanup_expired_profiles(&self) -> usize {
        let now = Utc::now();
        let ttl = Duration::seconds(self.config.profile_ttl_seconds as i64);
        let mut expired_count = 0;

        self.profiles.retain(|_ip, profile| {
            let age = now.signed_duration_since(profile.window_start);
            if age > ttl {
                expired_count += 1;
                false
            } else {
                true
            }
        });

        let metrics_cleaned = self.collector.cleanup_expired_metrics();

        if expired_count > 0 || metrics_cleaned > 0 {
            info!(
                "Behavior profile cleanup: {} profiles, {} metrics removed",
                expired_count, metrics_cleaned
            );
        }

        expired_count
    }

    pub fn start_gc_worker(self: &Arc<Self>) -> tokio::task::JoinHandle<()> {
        let manager = Arc::clone(self);
        let interval_secs = self.config.gc_interval_seconds;

        tokio::spawn(async move {
            let mut gc_interval = interval(TokioDuration::from_secs(interval_secs));
            loop {
                gc_interval.tick().await;
                manager.cleanup_expired_profiles();
            }
        })
    }

    pub fn get_profile_count(&self) -> usize {
        self.profiles.len()
    }

    fn update_profile_from_collector(&self, ip: &str) {
        let metrics = match self.collector.get_metrics(ip) {
            Some(m) => m,
            None => return,
        };

        let now = Utc::now();
        let mut behavior_metrics = Vec::new();

        behavior_metrics.push(BehaviorMetric {
            metric_type: "request_count".to_string(),
            value: metrics.request_count as f64,
            timestamp: now,
        });

        behavior_metrics.push(BehaviorMetric {
            metric_type: "unique_paths".to_string(),
            value: metrics.unique_paths.len() as f64,
            timestamp: now,
        });

        behavior_metrics.push(BehaviorMetric {
            metric_type: "error_rate".to_string(),
            value: metrics.error_rate,
            timestamp: now,
        });

        behavior_metrics.push(BehaviorMetric {
            metric_type: "user_agent_count".to_string(),
            value: metrics.user_agents.len() as f64,
            timestamp: now,
        });

        let profile = BehaviorProfile {
            ip: ip.to_string(),
            request_count: metrics.request_count,
            unique_paths: metrics.unique_paths,
            error_count: metrics.error_count,
            user_agents: metrics.user_agents,
            window_start: metrics.window_start,
            metrics: behavior_metrics,
        };

        self.profiles.insert(ip.to_string(), profile);
    }
}

#[cfg(test)]
#[cfg(feature = "behavior-profiling")]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration as StdDuration;

    fn create_test_collector(window_seconds: u64) -> Arc<BehaviorMetricsCollector> {
        let config = BehaviorProfilingConfig {
            enabled: true,
            window_seconds,
            profile_ttl_seconds: 3600,
            gc_interval_seconds: 600,
            max_profiles: 10000,
        };
        Arc::new(BehaviorMetricsCollector::new(config))
    }

    fn create_test_score_engine(
        collector: Arc<BehaviorMetricsCollector>,
    ) -> Arc<BehaviorScoreEngine> {
        Arc::new(BehaviorScoreEngine::new(collector, 70.0, 40.0, 30.0))
    }

    fn create_test_profile_manager(
        collector: Arc<BehaviorMetricsCollector>,
        score_engine: Arc<BehaviorScoreEngine>,
    ) -> BehaviorProfileManager {
        BehaviorProfileManager::new(collector, score_engine, BehaviorProfilingConfig::default())
    }

    fn simulate_requests(
        collector: &BehaviorMetricsCollector,
        ip: &str,
        count: u64,
        urls: &[&str],
        status_codes: &[u16],
        user_agents: &[&str],
    ) {
        let count_usize = count as usize;
        for i in 0..count_usize {
            let url = urls[i % urls.len()];
            let status = status_codes[i % status_codes.len()];
            let ua = user_agents[i % user_agents.len()];
            collector.track_request(ip, url, status, ua);
        }
    }

    #[test]
    fn test_rapid_path_enumeration_detection() {
        let collector = create_test_collector(60);
        let score_engine = create_test_score_engine(collector.clone());

        let scanner_ip = "192.168.1.100";
        let paths_strings: Vec<String> = (0..50).map(|i| format!("/path{}", i)).collect();
        let paths: Vec<&str> = paths_strings.iter().map(|s| s.as_str()).collect();

        simulate_requests(&collector, scanner_ip, 50, &paths, &[404], &["scanner/1.0"]);

        let score = score_engine.compute_score(scanner_ip);

        assert!(
            score.score >= 70.0,
            "Scanner IP should have high score (got {:.1})",
            score.score
        );

        assert!(!score.factors.is_empty(), "Should have identifying factors");

        assert!(
            score.diversity_score > 0.0,
            "Should have diversity score component"
        );

        assert!(
            score.error_rate_score > 0.0,
            "Should have error rate score component"
        );
    }

    #[test]
    fn test_legitimate_admin_access_scenario() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let admin_ip = "10.0.0.50";
        let admin_paths = vec![
            "/admin/dashboard",
            "/admin/users",
            "/admin/settings",
            "/admin/logs",
            "/api/health",
            "/api/metrics",
        ];

        let admin_path_refs: Vec<&str> = admin_paths.iter().map(|&s| s).collect();
        simulate_requests(
            &collector,
            admin_ip,
            10,
            &admin_path_refs,
            &[200],
            &["Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0"],
        );

        let score = score_engine.compute_score(admin_ip);

        assert!(
            score.score < 40.0,
            "Legitimate admin should have low score (got {:.1})",
            score.score
        );

        assert_eq!(
            score.velocity_score, 0.0,
            "Normal request rate should have zero velocity score"
        );

        assert_eq!(
            score.error_rate_score, 0.0,
            "No errors should result in zero error rate score"
        );
    }

    #[test]
    fn test_score_decay_over_time() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let ip = "172.16.0.1";
        let suspicious_paths = vec![
            "/etc/passwd",
            "/admin/config",
            "/.env",
            "/wp-admin",
            "/api/debug",
        ];

        simulate_requests(
            &collector,
            ip,
            20,
            &suspicious_paths
                .iter()
                .map(|s| s.as_ref())
                .collect::<Vec<_>>(),
            &[200, 403, 404, 500],
            &["curl/7.68.0", "python-requests/2.28.0"],
        );

        let initial_score = score_engine.compute_score(ip);
        assert!(
            initial_score.score > 0.0,
            "Should have non-zero initial score"
        );

        let mut metrics = collector.metrics.get_mut(ip).unwrap();
        let old_time = Utc::now() - Duration::minutes(45);
        metrics.value_mut().window_start = old_time;

        for req in metrics.value_mut().requests.iter_mut() {
            req.timestamp = old_time;
        }

        let decayed_score = score_engine.compute_score(ip);

        assert!(
            decayed_score.score < initial_score.score,
            "Decayed score ({:.1}) should be less than initial ({:.1})",
            decayed_score.score,
            initial_score.score
        );

        assert!(decayed_score.score >= 0.0, "Score should not be negative");

        debug!(
            "Decay test: initial={:.1}, decayed={:.1}",
            initial_score.score, decayed_score.score
        );
    }

    #[test]
    fn test_profile_expiration_and_cleanup() {
        let collector = create_test_collector(60);
        let score_engine = create_test_score_engine(collector.clone());

        let _config = BehaviorProfilingConfig {
            enabled: true,
            window_seconds: 60,
            profile_ttl_seconds: 120,
            gc_interval_seconds: 600,
            max_profiles: 10000,
        };

        let manager = create_test_profile_manager(collector.clone(), score_engine.clone());

        let expired_ip = "192.168.100.1";
        let active_ip = "192.168.100.2";

        collector.track_request(expired_ip, "/old-path", 200, "old-agent");
        collector.track_request(active_ip, "/current-path", 200, "current-agent");

        manager.update_profile_from_collector(expired_ip);
        manager.update_profile_from_collector(active_ip);

        let initial_count = manager.get_profile_count();
        assert_eq!(initial_count, 2, "Should have 2 profiles initially");

        let mut expired_profile = manager.profiles.get_mut(expired_ip).unwrap();
        expired_profile.value_mut().window_start = Utc::now() - Duration::seconds(180);

        let cleaned = manager.cleanup_expired_profiles();

        assert!(
            cleaned >= 1,
            "Should have cleaned at least 1 expired profile (got {})",
            cleaned
        );

        let remaining_count = manager.get_profile_count();
        assert_eq!(
            remaining_count,
            initial_count - cleaned,
            "Remaining count should match"
        );

        let active_profile_exists = manager.profiles.contains_key(active_ip);
        assert!(
            active_profile_exists,
            "Active IP profile should still exist"
        );
    }

    #[test]
    fn test_high_velocity_detection() {
        let collector = create_test_collector(60);
        let score_engine = create_test_score_engine(collector.clone());

        let ip = "10.10.10.10";

        for i in 0..60 {
            collector.track_request(ip, &format!("/api/resource/{}", i), 200, "Mozilla/5.0");
        }

        let score = score_engine.compute_score(ip);

        assert!(
            score.velocity_score > 0.0,
            "High velocity should trigger velocity score"
        );

        assert!(
            score.factors.iter().any(|f| f.contains("velocity")),
            "Should have velocity factor"
        );
    }

    #[test]
    fn test_multiple_ua_changes_detection() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let ip = "192.168.50.50";
        let user_agents = vec![
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1.15",
            "curl/7.68.0",
            "python-requests/2.28.0",
            "sqlmap/1.6",
        ];

        for (i, ua) in user_agents.iter().enumerate() {
            collector.track_request(ip, &format!("/page/{}", i), 200, ua);
        }

        let score = score_engine.compute_score(ip);

        assert!(
            score.factors.iter().any(|f| f.contains("user agent")),
            "Should detect multiple user agents"
        );
    }

    #[test]
    fn test_concurrent_request_tracking() {
        let collector = create_test_collector(300);
        let ip = "10.0.0.1";

        let mut handles = vec![];

        for thread_id in 0..10 {
            let collector_clone = collector.clone();
            let ip_clone = ip.to_string();

            let handle = thread::spawn(move || {
                for i in 0..100 {
                    collector_clone.track_request(
                        &ip_clone,
                        &format!("/thread/{}/req/{}", thread_id, i),
                        200,
                        &format!("Agent-{}", thread_id),
                    );
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let metrics = collector.get_metrics(ip).unwrap();
        assert!(
            metrics.request_count >= 1000,
            "Should have tracked all requests (got {})",
            metrics.request_count
        );

        assert!(
            metrics.user_agents.len() == 10,
            "Should have 10 unique user agents"
        );
    }

    #[test]
    fn test_empty_ip_score() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let score = score_engine.compute_score("1.2.3.4");

        assert_eq!(score.score, 0.0, "Unknown IP should have zero score");
        assert_eq!(score.velocity_score, 0.0);
        assert_eq!(score.diversity_score, 0.0);
        assert_eq!(score.error_rate_score, 0.0);
        assert!(score.factors.is_empty());
    }

    #[test]
    fn test_baseline_update() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let ip = "10.1.1.1";

        score_engine.update_baseline(ip, 10.0);
        assert_eq!(score_engine.get_baseline(ip), 10.0);

        score_engine.update_baseline(ip, 20.0);
        let new_baseline = score_engine.get_baseline(ip);
        assert!(
            new_baseline > 10.0 && new_baseline < 20.0,
            "Baseline should be smoothed (got {:.2})",
            new_baseline
        );

        score_engine.clear_baseline(ip);
        assert_eq!(
            score_engine.get_baseline(ip),
            0.0,
            "Cleared baseline should be zero"
        );
    }

    #[test]
    fn test_risk_level_classification() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());

        let high_score = BehaviorScore {
            ip: "1.1.1.1".to_string(),
            score: 85.0,
            velocity_score: 30.0,
            diversity_score: 25.0,
            error_rate_score: 30.0,
            breakdown: BehaviorScoreBreakdown {
                velocity_score: 30.0,
                path_diversity_score: 25.0,
                error_rate_score: 30.0,
                session_consistency_score: 0.0,
            },
            factors: vec![],
        };

        let medium_score = BehaviorScore {
            ip: "2.2.2.2".to_string(),
            score: 55.0,
            velocity_score: 20.0,
            diversity_score: 15.0,
            error_rate_score: 20.0,
            breakdown: BehaviorScoreBreakdown {
                velocity_score: 20.0,
                path_diversity_score: 15.0,
                error_rate_score: 20.0,
                session_consistency_score: 0.0,
            },
            factors: vec![],
        };

        let low_score = BehaviorScore {
            ip: "3.3.3.3".to_string(),
            score: 20.0,
            velocity_score: 5.0,
            diversity_score: 5.0,
            error_rate_score: 10.0,
            breakdown: BehaviorScoreBreakdown {
                velocity_score: 5.0,
                path_diversity_score: 5.0,
                error_rate_score: 10.0,
                session_consistency_score: 0.0,
            },
            factors: vec![],
        };

        assert_eq!(
            score_engine.get_risk_level(&high_score),
            "high",
            "Score 85 should be high risk"
        );
        assert_eq!(
            score_engine.get_risk_level(&medium_score),
            "medium",
            "Score 55 should be medium risk"
        );
        assert_eq!(
            score_engine.get_risk_level(&low_score),
            "low",
            "Score 20 should be low risk"
        );
    }

    #[test]
    fn test_profile_manager_enrichment() {
        let collector = create_test_collector(300);
        let score_engine = create_test_score_engine(collector.clone());
        let manager = create_test_profile_manager(collector.clone(), score_engine.clone());

        let ip = "10.20.30.40";

        collector.track_request(ip, "/admin", 200, "Mozilla/5.0");
        collector.track_request(ip, "/config", 403, "Mozilla/5.0");

        let profile = manager.get_profile(ip).unwrap();

        assert_eq!(profile.ip, ip);
        assert!(profile.request_count >= 2);
        assert!(profile.current_score >= 0.0);
        assert!(!profile.risk_level.is_empty());
    }

    #[test]
    fn test_sliding_window_pruning() {
        let collector = create_test_collector(5);
        let ip = "192.168.200.1";

        collector.track_request(ip, "/old-request", 200, "agent1");

        thread::sleep(StdDuration::from_secs(6));

        collector.track_request(ip, "/new-request", 200, "agent1");

        let metrics = collector.get_metrics(ip).unwrap();

        assert!(
            metrics.request_count <= 2,
            "Old requests should be pruned (got {})",
            metrics.request_count
        );
    }

    #[test]
    fn test_max_profiles_eviction() {
        let config = BehaviorProfilingConfig {
            enabled: true,
            window_seconds: 300,
            profile_ttl_seconds: 3600,
            gc_interval_seconds: 600,
            max_profiles: 5,
        };

        let collector = Arc::new(BehaviorMetricsCollector::new(config));

        for i in 0..10 {
            collector.track_request(&format!("10.0.0.{}", i), "/test", 200, "Mozilla/5.0");
        }

        assert!(
            collector.get_active_ip_count() <= 5,
            "Should not exceed max profiles (got {})",
            collector.get_active_ip_count()
        );
    }
}
