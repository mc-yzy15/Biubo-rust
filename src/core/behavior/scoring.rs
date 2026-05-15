use chrono::Utc;
use std::collections::HashSet;

use crate::core::models::{BehaviorProfile, BehaviorScore, BehaviorScoreBreakdown};

const VELOCITY_MAX_SCORE: f64 = 25.0;
const PATH_DIVERSITY_MAX_SCORE: f64 = 25.0;
const ERROR_RATE_MAX_SCORE: f64 = 25.0;
const SESSION_CONSISTENCY_MAX_SCORE: f64 = 25.0;
const SCORE_DECAY_TIME_CONSTANT: f64 = 30.0;
const SCORE_DECAY_MINIMUM: f64 = 0.0;

pub struct ThresholdChecker;

impl ThresholdChecker {
    pub fn check_velocity(requests_per_min: f64) -> f64 {
        if requests_per_min < 10.0 {
            0.0
        } else if requests_per_min <= 30.0 {
            5.0
        } else if requests_per_min <= 60.0 {
            10.0
        } else if requests_per_min <= 100.0 {
            15.0
        } else {
            25.0
        }
    }

    pub fn check_path_diversity(unique_paths_per_60s: u64, error_rate: f64) -> f64 {
        let error_pct = error_rate * 100.0;

        if unique_paths_per_60s > 30 && error_pct > 40.0 {
            25.0
        } else if unique_paths_per_60s > 20 && error_pct > 30.0 {
            20.0
        } else if unique_paths_per_60s > 15 && error_pct > 20.0 {
            15.0
        } else if unique_paths_per_60s > 10 {
            10.0
        } else {
            0.0
        }
    }

    pub fn check_error_rate(error_ratio: f64) -> f64 {
        let error_pct = error_ratio * 100.0;

        if error_pct > 80.0 {
            25.0
        } else if error_pct > 60.0 {
            20.0
        } else if error_pct > 40.0 {
            15.0
        } else if error_pct > 20.0 {
            10.0
        } else {
            0.0
        }
    }

    pub fn check_session_consistency(user_agents: &[String]) -> f64 {
        let unique_ua: HashSet<&str> = user_agents.iter().map(|s| s.as_str()).collect();
        let count = unique_ua.len();

        if count > 3 {
            25.0
        } else if count >= 2 {
            15.0
        } else {
            0.0
        }
    }
}

pub struct ScoreDecay;

impl ScoreDecay {
    pub fn decay_score(current_score: f64, elapsed_minutes: f64) -> f64 {
        if elapsed_minutes <= 0.0 {
            return current_score.max(SCORE_DECAY_MINIMUM);
        }

        let decay_factor: f64 = (-elapsed_minutes / SCORE_DECAY_TIME_CONSTANT).exp();
        let decayed_score = current_score * decay_factor;

        decayed_score.max(SCORE_DECAY_MINIMUM)
    }
}

pub struct BehaviorScoreCalculator;

impl BehaviorScoreCalculator {
    pub fn compute_score(profile: &BehaviorProfile) -> BehaviorScore {
        let requests_per_min = Self::calculate_requests_per_minute(profile);
        let unique_paths_count = profile.unique_paths.len() as u64;
        let error_rate = Self::calculate_error_rate(profile);

        let velocity_score = ThresholdChecker::check_velocity(requests_per_min);
        let path_diversity_score =
            ThresholdChecker::check_path_diversity(unique_paths_count, error_rate);
        let error_rate_score = ThresholdChecker::check_error_rate(error_rate);
        let session_consistency_score =
            ThresholdChecker::check_session_consistency(&profile.user_agents);

        let raw_score =
            velocity_score + path_diversity_score + error_rate_score + session_consistency_score;

        let decayed_score = Self::apply_decay_if_needed(profile, raw_score);

        let final_score = decayed_score.min(100.0);
        let factors = Self::generate_factors(
            requests_per_min,
            unique_paths_count,
            error_rate,
            &profile.user_agents,
            velocity_score,
            path_diversity_score,
            error_rate_score,
            session_consistency_score,
        );

        let breakdown = BehaviorScoreBreakdown {
            velocity_score,
            path_diversity_score,
            error_rate_score,
            session_consistency_score,
        };

        BehaviorScore {
            ip: profile.ip.clone(),
            score: final_score,
            velocity_score,
            diversity_score: path_diversity_score,
            error_rate_score,
            breakdown,
            factors,
        }
    }

    fn calculate_requests_per_minute(profile: &BehaviorProfile) -> f64 {
        let now = Utc::now();
        let window_seconds = (now - profile.window_start).num_seconds() as f64;

        if window_seconds <= 0.0 {
            return profile.request_count as f64;
        }

        let window_minutes = window_seconds / 60.0;
        profile.request_count as f64 / window_minutes
    }

    fn calculate_error_rate(profile: &BehaviorProfile) -> f64 {
        if profile.request_count == 0 {
            return 0.0;
        }
        profile.error_count as f64 / profile.request_count as f64
    }

    fn apply_decay_if_needed(profile: &BehaviorProfile, raw_score: f64) -> f64 {
        let now = Utc::now();
        let elapsed_seconds = (now - profile.window_start).num_seconds() as f64;
        let elapsed_minutes = elapsed_seconds / 60.0;

        if elapsed_minutes > 1.0 {
            ScoreDecay::decay_score(raw_score, elapsed_minutes)
        } else {
            raw_score
        }
    }

    fn generate_factors(
        requests_per_min: f64,
        unique_paths_count: u64,
        error_rate: f64,
        user_agents: &[String],
        velocity_score: f64,
        path_diversity_score: f64,
        error_rate_score: f64,
        session_consistency_score: f64,
    ) -> Vec<String> {
        let mut factors = Vec::new();

        if velocity_score > 0.0 {
            factors.push(format!(
                "High request velocity: {:.1} requests/minute",
                requests_per_min
            ));
        }

        if path_diversity_score > 0.0 {
            factors.push(format!(
                "Path diversity: {} unique paths with {:.1}% error rate",
                unique_paths_count,
                error_rate * 100.0
            ));
        }

        if error_rate_score > 0.0 {
            factors.push(format!(
                "Elevated error rate: {:.1}% of requests failed",
                error_rate * 100.0
            ));
        }

        let unique_ua: HashSet<&str> = user_agents.iter().map(|s| s.as_str()).collect();
        if session_consistency_score > 0.0 {
            factors.push(format!(
                "Multiple user agents detected ({})",
                unique_ua.len()
            ));
        }

        factors
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::HashSet;

    #[test]
    fn test_velocity_low_traffic() {
        assert_eq!(ThresholdChecker::check_velocity(5.0), 0.0);
        assert_eq!(ThresholdChecker::check_velocity(9.9), 0.0);
    }

    #[test]
    fn test_velocity_moderate_traffic() {
        assert_eq!(ThresholdChecker::check_velocity(10.0), 5.0);
        assert_eq!(ThresholdChecker::check_velocity(30.0), 5.0);
    }

    #[test]
    fn test_velocity_elevated_traffic() {
        assert_eq!(ThresholdChecker::check_velocity(31.0), 10.0);
        assert_eq!(ThresholdChecker::check_velocity(60.0), 10.0);
    }

    #[test]
    fn test_velocity_high_traffic() {
        assert_eq!(ThresholdChecker::check_velocity(61.0), 15.0);
        assert_eq!(ThresholdChecker::check_velocity(100.0), 15.0);
    }

    #[test]
    fn test_velocity_extreme_traffic() {
        assert_eq!(ThresholdChecker::check_velocity(101.0), 25.0);
        assert_eq!(ThresholdChecker::check_velocity(500.0), 25.0);
    }

    #[test]
    fn test_path_diversity_scanner_pattern() {
        assert_eq!(ThresholdChecker::check_path_diversity(35, 0.5), 25.0);
        assert_eq!(ThresholdChecker::check_path_diversity(50, 0.7), 25.0);
    }

    #[test]
    fn test_path_diversity_moderate_scanning() {
        assert_eq!(ThresholdChecker::check_path_diversity(25, 0.35), 20.0);
    }

    #[test]
    fn test_path_diversity_light_scanning() {
        assert_eq!(ThresholdChecker::check_path_diversity(16, 0.25), 15.0);
    }

    #[test]
    fn test_path_diversity_many_paths_low_error() {
        assert_eq!(ThresholdChecker::check_path_diversity(12, 0.1), 10.0);
        assert_eq!(ThresholdChecker::check_path_diversity(25, 0.1), 10.0);
    }

    #[test]
    fn test_path_diversity_normal_usage() {
        assert_eq!(ThresholdChecker::check_path_diversity(5, 0.0), 0.0);
        assert_eq!(ThresholdChecker::check_path_diversity(8, 0.5), 0.0);
    }

    #[test]
    fn test_error_rate_critical() {
        assert_eq!(ThresholdChecker::check_error_rate(0.85), 25.0);
        assert_eq!(ThresholdChecker::check_error_rate(1.0), 25.0);
    }

    #[test]
    fn test_error_rate_high() {
        assert_eq!(ThresholdChecker::check_error_rate(0.65), 20.0);
        assert_eq!(ThresholdChecker::check_error_rate(0.80), 20.0);
    }

    #[test]
    fn test_error_rate_moderate() {
        assert_eq!(ThresholdChecker::check_error_rate(0.45), 15.0);
        assert_eq!(ThresholdChecker::check_error_rate(0.60), 15.0);
    }

    #[test]
    fn test_error_rate_low() {
        assert_eq!(ThresholdChecker::check_error_rate(0.25), 10.0);
        assert_eq!(ThresholdChecker::check_error_rate(0.40), 10.0);
    }

    #[test]
    fn test_error_rate_clean() {
        assert_eq!(ThresholdChecker::check_error_rate(0.0), 0.0);
        assert_eq!(ThresholdChecker::check_error_rate(0.15), 0.0);
        assert_eq!(ThresholdChecker::check_error_rate(0.20), 0.0);
    }

    #[test]
    fn test_session_consistency_many_agents() {
        let agents = vec![
            "Mozilla/5.0".to_string(),
            "curl/7.68.0".to_string(),
            "Python-requests/2.25.1".to_string(),
            "Googlebot/2.1".to_string(),
        ];
        assert_eq!(ThresholdChecker::check_session_consistency(&agents), 25.0);
    }

    #[test]
    fn test_session_consistency_few_agents() {
        let agents = vec!["Mozilla/5.0".to_string(), "curl/7.68.0".to_string()];
        assert_eq!(ThresholdChecker::check_session_consistency(&agents), 15.0);
    }

    #[test]
    fn test_session_consistency_single_agent() {
        let agents = vec!["Mozilla/5.0".to_string()];
        assert_eq!(ThresholdChecker::check_session_consistency(&agents), 0.0);
    }

    #[test]
    fn test_session_consistency_duplicate_agents() {
        let agents = vec![
            "Mozilla/5.0".to_string(),
            "Mozilla/5.0".to_string(),
            "curl/7.68.0".to_string(),
        ];
        assert_eq!(ThresholdChecker::check_session_consistency(&agents), 15.0);
    }

    #[test]
    fn test_session_consistency_empty_agents() {
        let agents: Vec<String> = vec![];
        assert_eq!(ThresholdChecker::check_session_consistency(&agents), 0.0);
    }

    #[test]
    fn test_score_decay_no_elapsed() {
        assert_eq!(ScoreDecay::decay_score(80.0, 0.0), 80.0);
    }

    #[test]
    fn test_score_decay_half_life() {
        let decayed = ScoreDecay::decay_score(80.0, 30.0);
        assert!(
            (decayed - 29.4).abs() < 1.0,
            "Expected ~29.4, got {}",
            decayed
        );
    }

    #[test]
    fn test_score_decay_one_hour() {
        let decayed = ScoreDecay::decay_score(100.0, 60.0);
        let expected: f64 = 100.0_f64 * (-60.0_f64 / 30.0_f64).exp();
        assert!(
            (decayed - expected).abs() < 0.01,
            "Expected {}, got {}",
            expected,
            decayed
        );
    }

    #[test]
    fn test_score_decay_minimum() {
        let decayed = ScoreDecay::decay_score(50.0, 300.0);
        assert!(
            decayed >= 0.0,
            "Score must not be negative, got {}",
            decayed
        );
    }

    #[test]
    fn test_score_decay_negative_elapsed() {
        let decayed = ScoreDecay::decay_score(80.0, -10.0);
        assert_eq!(
            decayed, 80.0,
            "Negative elapsed should return current score"
        );
    }

    fn create_test_profile(
        request_count: u64,
        unique_paths: Vec<&str>,
        error_count: u64,
        user_agents: Vec<&str>,
        window_start_offset_seconds: i64,
    ) -> BehaviorProfile {
        let now = Utc::now();
        let window_start = now - Duration::seconds(window_start_offset_seconds);

        let paths: HashSet<String> = unique_paths.iter().map(|s| s.to_string()).collect();
        let agents: Vec<String> = user_agents.iter().map(|s| s.to_string()).collect();

        BehaviorProfile {
            ip: "10.0.0.1".to_string(),
            request_count,
            unique_paths: paths,
            error_count,
            user_agents: agents,
            window_start,
            metrics: vec![],
        }
    }

    #[test]
    fn test_rapid_path_enumeration_scoring() {
        let mut paths = Vec::new();
        for i in 0..35 {
            paths.push(format!("/path{}", i));
        }

        let profile = create_test_profile(
            70,
            paths.iter().map(|s| s.as_str()).collect(),
            35,
            vec!["scanner/1.0"],
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(
            score.score >= 70.0,
            "Rapid path enumeration should score >= 70, got {}",
            score.score
        );
    }

    #[test]
    fn test_legitimate_admin_scoring() {
        let profile = create_test_profile(
            5,
            vec!["/admin", "/dashboard", "/settings"],
            0,
            vec!["Mozilla/5.0 (Windows NT 10.0; Win64; x64)"],
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(
            score.score < 20.0,
            "Legitimate admin should score < 20, got {}",
            score.score
        );
    }

    #[test]
    fn test_bot_activity_scoring() {
        let mut paths = Vec::new();
        for i in 0..50 {
            paths.push(format!("/scan{}", i));
        }

        let profile = create_test_profile(
            120,
            paths.iter().map(|s| s.as_str()).collect(),
            84,
            vec!["bot/1.0", "bot/2.0", "scanner/1.0", "exploit/3.0"],
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(
            score.score >= 90.0,
            "Bot activity should score >= 90, got {}",
            score.score
        );
    }

    #[test]
    fn test_behavior_score_breakdown() {
        let profile = create_test_profile(
            120,
            vec![
                "/a", "/b", "/c", "/d", "/e", "/f", "/g", "/h", "/i", "/j", "/k",
            ],
            84,
            vec!["bot/1.0", "bot/2.0", "scanner/1.0", "exploit/3.0"],
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(score.breakdown.velocity_score > 0.0);
        assert!(score.breakdown.path_diversity_score > 0.0);
        assert!(score.breakdown.error_rate_score > 0.0);
        assert!(score.breakdown.session_consistency_score > 0.0);

        assert_eq!(score.velocity_score, score.breakdown.velocity_score);
        assert_eq!(score.diversity_score, score.breakdown.path_diversity_score);
        assert_eq!(score.error_rate_score, score.breakdown.error_rate_score);
    }

    #[test]
    fn test_score_factors_generation() {
        let profile = create_test_profile(
            120,
            vec!["/scan1", "/scan2", "/scan3", "/scan4", "/scan5"],
            100,
            vec!["bot/1.0", "bot/2.0"],
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(!score.factors.is_empty(), "Should have scoring factors");
        assert!(
            score.factors.len() >= 3,
            "Should have at least 3 factors, got {}",
            score.factors.len()
        );
    }

    #[test]
    fn test_clean_traffic_no_factors() {
        let profile = create_test_profile(5, vec!["/home", "/about"], 0, vec!["Mozilla/5.0"], 60);

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(
            score.factors.is_empty(),
            "Clean traffic should have no factors, got {:?}",
            score.factors
        );
    }

    #[test]
    fn test_score_maximum_cap() {
        let mut paths = Vec::new();
        for i in 0..100 {
            paths.push(format!("/path{}", i));
        }

        let mut agents = Vec::new();
        for i in 0..10 {
            agents.push(format!("agent/{}", i));
        }

        let profile = create_test_profile(
            1000,
            paths.iter().map(|s| s.as_str()).collect(),
            900,
            agents.iter().map(|s| s.as_str()).collect(),
            60,
        );

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert!(
            score.score <= 100.0,
            "Score must not exceed 100, got {}",
            score.score
        );
    }

    #[test]
    fn test_zero_requests_profile() {
        let profile = create_test_profile(0, vec![], 0, vec![], 60);

        let score = BehaviorScoreCalculator::compute_score(&profile);

        assert_eq!(score.score, 0.0, "Zero requests should score 0");
    }
}
