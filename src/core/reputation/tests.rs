#[cfg(test)]
mod provider_tests {
    use crate::core::models::ReputationProviderConfig;
    use crate::core::reputation::manager::ReputationManager;

    #[tokio::test]
    async fn test_reputation_manager_initialization() {
        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-abuseipdb-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "virustotal".to_string(),
                api_key: "test-vt-key".to_string(),
                enabled: true,
                base_url: None,
            },
        ];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 2);

        let names = manager.provider_names();
        assert!(names.contains(&"AbuseIPDB"));
        assert!(names.contains(&"VirusTotal"));
    }

    #[tokio::test]
    async fn test_reputation_manager_mixed_enabled_disabled() {
        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "greynoise".to_string(),
                api_key: "test-key".to_string(),
                enabled: false,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "spamhaus".to_string(),
                api_key: String::new(),
                enabled: true,
                base_url: None,
            },
        ];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 2);
    }

    #[tokio::test]
    async fn test_reputation_manager_all_providers() {
        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "greynoise".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "virustotal".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "spamhaus".to_string(),
                api_key: String::new(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "ipinfo".to_string(),
                api_key: String::new(),
                enabled: true,
                base_url: None,
            },
        ];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 5);
    }

    #[tokio::test]
    async fn test_query_all_returns_zero_score_with_no_providers() {
        let manager = ReputationManager::new(&[]);
        let score = manager.query_all("192.168.1.1").await;

        assert_eq!(score.ip, "192.168.1.1");
        assert_eq!(score.score, 0.0);
        assert!(score.provider_results.is_empty());
        assert!(!score.cached);
    }

    #[tokio::test]
    async fn test_provider_type_case_sensitivity() {
        let configs = vec![
            ReputationProviderConfig {
                provider_type: "AbuseIPDB".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
            ReputationProviderConfig {
                provider_type: "ABUSEIPDB".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: None,
            },
        ];

        let manager = ReputationManager::new(&configs);
        assert_eq!(manager.provider_count(), 0);
    }

    #[tokio::test]
    async fn test_spamhaus_ip_reversal() {
        use crate::core::reputation::providers::SpamhausProvider;

        let ip = "192.168.1.100";
        let reversed = SpamhausProvider::reverse_ip(ip);
        assert_eq!(reversed, "100.1.168.192");
    }

    #[tokio::test]
    async fn test_greynoise_verdict_mapping() {
        use crate::core::reputation::providers::GreyNoiseProvider;

        assert_eq!(
            GreyNoiseProvider::map_verdict_to_score("malicious"),
            (1.0, true)
        );
        assert_eq!(GreyNoiseProvider::map_verdict_to_score("bad"), (0.8, true));
        assert_eq!(
            GreyNoiseProvider::map_verdict_to_score("suspicious"),
            (0.5, true)
        );
        assert_eq!(
            GreyNoiseProvider::map_verdict_to_score("unknown"),
            (0.0, false)
        );
        assert_eq!(
            GreyNoiseProvider::map_verdict_to_score("good"),
            (0.0, false)
        );
        assert_eq!(
            GreyNoiseProvider::map_verdict_to_score("random"),
            (0.0, false)
        );
    }

    #[tokio::test]
    async fn test_ipinfo_risk_score_calculation() {
        use crate::core::reputation::providers::IPInfoProvider;

        assert_eq!(
            IPInfoProvider::calculate_risk_score(false, false, false, false),
            (0.0, false)
        );
        assert_eq!(
            IPInfoProvider::calculate_risk_score(true, false, false, false),
            (0.3, false)
        );
        assert_eq!(
            IPInfoProvider::calculate_risk_score(false, true, false, false),
            (0.4, false)
        );
        assert_eq!(
            IPInfoProvider::calculate_risk_score(false, false, true, false),
            (0.5, true)
        );
        assert_eq!(
            IPInfoProvider::calculate_risk_score(false, false, false, true),
            (0.8, true)
        );
        assert_eq!(
            IPInfoProvider::calculate_risk_score(true, true, true, true),
            (1.0, true)
        );
    }

    #[tokio::test]
    async fn test_abuseipdb_score_normalization() {
        let confidence_0 = 0.0;
        let confidence_50 = 50.0;
        let confidence_100 = 100.0;

        let normalized_0 = confidence_0 / 100.0;
        let normalized_50 = confidence_50 / 100.0;
        let normalized_100 = confidence_100 / 100.0;

        assert_eq!(normalized_0, 0.0);
        assert_eq!(normalized_50, 0.5);
        assert_eq!(normalized_100, 1.0);
    }

    #[tokio::test]
    async fn test_virustotal_malicious_ratio() {
        let test_cases = vec![
            (0.0, 0.0, 0.0),
            (5.0, 70.0, 5.0 / 70.0),
            (35.0, 70.0, 0.5),
            (70.0, 70.0, 1.0),
        ];

        for (malicious, total, expected) in test_cases {
            let ratio: f64 = if total > 0.0 { malicious / total } else { 0.0 };
            assert!((ratio - expected).abs() < f64::EPSILON);
        }
    }
}

#[cfg(test)]
mod mock_tests {
    use crate::core::models::ReputationProviderConfig;
    use crate::core::reputation::manager::ReputationManager;
    use mockito::Server;

    #[tokio::test]
    async fn test_mock_abuseipdb_provider() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=1.2.3.4")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "data": {
                    "ipAddress": "1.2.3.4",
                    "abuseConfidenceScore": 75,
                    "totalReports": 10,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert_eq!(score.provider_results.len(), 1);
        assert_eq!(score.provider_results[0].provider_name, "AbuseIPDB");
        assert_eq!(score.provider_results[0].score, 0.75);
        assert!(score.provider_results[0].is_listed);

        mock.assert();
    }

    #[tokio::test]
    async fn test_mock_greynoise_provider_malicious() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/v3/community/1.2.3.4")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "ip": "1.2.3.4",
                "verdict": "malicious",
                "noise": true,
                "spoofable": false
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "greynoise".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert_eq!(score.provider_results.len(), 1);
        assert_eq!(score.provider_results[0].score, 1.0);
        assert!(score.provider_results[0].is_listed);

        mock.assert();
    }

    #[tokio::test]
    async fn test_mock_virustotal_provider() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/api/v3/ip_addresses/1.2.3.4")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "data": {
                    "type": "ip_address",
                    "id": "1.2.3.4",
                    "attributes": {
                        "last_analysis_stats": {
                            "harmless": 60,
                            "malicious": 10,
                            "suspicious": 0,
                            "undetected": 0,
                            "timeout": 0
                        }
                    }
                }
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "virustotal".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert_eq!(score.provider_results.len(), 1);
        assert_eq!(score.provider_results[0].score, 10.0 / 70.0);
        assert!(score.provider_results[0].is_listed);

        mock.assert();
    }

    #[tokio::test]
    async fn test_mock_ipinfo_provider_proxy() {
        let mut server = Server::new_async().await;

        let mock = server
            .mock("GET", "/1.2.3.4/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "ip": "1.2.3.4",
                "city": "Unknown",
                "region": "Unknown",
                "country": "XX",
                "org": "AS12345 Proxy Provider",
                "privacy": {
                    "vpn": false,
                    "proxy": true,
                    "tor": false,
                    "relay": false,
                    "hosting": false,
                    "service": ""
                }
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "ipinfo".to_string(),
            api_key: String::new(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert_eq!(score.provider_results.len(), 1);
        assert_eq!(score.provider_results[0].score, 0.5);
        assert!(score.provider_results[0].is_listed);

        mock.assert();
    }

    #[tokio::test]
    async fn test_mock_abuseipdb_timeout() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/api/v2/check")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body_from_request(|_| {
                std::thread::sleep(std::time::Duration::from_secs(5));
                b"{}".to_vec()
            })
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "test-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert!(score.provider_results.is_empty());
        assert_eq!(score.score, 0.0);
    }

    #[tokio::test]
    async fn test_mock_multiple_providers_aggregate() {
        let mut server1 = Server::new_async().await;
        let mut server2 = Server::new_async().await;

        let _mock1 = server1
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=5.6.7.8")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "data": {
                    "ipAddress": "5.6.7.8",
                    "abuseConfidenceScore": 80,
                    "totalReports": 50,
                    "lastReportedAt": "2024-01-01T00:00:00Z"
                }
            }
            "#,
            )
            .create_async()
            .await;

        let _mock2 = server2
            .mock("GET", "/v3/community/5.6.7.8")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "ip": "5.6.7.8",
                "verdict": "bad",
                "noise": true,
                "spoofable": false
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server1.url()),
            },
            ReputationProviderConfig {
                provider_type: "greynoise".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server2.url()),
            },
        ];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("5.6.7.8").await;

        assert_eq!(score.provider_results.len(), 2);
        assert!(score.score > 0.0 && score.score <= 1.0);

        let abuseipdb_result = score
            .provider_results
            .iter()
            .find(|r| r.provider_name == "AbuseIPDB")
            .unwrap();
        let greynoise_result = score
            .provider_results
            .iter()
            .find(|r| r.provider_name == "GreyNoise")
            .unwrap();

        assert_eq!(abuseipdb_result.score, 0.8);
        assert_eq!(greynoise_result.score, 0.8);

        let expected_aggregate = (0.8 * 1.0 + 0.8 * 1.0) / (1.0 + 1.0);
        assert!((score.score - expected_aggregate).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_mock_provider_api_error() {
        let mut server = Server::new_async().await;

        let _mock = server
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=1.2.3.4")
            .with_status(401)
            .with_header("content-type", "application/json")
            .with_body(r#"{"errors": [{"detail": "Invalid API key"}]}"#)
            .create_async()
            .await;

        let configs = vec![ReputationProviderConfig {
            provider_type: "abuseipdb".to_string(),
            api_key: "invalid-key".to_string(),
            enabled: true,
            base_url: Some(server.url()),
        }];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("1.2.3.4").await;

        assert!(score.provider_results.is_empty());
        assert_eq!(score.score, 0.0);
    }

    #[tokio::test]
    async fn test_mock_safe_ip_all_providers() {
        let mut server1 = Server::new_async().await;
        let mut server2 = Server::new_async().await;
        let mut server3 = Server::new_async().await;

        let _mock1 = server1
            .mock("GET", "/api/v2/check")
            .match_query("ipAddress=8.8.8.8")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "data": {
                    "ipAddress": "8.8.8.8",
                    "abuseConfidenceScore": 0,
                    "totalReports": 0,
                    "lastReportedAt": null
                }
            }
            "#,
            )
            .create_async()
            .await;

        let _mock2 = server2
            .mock("GET", "/v3/community/8.8.8.8")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "ip": "8.8.8.8",
                "verdict": "good",
                "noise": false,
                "spoofable": false
            }
            "#,
            )
            .create_async()
            .await;

        let _mock3 = server3
            .mock("GET", "/8.8.8.8/json")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(
                r#"
            {
                "ip": "8.8.8.8",
                "city": "Mountain View",
                "region": "California",
                "country": "US",
                "org": "AS15169 Google LLC",
                "privacy": {
                    "vpn": false,
                    "proxy": false,
                    "tor": false,
                    "relay": false,
                    "hosting": false,
                    "service": ""
                }
            }
            "#,
            )
            .create_async()
            .await;

        let configs = vec![
            ReputationProviderConfig {
                provider_type: "abuseipdb".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server1.url()),
            },
            ReputationProviderConfig {
                provider_type: "greynoise".to_string(),
                api_key: "test-key".to_string(),
                enabled: true,
                base_url: Some(server2.url()),
            },
            ReputationProviderConfig {
                provider_type: "ipinfo".to_string(),
                api_key: String::new(),
                enabled: true,
                base_url: Some(server3.url()),
            },
        ];

        let manager = ReputationManager::new(&configs);
        let score = manager.query_all("8.8.8.8").await;

        assert_eq!(score.provider_results.len(), 3);
        assert_eq!(score.score, 0.0);
        assert!(!score.provider_results.iter().any(|r| r.is_listed));
    }
}
