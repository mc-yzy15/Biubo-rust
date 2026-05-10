# 🗺️ Biubo WAF Roadmap

This is the future of Biubo WAF. We are an ambitious, independent project and we have big plans.

## 🏁 Phase 1: Foundations (Current)

- [x] **Regex Detection**: High-performance SQLI, XSS, RCE rules.
- [x] **LLM Intelligence**: Secondary analysis using OpenAI/Qwen.
- [x] **Visual Replay**: Integrated `rrweb` sessions.
- [x] **Dashboard**: Basic monitoring and control.

## 🏃 Phase 2: Performance & Scalability (In Progress)

- [x] **Asynchronous AI Detection**: Queue-based LLM analysis to avoid request blocking.
- [x] **Docker Support**: Containerized deployment with `docker-compose`.
- [x] **Storage Drivers**: Optional Redis/PostgreSQL support for high-traffic logs.
- [x] **SSL Management**: Automated Let's Encrypt certificates directly in the WAF.
- [x] **HTTPS Server**: TLS listener with HTTP→HTTPS redirect.
- [x] **Multi-platform CI/CD**: Docker Hub push, multi-arch builds, integration tests.

## 🛡️ Phase 3: Advanced Defense (In Progress)

- [x] **Enterprise Rule Engine**: OWASP CRS-inspired architecture with thousands of rules, paranoia levels (1-4), rule browser, and hot-reload.
- [x] **Multi-Source IP Reputation**: 5 public authoritative providers (AbuseIPDB, GreyNoise, VirusTotal, Spamhaus, IPinfo.io) with weighted aggregation.
- [x] **Two-Tier LLM**: Quick evaluation (small model, 3s) → Deep analysis (large model, 10s). Triggered only when rules don't match AND threat signals exist.
- [x] **Behavioral Profiling**: Per-IP behavior tracking (velocity, path diversity, error rate) with anomaly scoring and decay function.
- [x] **Automatic Patching**: AI-generated remediation suggestions with code examples for detected vulnerabilities.
- [x] **Cluster Support**: Redis-backed config sync, threat intelligence sharing, and primary/secondary failover.
- [x] **WAF API**: REST + WebSocket API for backend applications (check/report/block/unblock/stats/events).
- [x] **Dashboard UI**: 6 new tabs - IP Reputation, Rule Browser, Behavior Monitor, Cluster Manager, API Keys, Patch Suggestions.

## 🌍 Phase 4: Ecosystem & Plugins

- [x] **Plugin System**: Allow community members to write custom detection rules or log exporters.
- [x] **Mobile Dashboard**: A mobile app or optimized UI for on-the-go security management.

---

**Want to help us get there faster?** Check our [CONTRIBUTING.md](CONTRIBUTING.md) and join the movement!
