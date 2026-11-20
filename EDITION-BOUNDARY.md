# Biubo WAF — Edition Boundary

This document is the canonical reference for what belongs in the Community Edition (OSS) versus the Commercial Edition (EE).  
CLAUDE.md requires all code to respect this boundary; any new feature must be placed here before implementation.

---

## Boundary Rule

| Rule | Detail |
|------|--------|
| **OSS is standalone** | Community Edition must be a fully functional WAF with zero dependency on `commercial/`. |
| **EE is additive** | Commercial Edition adds capabilities on top of OSS; it never removes or replaces OSS defaults for OSS users. |
| **No EE code in `src/`** | All EE implementation lives in `commercial/`. OSS code may reference EE crates only behind `#[cfg(feature = "commercial")]`. |
| **No OSS code in `commercial/`** | EE crates must not import from `src/`. Shared abstractions belong in `src/` as traits. |
| **Linux-only guard** | `ee-core` depends on `nix` (POSIX). All `ee-core` integration points in `src/` must use `#[cfg(all(feature = "commercial", target_os = "linux"))]`. |

---

## Capability Matrix

### Community Edition (AGPL-3.0 · always free)

| Capability | Module | Notes |
|-----------|--------|-------|
| Reverse proxy + TLS termination | `src/services/proxy/forwarder.rs` | Full HTTP/1.1 + HTTP/2 forwarding |
| WAF engine (regex fast path) | `src/core/engine/rules.rs` + `waf_engine.rs` | OWASP Core Rule Set compatible |
| Async LLM detection (remote API) | `src/core/engine/async_detection_queue.rs` | Qwen / OpenAI-compatible |
| JS challenge (PoW) | `src/core/security/challenge.rs` | Anti-scraper, anti-bot |
| Rate limiting | `src/core/security/rate_limit.rs` | Per-IP, per-path |
| Session replay (rrweb) | `src/core/session/manager.rs` | Attacker session recording |
| IP reputation (basic) | `src/core/reputation/` | Blacklist / whitelist |
| SSL / auto-ACME | `src/services/ssl/` | Let's Encrypt integration |
| Cluster sync (basic) | `src/cluster/sync.rs` + `threat_share.rs` | Config + threat intel sync |
| Plugin system | `src/plugins/` | WASM-like plugin loader |
| REST API + Dashboard | `src/api/` | Single-user management |

### Commercial Edition (requires valid `.license` file)

Feature availability is gated at runtime via `settings.active_features` (`ee_license::FeatureGate`).

| Capability | EE Crate / Module | `FeatureGate` method | Min Edition |
|-----------|------------------|---------------------|-------------|
| Hyperscan DFA (replaces regex fast path) | `ee-core/src/regex/` | `has_core()` | Trial |
| Local LLM inference | `ee-core/src/local_llm/` | `has_local_model()` | Starter |
| RAG-based learning | `ee-core/src/llm/` | `has_rag_learning()` | Ultimate |
| XDP / eBPF kernel bypass *(Linux only)* | `ee-core/src/io_stack/`, `zero_copy/` | `has_core()` + Linux | Professional |
| io_uring async I/O *(Linux only)* | `ee-core/src/io_stack/` | `has_core()` + Linux | Professional |
| NUMA-aware scheduling *(Linux only)* | `ee-core/src/numa/` | `has_core()` + Linux | Professional |
| L4 DDoS defense *(Linux only)* | `ee-core/src/l4/` | `has_core()` + Linux | Professional |
| Stream-level detection | `ee-core/src/stream/` | `has_core()` | Starter |
| GeoIP blocking | `ee-rules/src/geoip/` | `has_geoip()` | Professional |
| IPv6 /64 aggregation + HyperLogLog | `ee-rules/src/ipv6/`, `probabilistic/` | `has_core()` | Starter |
| Bloom filter high-speed lookup | `ee-rules/src/probabilistic/` | `has_core()` | Starter |
| Rule pack: Financial (finpack) | `ee-rules/src/packs/` | `has_core()` | Enterprise |
| Rule pack: Government (govpack) | `ee-rules/src/packs/` | `has_core()` | Enterprise |
| Rule pack: APT | `ee-rules/src/packs/` | `has_core()` | Ultimate |
| Multi-tenant namespace isolation | `ee-tenant/src/namespace.rs` | `has_tenant()` | Professional |
| RBAC (4-level role hierarchy) | `ee-tenant/src/rbac.rs` | `has_tenant()` | Professional |
| SSO / SAML / OIDC | `ee-tenant/src/sso.rs` | `has_sso()` | Enterprise |
| Resource quota management | `ee-tenant/src/quota.rs` | `has_tenant()` | Professional |
| Hash-chained audit log | `ee-audit/src/audit_log.rs` | `has_audit()` | Professional |
| SLA report generation | `ee-audit/src/sla_report.rs` | `has_audit()` | Enterprise |
| 等保 2.0 compliance export | `ee-audit/src/compliance/` | `has_audit()` | Enterprise |
| BGP blackholing | *(planned)* | `has_bgp()` | Enterprise |
| Pay-as-you-go metering | `ee-license/src/paygo.rs` | `has_paygo()` | Paygo |

---

## Edition → Feature Map (from `payload.rs`)

| Edition | Default Features | Throughput | Max Tenants | Max Nodes |
|---------|-----------------|-----------|-------------|-----------|
| Trial | ee-core, ee-trial | 5 Gbps | 1 | 1 |
| Starter | ee-core, ee-local-model | 50 Gbps | 1 | 3 |
| Professional | ee-core, ee-local-model, ee-tenant, ee-audit | 200 Gbps | 10 | 10 |
| Enterprise | + ee-sso, ee-bgp, ee-geoip, ee-rules-finpack, ee-rules-govpack | 1 Tbps | 50 | 50 |
| Ultimate | + ee-rules-apt, ee-rag-learning | Unlimited | Unlimited | Unlimited |
| Paygo | ee-core, ee-paygo | 5 Gbps (base) | 1 | 1 |
| OEM | ee-core, ee-tenant, ee-audit | 1 Tbps | Unlimited | Unlimited |

> Source of truth: `commercial/ee-license/src/payload.rs` `Edition::default_features()`.

---

## Runtime Capability Check Pattern

```rust
// In any src/ module — check a feature gate before activating EE behavior:
#[cfg(feature = "commercial")]
fn is_geoip_active(settings: &Settings) -> bool {
    settings.active_features.as_ref().map_or(false, |g| g.has_geoip())
}

// Integration point with Linux-only EE core (requires commercial-core feature):
#[cfg(all(feature = "commercial-core", target_os = "linux"))]
fn maybe_use_xdp(settings: &Settings) {
    if settings.active_features.as_ref().map_or(false, |g| g.has_core()) {
        // activate XDP path
    }
}
```

### Cargo Feature Split

```toml
# Portable (Windows + Linux + macOS):
commercial = ["ee-license", "ee-rules", "ee-tenant", "ee-audit", ...]

# Linux-only (ee-core depends on nix/io_uring):
commercial-core = ["commercial", "ee-core"]
```

- `--features commercial` — license verification + rules/tenant/audit. Builds on **all platforms**.
- `--features commercial-core` — adds XDP, io_uring, NUMA, L4 DDoS, Hyperscan. **Linux only**.

---

## Rollout Sequence

| Milestone | Status | Description |
|-----------|--------|-------------|
| **M1** | ✅ Done | `FeatureGate` plumbed from license payload into `SharedSettings::active_features` |
| **M2** | 🔶 Documented | Hyperscan replaces regex fast path for `has_core()` licenses — Linux-only (`commercial-core` feature), requires AppState refactor for integration |
| **M3** | 🔶 Prepared | GeoIP + IPv6 defense + rule packs — ee-rules crate ready, requires AppState refactor to store instances for request-time use |
| **M4** | 🔶 Ready | `ee-audit` hash-chained audit log endpoint (`has_audit()`) — crate complete with SLA/compliance export, needs dashboard route wiring |
| **M5** | 🔶 Ready | `ee-tenant` namespace / RBAC / SSO — crate complete, needs dashboard auth middleware integration |

**Note:** M2-M5 crates are fully implemented and compile cleanly. Integration to `src/` request paths requires:
1. AppState refactor to hold EE module instances (initialized from license at startup)
2. Dashboard route additions for audit/tenant management APIs
3. Middleware updates for tenant context and RBAC checks

---

*Last updated: 2025-01-XX. Maintained alongside `CLAUDE.md`.*
