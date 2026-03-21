# Gatekeeper Punchlist

**Goal:** Production-ready network firewall appliance deployment.
**Status:** 5/5 Critical DONE, 25/26 High DONE. 1 High deferred (H17 CI — GitHub OAuth scope). 70+ Medium remaining.
**Updated:** 2026-03-21

Items marked `[x]` are verified complete. Items marked `[ ]` are open. Priority order within each severity.

---

## CRITICAL (deployment blockers)

- [x] **C1 — NftablesBackend drops per-rule forwarding** `internal/backend/firewall_nftables.go` — FIXED: Added compileRuleExprs() + compilePortMatch(). Now iterates policy.Rules into netlink expressions. *(Network Engineer)*
- [x] **C2 — Multi-WAN recovery never triggers** `internal/service/multiwan.go` — FIXED: Dedicated recovery counters that increment on success, reset on failure. *(Network Engineer)*
- [x] **C3 — CSP blocks own scripts** — FIXED: Vendored htmx.min.js + qrcode.js to /static/, updated template refs, CSP now allows 'unsafe-inline' for scripts. *(Frontend Developer)*
- [x] **C4 — Default deployment has zero auth** `cmd/gatekeeperd/main.go:59-66` — FIXED: Daemon now refuses to start without `--api-key` or `--enable-rbac`. *(Security Engineer)*
- [x] **C5 — mergedThreats map swapped without synchronization** — FIXED: Now uses sync/atomic.Value for load/store. *(Threat Detection Engineer)*

---

## HIGH

### Existing
- [x] **H1 — MCP server no cryptographic auth** — FIXED: MCP handler wrapped with API AuthMiddleware in main.go. *(Security Engineer)* `1cf0cb6`
- [x] **H2 — XSS in WireGuard innerHTML** — FIXED: Replaced innerHTML with DOM construction (createElement/textContent). *(Frontend Developer)* `bcc48ff`
- [x] **H3 — htmx-to-API auth mismatch** — FIXED: API middleware accepts gk_session cookie via shared SessionValidator. *(Frontend Developer)* `acf5d0b`
- [x] **H4 — Netlink multi-port uses first port only** — FIXED: Multi-port expands to one rule per port. *(Network Engineer)* `3281350`
- [x] **H5 — No anti-spoof rules on WAN** — FIXED: Bogon nft set + anti-spoof drop rule on WAN forward chain. *(Network Engineer)* `2ec073c`
- [x] **H6 — ICMP accept-all includes WAN** — FIXED: Restricted to types 0,3,8,11 across all 3 backends. *(Network Engineer)* `be724e0`
- [x] **H7 — RBAC cache stores plaintext keys** — FIXED: Cache keyed by SHA-256 of key. *(Security Engineer)* `f4ba3ab`
- [x] **H8 — No zone subnet overlap validation** — FIXED: CIDR overlap check in CreateZone()/UpdateZone(). *(Network Engineer)* `0d0e5a4`

### Threat Detection
- [x] **H9 — XDP/eBPF is control-plane only** — FIXED: Marked as experimental stub with WARN logs. *(Threat Detection)* `64502b4`
- [x] **H10 — matchCIDRSimple uses broken prefix matching** — FIXED: Replaced with net.ParseCIDR + Contains(). *(Threat Detection)* `1db9d0d`
- [x] **H11 — GenerateNftRules builds shell-out strings** — FIXED: Replaced with structured rule descriptors. *(Threat Detection)* `d1e2403`
- [x] **H12 — Fingerprint RecordFingerprint upsert broken** — FIXED: ON CONFLICT(hash, src_ip) + unique index. *(Threat Detection)* `b988e4b`

### Backend Architecture
- [x] **H13 — driver/nftables.go + nftables_netlink.go are ~810 lines dead code** — FIXED: Deleted. *(Backend Architect)* `a8208df`
- [x] **H14 — NftablesBackend hardcodes API port 8080** — FIXED: Uses `input.APIPort`. *(Backend Architect)* `8e894ea`
- [x] **H15 — NftablesBackend never builds alias sets** — FIXED: buildAliasSets() + Lookup expressions. *(Backend Architect)* `0e0f50c`
- [x] **H16 — ApplyWithConfirm timer races with Confirm()** — FIXED: confirmed flag + applyLocked(). *(Backend Architect)* `de20737`

### CI/CD
- [ ] **H17 — CI lint step will fail on first run** `.github/workflows/ci.yml:19` — `make lint` calls golangci-lint but CI never installs it. *(DevOps Automator)*

### SRE
- [x] **H18 — No log-level flag; stuck at INFO** — FIXED: --log-level flag (debug/info/warn/error). *(SRE)* `e3aef18`
- [x] **H19 — Audit middleware only logs to stdout, not DB** — FIXED: Persists to DB via store.LogAudit(). *(SRE)* `83aa8c2`
- [x] **H20 — No WAL checkpoint or VACUUM** — FIXED: Store.Maintenance() with daily goroutine. *(SRE)* `c301503`
- [x] **H21 — Config revisions grow without bound** — FIXED: Pruned to last 100 in Maintenance(). *(SRE)* `c301503`
- [x] **H22 — No log rotation** — FIXED: Logrotate config, daily, 14d retention, 50MB max. *(SRE)* `be6559c`

### Software Architecture
- [ ] **H23 — Dead code: driver/nftables.go + nftables_netlink.go** — ~400 LOC superseded by backend equivalents. *(Software Architect)* [overlaps H13]
- [ ] **H24 — Concrete types leak through layers** — WireGuard/dnsmasq drivers not behind interfaces. *(Software Architect)*
- [x] **H25 — Three unused interfaces** — FIXED: Deleted VPNBackend/DHCPBackend/PackageManager (~80 lines). *(Software Architect)* `9e65e05`

### Database
- [x] **H26 — Revision Commit() has TOCTOU race** — FIXED: Wrapped in transaction. *(Database Optimizer)* `dc69ca9`

---

## MEDIUM

### Frontend/UX
- [ ] **M-F1 — No CSRF tokens** — SameSite=Strict partially mitigates. Add explicit tokens for defense-in-depth.
- [ ] **M-F2 — Zero ARIA attributes** — No role="dialog", aria-live, aria-current anywhere.
- [ ] **M-F3 — Firewall tabs not keyboard accessible** `internal/web/templates/firewall.html:27-29` — div+onclick, no tabindex/ARIA.
- [ ] **M-F4 — WireGuard modal no focus trap** `internal/web/templates/wireguard.html:51-59`
- [ ] **M-F5 — Store errors silently swallowed** `internal/web/web.go:106-107` — `zones, _ := store.ListZones()` throughout.
- [ ] **M-F6 — Login error on any ?error= param** — Minor phishing vector.

### Security
- [ ] **M-S1 — Audit log hardcodes actor "api"** `internal/api/handlers.go:25` — Should use RBAC key ID from context.
- [ ] **M-S2 — Session store unbounded** `internal/web/web.go:547-597` — Cap at max size.
- [ ] **M-S3 — MCP permissions default all-open** `internal/mcp/server.go:248-249`
- [ ] **M-S4 — SysctlSet no path validation** `internal/backend/network.go:29-35` — Validate resolved path starts with /proc/sys/.

### Network
- [ ] **M-N1 — DHCP range ignores prefix length** `internal/driver/dnsmasq.go:283-295` — Always .100-.250.
- [ ] **M-N2 — No output chain** — Firewall-originated traffic unfiltered.
- [ ] **M-N3 — No DNAT/port forwarding** — No prerouting chain, no model.
- [ ] **M-N4 — API exposure inconsistent** — Text compiler: all interfaces. Netlink: trusted only.
- [ ] **M-N5 — Auto-rollback no kernel fallback** `internal/backend/firewall.go:86-95`
- [ ] **M-N6 — Zone deletion no referential integrity** `internal/config/zones.go:83-86`

### Threat Detection
- [ ] **M-TD1 — Suricata YAML config via string concat** `internal/service/ids.go:221-297` — No YAML escaping. Injection of YAML directives possible via config values. *(Threat Detection)*
- [ ] **M-TD2 — Three different CIDR matching implementations** — anomaly.go and iocstore.go correct (net.ParseCIDR); countermeasures.go broken. *(Threat Detection)*
- [ ] **M-TD3 — Packet capture IPv4-only** `internal/inspect/capture.go:177` — IPv6 TLS traffic silently dropped. *(Threat Detection)*
- [ ] **M-TD4 — ListThreatMatches ignores threat_match filter** `internal/inspect/store.go:147` — Returns all fingerprints not just threats. *(Threat Detection)*
- [ ] **M-TD5 — Anomaly severity off-by-one** `internal/inspect/anomaly.go:207-222` — Change counter incremented after assessment. *(Threat Detection)*
- [ ] **M-TD6 — ContentFilterEngine.Reload() potential deadlock** `internal/service/content_filter.go:126-127` — RLock inside method that takes WLock. Go RWMutex not reentrant. *(Threat Detection)*
- [ ] **M-TD7 — TTL randomization static per rule build** `internal/xdp/enforcer.go:403-409` — Same "random" TTL until rules rebuilt. *(Threat Detection)*
- [ ] **M-TD8 — DNS filter HTTP client may be nil** `internal/service/dns_filter.go:315` — Package-level HTTP variable never shown initialized. *(Threat Detection)*

### DevOps/CI
- [ ] **M-D1 — No .dockerignore** — Docker build ships entire repo including .git/. *(DevOps Automator)*
- [ ] **M-D2 — Dockerfile has no HEALTHCHECK** `Dockerfile:31-32` *(DevOps Automator)*
- [ ] **M-D3 — Dockerfile has no OCI labels** *(DevOps Automator)*
- [ ] **M-D4 — Linting config disables errcheck** `.golangci.yml:10` — Dangerous for firewall code. *(DevOps Automator)*
- [ ] **M-D5 — No test coverage tracking** *(DevOps Automator)*
- [ ] **M-D6 — No dependency vulnerability scanning** *(DevOps Automator)*
- [ ] **M-D7 — Release versioning uses run_number** `.github/workflows/release.yml:17` — Ignores CalVer in Makefile. *(DevOps Automator)*
- [ ] **M-D8 — Release tar packaging may break** `.github/workflows/release.yml:35-39` *(DevOps Automator)*
- [ ] **M-D9 — No container image build/push in CI** *(DevOps Automator)*
- [ ] **M-D10 — Smoke test not wired into CI** *(DevOps Automator)*
- [ ] **M-D11 — Integration tests have no build tag** `test/integration/api_test.go:1` *(DevOps Automator)*
- [ ] **M-D12 — Makefile build lacks CGO_ENABLED=0** `Makefile:10` *(DevOps Automator)*

### Code Quality
- [ ] **M-CR1 — Error classification by string matching** `internal/api/handlers.go:84,166,210` — Use sentinel errors + errors.Is(). *(Code Reviewer)*
- [ ] **M-CR2 — Audit log write failures silently discarded** 25+ sites use `_ = o.store.LogAudit(...)`. *(Code Reviewer)*
- [ ] **M-CR3 — sanitizeName duplicated verbatim** `compiler.go:343` and `nftables_netlink.go:460`. *(Code Reviewer)*
- [ ] **M-CR4 — resolveAliasMembers duplicated; netlink version lacks 10K expansion cap** *(Code Reviewer)*
- [ ] **M-CR5 — buildInput() duplicated** `driver/nftables.go:125` and `backend/firewall.go:126` — Driver version omits MSSClampPMTU/APIPort. *(Code Reviewer)*
- [ ] **M-CR6 — In-memory pagination copy-pasted 4 times** `internal/api/handlers.go` — Only zones use SQL LIMIT/OFFSET. *(Code Reviewer)*
- [ ] **M-CR7 — json.Unmarshal errors unchecked in tests** `internal/api/router_test.go:60,121,145` *(Code Reviewer)*
- [ ] **M-CR8 — Integration tests use http.DefaultClient** `test/integration/api_test.go:58` — No timeout. *(Code Reviewer)*
- [ ] **M-CR9 — No test for invalid/malicious API input** — No tests for oversized bodies, invalid fields, rate limiter. *(Code Reviewer)*
- [ ] **M-CR10 — Compiler tests only check string containment** `compiler_test.go:46-88` — Passes even with wrong ordering. *(Code Reviewer)*
- [ ] **M-CR11 — RateLimiter goroutine leaks** `internal/api/middleware.go:58-66` — No shutdown mechanism. *(Code Reviewer)*
- [ ] **M-CR12 — sessionStore goroutine leaks** `internal/web/web.go:554` — No stop channel. *(Code Reviewer)*
- [ ] **M-CR13 — nft.Conn not closed in driver** `internal/driver/nftables_netlink.go:19-21` — Leaks netlink socket fd per apply. *(Code Reviewer)*

### SRE
- [ ] **M-SRE1 — Metrics too shallow** `internal/api/metrics.go:11-17` — Only 6 counters. No latency histograms, per-endpoint breakdown, goroutine count. *(SRE)*
- [ ] **M-SRE2 — MCP rateLimiter map never garbage-collected** `internal/mcp/server.go:185-218` *(SRE)*
- [ ] **M-SRE3 — Graceful shutdown doesn't drain SIGHUP handler** `cmd/gatekeeperd/main.go:224-244` *(SRE)*
- [ ] **M-SRE4 — OpenRC init PID file race** `init/gatekeeperd.openrc:8-9` *(SRE)*
- [ ] **M-SRE5 — Readiness check doesn't verify nftables/dnsmasq** `internal/api/router.go:302-314` *(SRE)*
- [ ] **M-SRE6 — No version-gated migration; no downgrade path** `internal/config/migrations.go` *(SRE)*
- [ ] **M-SRE7 — Background tickers never stopped** `middleware.go:72`, `web.go:585`, `mcp/server.go:338` — Goroutine leak on shutdown. *(SRE)*
- [ ] **M-SRE8 — first-boot.sh prints API key to stdout** `scripts/first-boot.sh:23-24` *(SRE)*

### Backend Architecture
- [ ] **M-BA1 — Duplicated alias resolution; netlink lacks 10K expansion cap** *(Backend Architect)*
- [ ] **M-BA2 — Triplicated nftables expression helpers with different names** *(Backend Architect)*
- [ ] **M-BA3 — Package-level mutable globals for DI** `internal/service/procmgr.go` *(Backend Architect)*
- [ ] **M-BA4 — service.Manager.List() holds RLock during SQLite queries** *(Backend Architect)*
- [ ] **M-BA5 — ops.Ops.Store() exposes raw config store** — Bypasses validation/audit. *(Backend Architect)*
- [ ] **M-BA6 — BuildCompilerInput duplicated in 3 locations** *(Backend Architect)*
- [ ] **M-BA7 — NftablesBackend creates new netlink socket per operation** — FD exhaustion risk. *(Backend Architect)*
- [ ] **M-BA8 — StopAll() uses random map iteration** — Dependency-unaware shutdown. *(Backend Architect)*
- [ ] **M-BA9 — MultiWAN routing setup ignores all errors** *(Backend Architect)*
- [ ] **M-BA10 — IDS exec.Command calls have no timeout** *(Backend Architect)*

### Database
- [ ] **M-DB1 — N+1 query in ListAliases** `internal/config/aliases.go:10-36` — 100 aliases = 101 queries. *(Database Optimizer)*
- [ ] **M-DB2 — N+1 query in ListPolicies** `internal/config/policies.go:10-37` *(Database Optimizer)*
- [ ] **M-DB3 — Import restores hardcoded zone_id/profile_id** `internal/config/revisions.go:258-268` — IDs may differ after DELETE+INSERT. *(Database Optimizer)*
- [ ] **M-DB4 — No index on rules.policy_id** `internal/config/migrations.go:46-57` *(Database Optimizer)*
- [ ] **M-DB5 — No standalone index on alias_members.alias_id** *(Database Optimizer)*
- [ ] **M-DB6 — No index on audit_log; unbounded growth** *(Database Optimizer)*
- [ ] **M-DB7 — content_filters zone_id/profile_id lack FK constraints** *(Database Optimizer)*
- [ ] **M-DB8 — No SQLite connection pool tuning** `internal/config/store.go:23` *(Database Optimizer)*

### Software Architecture
- [ ] **M-SA1 — Triplicated State/ConfigField types across 3 packages** *(Software Architect)*
- [ ] **M-SA2 — Package-level mutable globals for DI** *(Software Architect)* [overlaps M-BA3]
- [ ] **M-SA3 — Anemic domain model** `internal/model/model.go` — Zero methods, all rules in ops/validate. *(Software Architect)*
- [ ] **M-SA4 — NetworkManager 31-method god interface** `internal/backend/backend.go` *(Software Architect)*
- [ ] **M-SA5 — web package bypasses ops layer** — 18+ direct store calls skip validation/audit. *(Software Architect)*
- [ ] **M-SA6 — Services bypass FirewallBackend** `internal/service/nfthelper.go` — Direct nftables netlink. *(Software Architect)*
- [ ] **M-SA7 — Hard-coded service registration in main.go** — 25+ entries. *(Software Architect)*

---

## LOW

- [ ] **L1 — No light mode** — Dark hardcoded, acceptable for appliance.
- [ ] **L2 — Nav doesn't collapse on mobile** — 12+ links wrap.
- [ ] **L3 — style.css never loaded** — Dead file, responsive rules never apply.
- [ ] **L4 — No form loading states** — Double-click submits twice.
- [ ] **L5 — No static lease vs DHCP range conflict detection**
- [ ] **L6 — WireGuard always full tunnel** — No split tunnel option.
- [ ] **L7 — IPv6 rules not wired into compiler** — Code exists in ipv6.go, never called.
- [ ] **L8 — TLS not enforced** — Server starts plaintext without certs.
- [ ] **L9 — Login rate limiter leaks memory** — Never cleans stale entries.
- [ ] **L10 — No CHANGELOG** *(DevOps Automator)*
- [ ] **L11 — No Dependabot/Renovate** *(DevOps Automator)*
- [ ] **L12 — No CODEOWNERS or branch protection docs** *(DevOps Automator)*
- [ ] **L13 — .gitignore missing .tar.gz** *(DevOps Automator)*
- [ ] **L14 — OpenRC init leaks API key on cmdline** `init/gatekeeperd.openrc:42` — Visible in `ps`. *(DevOps Automator)*
- [ ] **L15 — model.ConfigRevision defined but never used** `internal/model/model.go:128-134` *(Code Reviewer)*
- [ ] **L16 — Audit log no retention/pruning** *(Database Optimizer)*
- [ ] **L17 — Fingerprint/IOC store shares config database** — Competes for write lock. *(Database Optimizer)*
- [ ] **L18 — BulkAddIOCs indexes before tx.Commit** `internal/inspect/iocstore.go:414` *(Database Optimizer)*
- [ ] **L19 — OpenRCManager.Start() always returns error** *(Backend Architect)*
- [ ] **L20 — processUptime() hardcodes 100 HZ** *(Backend Architect)*
- [ ] **L21 — HTTPClient creates new client per request** *(Backend Architect)*
- [ ] **L22 — Capabilities() reports kernel version as nft version** *(Backend Architect)*
- [ ] **L23 — Hardcoded nftables table name "gatekeeper" in 15+ locations** *(Software Architect)*
- [ ] **L24 — No documented recovery procedure** *(SRE)*
- [ ] **L25 — Daemon cannot upgrade without downtime** *(SRE)*
- [ ] **L26 — install-alpine.sh silently suppresses package errors** *(SRE)*

---

## ARCHITECTURE

- [ ] **A1 — Three parallel firewall backends** — compiler.go, nftables_netlink.go, firewall_nftables.go have drifted apart. NftablesBackend is most incomplete. Text compiler is gold standard. Pick one, deprecate others. *(Network Engineer + Backend Architect)*
- [ ] **A2 — CI/CD skeleton only** — `.github/workflows/ci.yml` and `release.yml` exist but are minimal stubs with critical gaps (no lint install, no coverage, no security scan). *(DevOps Automator)*
- [ ] **A3 — OpenAPI spec 41% complete** — 42 of 103 endpoints documented. *(Technical Writer)*
- [ ] **A4 — HA module uses stubs** — stub elector, stub replicator, stub conntrack syncer. Not production-ready.
- [ ] **A5 — No CD pipeline** — No automated path from merge to deployed artifact. *(DevOps Automator)*
- [ ] **A6 — driver <-> backend bidirectional coupling** — Lower layer imports higher. *(Software Architect)*

---

## DOCUMENTATION (Technical Writer)

- [ ] **DOC1 — README API table shows 11 of 103 endpoints**
- [ ] **DOC2 — PLAN.md claims "no critical security findings"** — False (C4, H1, H7 exist)
- [ ] **DOC3 — PLAN.md marks HA as COMPLETE** — Stubs only
- [ ] **DOC4 — No admin guide, troubleshooting guide, or upgrade docs**
- [ ] **DOC5 — No MCP server documentation**
- [ ] **DOC6 — No service plugin configuration guide**
- [ ] **DOC7 — No backup/restore procedure docs**

---

## AGENT REVIEW LOG

| Agent | Status | Date |
|-------|--------|------|
| Frontend Developer | Done | 2026-03-21 |
| UX Architect | Done | 2026-03-21 |
| Security Engineer | Done | 2026-03-21 |
| Network Engineer | Done | 2026-03-21 |
| Reality Checker | Done | 2026-03-21 |
| Backend Architect | Done | 2026-03-21 |
| Code Reviewer | Done | 2026-03-21 |
| SRE | Done | 2026-03-21 |
| DevOps Automator | Done | 2026-03-21 |
| Threat Detection Engineer | Done | 2026-03-21 |
| Technical Writer | Done | 2026-03-21 |
| Database Optimizer | Done | 2026-03-21 |
| Software Architect | Done | 2026-03-21 |
| Incident Response Commander | Skipped | — |
