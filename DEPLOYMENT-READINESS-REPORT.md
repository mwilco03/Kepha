# Gatekeeper Deployment Readiness Report

**Manager Agent Assessment | 2026-03-21**
**Project:** Kepha/Gatekeeper -- Network Firewall Appliance
**Session under review:** `erudite-ukulele`
**Codebase:** 50,327 lines Go | 35 test files | 90+ API endpoints | 15 HTML templates
**Review team:** Frontend Developer, UX Architect, Security Engineer, Network Engineer, Reality Checker

---

## VERDICT: NOT READY FOR PRODUCTION DEPLOYMENT

The PLAN.md claims all phases complete. The code tells a different story. The architecture is genuinely impressive -- native netlink, parameterized SQL, solid crypto -- but four independent review agents found **4 Critical**, **8 High**, and **13 Medium** severity issues. Several are deployment blockers.

---

## CRITICAL BLOCKERS (must fix before deploy)

### C1. NftablesBackend drops ALL per-rule forwarding rules
- **File:** `internal/backend/firewall_nftables.go:558-594`
- **Impact:** Only emits default action per profile. Individual policy rules are silently ignored. A "deny-all + allow HTTP" policy becomes just "deny-all". The firewall's core function is broken on this code path.
- **Compare:** The text compiler (`compiler.go:172-178`) and netlink driver (`nftables_netlink.go:200-207`) correctly iterate policy rules. The NftablesBackend does not.

### C2. Multi-WAN recovery NEVER triggers
- **File:** `internal/service/multiwan.go:230-231`
- **Impact:** Counter reset/decrement logic makes `recovery_threshold` unreachable. Once a WAN link goes down, it stays down forever. Manual restart required.
- **Bug:** `wan1Fails = 0` then `wan1Fails--` resets to -1 every check. `-wan1Fails` is always 1, so `recoveryThreshold >= 2` is never met.

### C3. CSP blocks the app's own scripts
- **Files:** `internal/web/web.go:428`, `internal/web/templates/_base.html:4`, `internal/web/templates/wireguard.html:62`
- **Impact:** `script-src 'self'` blocks htmx from `unpkg.com` and all inline `<script>` blocks. htmx doesn't load, firewall tabs don't work, WireGuard page is completely inert. The web UI is non-functional with its own security policy.

### C4. Default deployment has ZERO authentication
- **Files:** `cmd/gatekeeperd/main.go:36`, `internal/api/router.go:277-281`, `internal/web/web.go:93-97`
- **Impact:** `--api-key` defaults to empty string. When empty, neither API nor web UI require any authentication. Anyone on the network can create firewall rules, modify DNS, add VPN peers with no credentials.

---

## HIGH SEVERITY (fix before production)

### H1. MCP server has NO cryptographic authentication
- **File:** `internal/mcp/server.go:387-389`
- Principal is self-declared `X-MCP-Principal` header. MCP endpoint bypasses API auth middleware entirely (`cmd/gatekeeperd/main.go:301-303`). Origin check is trivially bypassed by non-browser clients.

### H2. XSS vector in WireGuard page via innerHTML
- **File:** `internal/web/templates/wireguard.html:88-100`
- `loadPeers()` builds HTML via string concatenation from API JSON and injects via `innerHTML`. Peer `name`, `public_key`, `allowed_ips` are not HTML-escaped. Stored XSS if attacker can create a peer with crafted name.

### H3. htmx POST requests to API endpoints silently fail 401
- **Files:** `internal/web/templates/assign.html:11`, `internal/web/templates/services.html:30-32`
- Web UI uses cookie-based session auth. API uses `X-API-Key` header auth. htmx sends cookies but not the API key header. The Assign Device form and Services enable/disable buttons silently fail with 401.

### H4. Netlink multi-port matching only uses first port
- **File:** `internal/driver/nftables_netlink.go:530-539`
- Comment says "For simplicity, matches the first port." A rule for "80,443" only matches port 80 via netlink. Port 443 is silently ignored. Text compiler correctly emits `tcp dport { 80, 443 }`.

### H5. No anti-spoof rules on WAN interface
- **File:** `internal/compiler/compiler.go` (absent)
- Zero RFC1918/bogon ingress filtering. Spoofed packets from external networks pass through forward/input chains.

### H6. ICMP accept-all on input chain includes WAN
- **File:** `internal/compiler/compiler.go:118`
- `ip protocol icmp accept` accepts ALL ICMP types from ALL interfaces including WAN. Should restrict to types 0, 3, 8, 11 and rate-limit on WAN.

### H7. RBAC key cache stores plaintext API keys in memory
- **File:** `internal/rbac/rbac.go:240-241,351-353`
- Cache map keyed by raw plaintext API key. Memory dump exposes all active keys. Should use SHA-256 of key as cache key.

### H8. No zone subnet overlap validation
- **File:** `internal/config/zones.go:42-52`
- `CreateZone()` does zero network validation. Two zones can have overlapping CIDRs, causing ambiguous source zone resolution and incorrect rule application.

---

## MEDIUM SEVERITY

### Frontend/UX
- **M-F1.** No CSRF tokens anywhere. `SameSite=Strict` cookie partially mitigates but is not defense-in-depth.
- **M-F2.** Zero ARIA attributes across entire UI. No `role="dialog"`, no `aria-live` regions, no `aria-current`.
- **M-F3.** Firewall tab bar uses `<div onclick>` -- not keyboard accessible, no tabindex, no ARIA tab roles.
- **M-F4.** WireGuard QR modal has no focus trap, no Escape handler, no `role="dialog"`.
- **M-F5.** Every handler discards store errors (`zones, _ := store.ListZones()`). Database failures render silent empty pages.
- **M-F6.** Login error message shows on any `?error=` query param -- minor phishing vector.

### Security
- **M-S1.** Audit log hardcodes actor as `"api"` even when RBAC key ID is available in context.
- **M-S2.** Session store has no max size. Attacker can grow map unboundedly for 24 hours.
- **M-S3.** MCP permissions default to "all tools accessible" when `cfg.Permissions` is nil.
- **M-S4.** `SysctlSet` has no path validation -- `../../etc/shadow` resolves through `/proc/sys/`. Currently internal-only callers.

### Network
- **M-N1.** DHCP range always `.100-.250` regardless of prefix length. Breaks on anything other than /24.
- **M-N2.** No output chain -- firewall-originated traffic is completely unfiltered.
- **M-N3.** No DNAT/port forwarding support. No prerouting chain, no model for port-forward rules.
- **M-N4.** Text compiler allows API from ALL interfaces; netlink backends restrict to trusted zones. Inconsistent security.
- **M-N5.** Auto-rollback has no kernel-level fallback. If `Apply()` fails during rollback, broken rules persist.
- **M-N6.** Zone deletion has no referential integrity. Deleting a zone with active profiles leaves orphans.

---

## LOW SEVERITY

- No light mode / system preference detection (dark hardcoded)
- Nav bar doesn't collapse on mobile (12+ links wrap into 3-4 rows)
- `style.css` exists but is never loaded by any template (dead file)
- No loading/disabled states on form submit buttons
- No `<main>` landmark element
- No static lease vs DHCP range conflict detection
- WireGuard client config always routes `0.0.0.0/0` (no split tunnel option)
- IPv6 firewall rules exist in `ipv6.go` but are never called by the compiler
- TLS not enforced (server starts in plaintext when no certs provided)
- Login rate limiter never cleans stale entries (slow memory leak)
- API key passed via Basic auth is base64 (cleartext over HTTP)

---

## REALITY CHECK

| Claim in PLAN.md | Verdict |
|---|---|
| All phases complete | **OVERSTATED** -- critical bugs in firewall compilation, multi-WAN, web UI |
| "No shell-outs" | **MISLEADING** -- 16 exec.Command calls remain (core networking IS native, but claim is too broad) |
| OpenAPI spec matches API | **30% coverage** -- spec documents 28 of ~90 endpoints |
| CI/CD pipeline exists | **FALSE** -- zero CI config files. No GitHub Actions, no GitLab CI, nothing. |
| Tests pass | **UNVERIFIED** -- 13.6K lines of test code exist but Go not available to run them |
| No hardcoded credentials | **VERIFIED** -- clean |
| Install script works | **VERIFIED** -- complete, functional 96-line Alpine installer |
| Smoke test is real | **VERIFIED** -- 250-line comprehensive integration test |

---

## ARCHITECTURAL RISK: THREE PARALLEL FIREWALL IMPLEMENTATIONS

Three separate code paths compile firewall rules with **different security properties**:

1. `internal/compiler/compiler.go` -- text-based `nft -f` (allows API from all interfaces)
2. `internal/driver/nftables_netlink.go` -- netlink via google/nftables (restricts API to trusted zones)
3. `internal/backend/firewall_nftables.go` -- NftablesBackend interface (**drops per-rule forwarding entirely**)

These implementations have drifted apart. Pick ONE authoritative path and deprecate the others.

---

## WHAT TO DO NEXT

### Immediate (before any deployment)
1. Fix C1 -- Add per-rule compilation to `NftablesBackend.buildForwardChain()`
2. Fix C3 -- Vendor htmx + qrcode.js into `/static/`, update CSP
3. Fix C4 -- Make `--api-key` or `--enable-rbac` mandatory; refuse to start without auth
4. Fix H3 -- API middleware must accept web session cookies OR htmx must send API key

### Before production
5. Fix C2 -- Multi-WAN recovery counter bug
6. Add anti-spoof rules on WAN (H5)
7. Restrict ICMP to types 0,3,8,11 (H6)
8. Sanitize innerHTML in WireGuard page (H2)
9. Route MCP through auth middleware (H1)
10. Consolidate to one firewall backend

### Track and schedule
- Zone subnet overlap validation
- DHCP range prefix-aware calculation
- CSRF tokens
- Accessibility improvements (ARIA, keyboard nav)
- OpenAPI spec completion (28/90 endpoints documented)
- CI/CD pipeline (currently nonexistent)
- IPv6 compiler integration (code exists, not wired in)
- HA module needs real elector/replicator (currently stubs)

---

## POSITIVE FINDINGS

The code has genuine strengths that should be acknowledged:

- **SQL injection: fully mitigated.** 100% parameterized queries across all config store files.
- **Input validation: comprehensive.** Regex-based validation for names, interfaces, CIDRs, IPs, MACs, hostnames, protocols, ports, WireGuard keys.
- **Session security: solid.** HMAC-SHA256 tokens, server-side store, HttpOnly/Secure/SameSite=Strict cookies, login rate limiting, constant-time comparison.
- **Crypto: correct.** WireGuard key generation uses crypto/rand with proper Curve25519 clamping. TLS config uses TLS 1.2 minimum with ECDHE-only cipher suites.
- **Native netlink: real.** Core firewall, network config, and WireGuard all use pure Go libraries. No shell-out in the critical path.
- **Go template auto-escaping: used correctly.** No `template.HTML` or `template.JS` bypass types anywhere.
- **Test infrastructure: substantial.** 13,595 lines of test code including unit, integration, benchmark, and fuzz tests.
- **Install tooling: production-ready.** Install script and smoke test are both complete and functional.

---

*Report generated by Manager Agent with input from: Frontend Developer, UX Architect, Security Engineer, Network Engineer, Reality Checker*
*Agency agents installed from: https://github.com/msitarzewski/agency-agents*
*Network Engineer agent created for this project (was missing from agency-agents repo)*
