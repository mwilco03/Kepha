# Gatekeeper Punchlist

**Goal:** Production-ready network firewall appliance deployment.
**Status:** NOT READY — 4 Critical, 8 High, 13+ Medium findings from initial review.
**Updated:** 2026-03-21

Items marked `[x]` are verified complete. Items marked `[ ]` are open. Priority order within each severity.

---

## CRITICAL (deployment blockers)

- [ ] **C1 — NftablesBackend drops per-rule forwarding** `internal/backend/firewall_nftables.go:558-594` — Only emits default action. Individual policy rules silently ignored. "deny-all + allow HTTP" becomes "deny-all". *(Network Engineer)*
- [ ] **C2 — Multi-WAN recovery never triggers** `internal/service/multiwan.go:230-231` — Counter reset/decrement logic makes recovery_threshold unreachable. WAN stays down forever. *(Network Engineer)*
- [ ] **C3 — CSP blocks own scripts** `internal/web/web.go:428` — `script-src 'self'` blocks htmx from unpkg.com and inline JS. Web UI non-functional. Vendor htmx+qrcode.js into /static/, update CSP. *(Frontend Developer)*
- [ ] **C4 — Default deployment has zero auth** `cmd/gatekeeperd/main.go:36` — `--api-key` defaults empty. Refuse to start without `--api-key` or `--enable-rbac`. *(Security Engineer)*

---

## HIGH

- [ ] **H1 — MCP server no cryptographic auth** `internal/mcp/server.go:387-389` — Principal is self-declared header. Route MCP through API auth middleware. *(Security Engineer)*
- [ ] **H2 — XSS in WireGuard innerHTML** `internal/web/templates/wireguard.html:88-100` — Peer name/pubkey/allowed_ips unescaped in innerHTML. Use textContent or escapeHtml(). *(Frontend Developer)*
- [ ] **H3 — htmx-to-API auth mismatch** `internal/web/templates/assign.html:11` — Web session cookie not accepted by API middleware. Forms silently 401. *(Frontend Developer)*
- [ ] **H4 — Netlink multi-port uses first port only** `internal/driver/nftables_netlink.go:530-539` — "80,443" only matches 80. Implement anonymous nft sets. *(Network Engineer)*
- [ ] **H5 — No anti-spoof rules on WAN** `internal/compiler/compiler.go` (absent) — No RFC1918/bogon ingress filtering. *(Network Engineer)*
- [ ] **H6 — ICMP accept-all includes WAN** `internal/compiler/compiler.go:118` — Restrict to types 0,3,8,11. Rate-limit on WAN. *(Network Engineer)*
- [ ] **H7 — RBAC cache stores plaintext keys** `internal/rbac/rbac.go:240-241` — Use SHA-256 of key as cache key. *(Security Engineer)*
- [ ] **H8 — No zone subnet overlap validation** `internal/config/zones.go:42-52` — CreateZone() allows overlapping CIDRs. *(Network Engineer)*

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

---

## ARCHITECTURE

- [ ] **A1 — Three parallel firewall backends** — compiler.go, nftables_netlink.go, firewall_nftables.go have drifted apart. Pick one, deprecate others.
- [ ] **A2 — Zero CI/CD** — No GitHub Actions, no pipelines. PLAN.md claims otherwise.
- [ ] **A3 — OpenAPI spec 30% complete** — 28 of ~90 endpoints documented.
- [ ] **A4 — HA module uses stubs** — stub elector, stub replicator, stub conntrack syncer. Not production-ready.

---

## AGENT REVIEW LOG

| Agent | Status | Date |
|-------|--------|------|
| Frontend Developer | Done | 2026-03-21 |
| UX Architect | Done | 2026-03-21 |
| Security Engineer | Done | 2026-03-21 |
| Network Engineer | Done | 2026-03-21 |
| Reality Checker | Done | 2026-03-21 |
| Backend Architect | Pending | — |
| Code Reviewer | Pending | — |
| SRE | Pending | — |
| DevOps Automator | Pending | — |
| Incident Response Commander | Pending | — |
| Technical Writer | Pending | — |
| Threat Detection Engineer | Pending | — |
| Database Optimizer | Pending | — |
| Software Architect | Pending | — |
