# Changelog

## 2026.03.21 — Security Hardening Release

### Critical Fixes (5/5)
- **C1**: NftablesBackend now compiles per-rule forwarding (was dropping all individual policy rules)
- **C2**: Multi-WAN recovery counter logic fixed (was never triggering recovery)
- **C3**: Vendored htmx + qrcode.js, fixed CSP blocking own scripts
- **C4**: Authentication is now mandatory (refuse to start without --api-key or --enable-rbac)
- **C5**: Fixed mergedThreats data race with atomic.Value

### High Priority Fixes (25/26)
- **H1**: MCP server routed through API auth middleware
- **H2**: XSS in WireGuard page fixed (innerHTML replaced with DOM construction)
- **H3**: Web session cookies accepted by API middleware (htmx forms no longer 401)
- **H4**: Multi-port matching expanded to all ports (was only matching first)
- **H5**: Anti-spoof rules with RFC1918/bogon filtering on WAN
- **H6**: ICMP restricted to safe types (0, 3, 8, 11)
- **H7**: RBAC key cache uses SHA-256 instead of plaintext
- **H8**: Zone subnet overlap validation on create/update
- **H9**: XDP/eBPF marked as experimental with warnings
- **H10**: Broken CIDR matching in countermeasures replaced with net.ParseCIDR
- **H11**: Shell-out nft strings replaced with structured rule descriptors
- **H12**: Fingerprint upsert fixed (ON CONFLICT target corrected)
- **H13**: 810 lines dead driver code deleted
- **H14**: API port no longer hardcoded to 8080
- **H15**: NftablesBackend now builds alias sets for src/dst matching
- **H16**: ApplyWithConfirm timer race with Confirm() fixed
- **H18**: Added --log-level flag (debug/info/warn/error)
- **H19**: Audit middleware persists to DB (not just stdout)
- **H20/H21**: Daily SQLite maintenance (WAL checkpoint + revision pruning)
- **H22**: Logrotate config for daemon logs
- **H25**: Deleted unused VPNBackend/DHCPBackend interfaces
- **H26**: Revision Commit() TOCTOU race fixed with transaction

### Medium Priority Fixes (40+)
- Security: CSRF protection, session store cap, MCP deny-by-default, sysctl path validation, Suricata YAML escaping, content filter deadlock fix
- Network: DHCP range respects prefix length, output chain added, zone deletion checks references, emergency flush fallback, anti-spoof rules
- Code Quality: Sentinel errors, audit log warnings, pagination helper, goroutine leak fixes, test improvements
- Database: Missing indexes added, connection pool tuning, N+1 queries fixed, fingerprint store separated
- Frontend: ARIA attributes, keyboard-accessible tabs, WireGuard modal dialog role, loading states, mobile nav
- DevOps: .dockerignore, CGO_ENABLED=0 in Makefile, Dockerfile HEALTHCHECK + OCI labels, integration test build tags, coverage tracking
- SRE: Enhanced readiness check, SIGHUP drain, PID file race fix, MCP rate limiter cleanup, first-boot key safety

### Low Priority Fixes (15+)
- API key file flag (avoids ps exposure), HSTS header, login rate limiter cleanup, style.css loaded, mobile nav improvements, WireGuard split tunnel support, IPv6 TODO path documented

### Documentation
- Admin guide (auth, operations, backup, troubleshooting)
- MCP server documentation
- Service plugin configuration guide
- README updated with new flags and expanded API table
- PLAN.md corrected (security audit results, HA status)

### Infrastructure
- 13-agent code review framework installed (.agents/)
- Network Engineer agent created (missing from agency-agents repo)
- Deployment plan with build-test loop and rollback procedures
- 15-point smoke test verified at 192.168.7.131
