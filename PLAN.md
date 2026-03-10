# Gatekeeper Implementation Plan

## Executive Summary

Gatekeeper is a Linux-native, LXC-first network firewall and control plane. This plan defines a phased implementation strategy grounded in the design document and its rebuttal. The rebuttal correctly identifies that the full design is too ambitious for v1 — this plan scopes a credible MVP that can ship, then layers on complexity.

**Language:** Go (single binary, good stdlib, SQLite + nftables libraries)
**Target:** Privileged LXC on Proxmox, single-host, IPv4-only for v1

---

## Phase 0: Project Scaffolding

**Goal:** Buildable, testable Go project with CI skeleton.

- [ ] Initialize Go module (`github.com/gatekeeper-firewall/gatekeeper`)
- [ ] Set up directory structure:
  ```
  cmd/
    gatekeeperd/        # daemon entrypoint
    gk/                 # CLI entrypoint
  internal/
    config/             # SQLite config engine
    compiler/           # nftables rule compiler
    api/                # REST API handlers
    model/              # domain types (zones, aliases, profiles, rules, devices)
    driver/             # system drivers (nftables, dnsmasq, wireguard)
    web/                # server-rendered UI
  migrations/           # SQLite schema migrations
  api/                  # OpenAPI 3.1 spec
  web/                  # templates + static assets
  test/                 # integration tests
  scripts/              # build, install, packaging
  ```
- [ ] Add `Makefile` with targets: `build`, `test`, `lint`, `fmt`, `run`
- [ ] Add `.golangci.yml` for linting
- [ ] Add `Dockerfile` (for CI builds, not production)
- [ ] Add GitHub Actions CI: build, test, lint on push

**Exit criteria:** `make build` produces two binaries (`gatekeeperd`, `gk`), `make test` passes, CI green.

---

## Phase 1: Data Model & Config Engine

**Goal:** ACID transactional config store with revision history.

### 1a. SQLite Schema & Migrations

- [ ] Define SQLite schema for core objects:
  - `zones` (id, name, interface, network_cidr, trust_level, description)
  - `aliases` (id, name, type, description) + `alias_members` (alias_id, value)
  - `profiles` (id, name, description, zone_id, policy_name)
  - `policies` (id, name, description, default_action)
  - `rules` (id, policy_id, order, src_alias, dst_alias, protocol, ports, action, log, description)
  - `device_assignments` (id, ip, mac, hostname, profile_id, assigned_at)
  - `config_revisions` (id, rev_number, timestamp, message, snapshot_json)
- [ ] Implement migration runner (embed SQL files, run on boot)
- [ ] WAL mode enabled by default

### 1b. Config Engine

- [ ] `config.Store` — wraps SQLite with transaction helpers
- [ ] CRUD operations for all core objects
- [ ] `Commit(message)` — snapshot current state, increment revision, store diff
- [ ] `Rollback(rev)` — restore state from a previous revision's snapshot
- [ ] `Diff(rev1, rev2)` — return structured diff between two revisions
- [ ] `Export()` — full config as JSON
- [ ] `Import(json)` — restore config from JSON export
- [ ] Alias cycle detection on write (nested aliases)
- [ ] Store diffs incrementally, reconstruct full state on demand (per rebuttal recommendation)

### 1c. Default Seed Data

Per rebuttal: start with **2 zones** (wan, lan), not 8.

- [ ] Seed `wan` zone (upstream, no trust)
- [ ] Seed `lan` zone (10.10.0.0/24, full trust)
- [ ] Seed default `lan-outbound` policy (allow lan → wan)
- [ ] Seed default `deny-all` inter-zone policy
- [ ] Seed `desktop` and `server` profiles only

**Exit criteria:** Config engine passes unit tests for all CRUD, commit/rollback cycle, diff, export/import, and alias cycle detection.

---

## Phase 2: nftables Rule Compiler

**Goal:** Translate config model into nftables rulesets and apply them atomically.

### 2a. Compiler Core

- [ ] `compiler.Compile(config) → nftables.Ruleset` — reads full config, produces nftables rules
- [ ] Resolve aliases recursively (with depth limit)
- [ ] Use nftables **sets** for alias members (enables incremental updates, per rebuttal)
- [ ] Generate per-zone chains with inter-zone policy enforcement
- [ ] Default-deny between zones, explicit allow within policy
- [ ] NAT rules for wan masquerade (per rebuttal: NAT is essential for edge firewall)

### 2b. Apply Engine

- [ ] Use `google/nftables` Go library for netlink-based application (no shelling out)
- [ ] Atomic ruleset replacement via nftables transactions
- [ ] Incremental set updates for alias member changes (add/remove element, not full recompile)
- [ ] `DryRun(config) → string` — return nft ruleset as text without applying
- [ ] Apply-confirm pattern: auto-rollback after configurable timeout unless confirmed
  - Conservative implementation: short default timer (60s), explicit confirm required

### 2c. Validation

- [ ] Pre-apply validation: check for duplicate rules, missing aliases, empty sets
- [ ] Post-apply verification: query nftables state and compare to expected
- [ ] Boot-time validation: load config, compile, validate — enter safe mode on failure

**Exit criteria:** Compiler unit tests cover: basic allow/deny rules, alias expansion, NAT masquerade, set-based aliases. Integration test applies rules to a network namespace and verifies packet filtering with `nft list ruleset`.

---

## Phase 3: REST API

**Goal:** OpenAPI 3.1 API as the single source of truth for all operations.

### 3a. API Server

- [ ] HTTP server (stdlib `net/http` + router, e.g. `chi`)
- [ ] OpenAPI 3.1 spec file in `api/openapi.yaml`
- [ ] API key authentication via `X-API-Key` header
- [ ] Request validation middleware
- [ ] JSON error responses with consistent structure
- [ ] Pagination for list endpoints (per rebuttal: missing from original design)
- [ ] `?dry_run=true` support on mutation endpoints

### 3b. Endpoints (v1)

- [ ] **Aliases:** `GET/POST /api/v1/aliases`, `GET/PUT/DELETE /api/v1/aliases/{name}`, `POST /api/v1/aliases/{name}/members`
- [ ] **Zones:** `GET/POST /api/v1/zones`, `GET/PUT /api/v1/zones/{name}`
- [ ] **Profiles:** `GET/POST /api/v1/profiles`, `GET/PUT /api/v1/profiles/{name}`
- [ ] **Policies:** `GET/POST /api/v1/policies`, `GET/PUT /api/v1/policies/{name}`, rules CRUD nested
- [ ] **Device Assignment:** `POST /api/v1/assign`, `DELETE /api/v1/unassign`, `GET /api/v1/devices`
- [ ] **Config:** `POST /api/v1/config/commit`, `POST /api/v1/config/rollback/{rev}`, `GET /api/v1/config/revisions`, `GET /api/v1/config/diff`, `GET /api/v1/config/export`, `POST /api/v1/config/import`
- [ ] **Diagnostics:** `GET /api/v1/diag/ping/{target}`, `GET /api/v1/diag/interfaces`, `GET /api/v1/diag/connections`, `GET /api/v1/diag/leases`
- [ ] **System:** `GET /api/v1/status`, `POST /api/v1/config/confirm` (for apply-confirm)

### 3c. Security Hardening

- [ ] Rate limiting middleware (per rebuttal)
- [ ] Input sanitization on all string fields
- [ ] Audit log: record all mutations with timestamp, source, action, before/after
- [ ] TLS support (self-signed cert generation on first boot, user-provided cert option)
- [ ] Diagnostics rate-limited and privilege-separated (per rebuttal: security risk)

**Exit criteria:** API integration tests cover all endpoints, auth rejection, pagination, dry-run, rate limiting. OpenAPI spec validates.

---

## Phase 4: CLI (`gk`)

**Goal:** Thin client that talks to the REST API.

- [ ] `gk alias list|show|create|delete|add-member|remove-member`
- [ ] `gk zone list|show|create`
- [ ] `gk profile list|show|create`
- [ ] `gk assign <ip> --profile <name> --hostname <name>`
- [ ] `gk unassign <ip>`
- [ ] `gk policy list|show`
- [ ] `gk test <src> -> <dst>:<port>/<proto>` — path test
- [ ] `gk explain <src> -> <dst>` — show matching rules
- [ ] `gk commit [--message "..."]`
- [ ] `gk rollback <rev>`
- [ ] `gk diff [rev1] [rev2]`
- [ ] `gk status` — daemon health + zone summary
- [ ] `gk export|import` — config backup/restore
- [ ] Connection config: `--api-url`, `--api-key` flags + `~/.gatekeeper.yaml`
- [ ] Table and JSON output formats (`--output json|table`)

**Exit criteria:** CLI can perform full device assignment workflow (create alias → assign device → commit → verify). All commands have `--help` output.

---

## Phase 5: dnsmasq Integration

**Goal:** DHCP/DNS management tied to zones and device assignments.

- [ ] `driver.Dnsmasq` — manages dnsmasq configuration
- [ ] Generate `dnsmasq.conf` from zone/device config:
  - DHCP ranges per zone subnet
  - Static leases from device assignments
  - DNS entries from hostnames
- [ ] Atomic config write + SIGHUP reload (not full restart, per rebuttal)
- [ ] Lease file monitoring: detect new devices, surface in API
- [ ] API endpoints for DHCP lease listing (`/api/v1/diag/leases`)

**Exit criteria:** dnsmasq starts with generated config, serves DHCP for lan zone, static leases match device assignments, lease changes visible via API.

---

## Phase 6: Web UI

**Goal:** Server-rendered dashboard for monitoring and basic operations.

### 6a. Infrastructure

- [ ] Go HTML templates with Tailwind CSS v4
- [ ] htmx for interactive elements (no SPA)
- [ ] Dark mode default, monospace for IPs/addresses
- [ ] Static asset embedding via `embed` package
- [ ] Auth: same API key as REST API (cookie-based session after login)

### 6b. Pages

- [ ] **Dashboard** — zone status cards, device counts, last commit info
- [ ] **Zones** — list with device/alias counts, detail view with rules
- [ ] **Aliases** — searchable list with member expansion
- [ ] **Devices** — assignment table with profile, zone, IP, MAC, hostname
- [ ] **Rules** — visual rule table per policy with test button
- [ ] **Config** — revision timeline with diff view and rollback button
- [ ] **Assign** — form to assign device to profile (primary workflow)

**Exit criteria:** All pages render correctly, device assignment workflow works end-to-end through UI, htmx interactions functional.

---

## Phase 7: WireGuard (Minimal)

**Goal:** Basic VPN peer management, per rebuttal recommendation to keep scope minimal.

- [ ] `driver.WireGuard` — manage WireGuard interfaces and peers
- [ ] API: `GET /api/v1/wg/peers`, `POST /api/v1/wg/peers`, `DELETE /api/v1/wg/peers/{pubkey}`
- [ ] CLI: `gk wg peers`, `gk wg add-peer`, `gk wg remove-peer`
- [ ] Generate client configs (text format for copy/paste)
- [ ] QR code generation for mobile configs (web UI)
- [ ] WireGuard zone integration (vpn zone traffic policies)

**Exit criteria:** Can add/remove WireGuard peers via API/CLI, generated configs work on client devices, vpn zone policies enforced.

---

## Phase 8: Packaging & Distribution

**Goal:** Installable LXC image for Proxmox.

- [ ] Build script producing single static Go binary
- [ ] LXC rootfs tarball (Debian minimal base):
  - `gatekeeperd` + `gk` binaries
  - Embedded web assets
  - nftables, dnsmasq, wireguard-tools packages
  - systemd service files
  - First-boot setup script (generate API key, TLS cert, seed config)
- [ ] Proxmox-compatible container template
- [ ] Install script (signed, not curl|bash per rebuttal)
- [ ] Cloud-init support for headless provisioning
- [ ] Image size target: < 100 MB
- [ ] CalVer versioning (YYYY.MM.patch)

**Exit criteria:** `pct create` with gatekeeper template produces a working firewall container with API accessible, default zones active, and nftables rules applied.

---

## Phase 9: Hardening & Testing

**Goal:** Production-ready stability and security.

- [ ] End-to-end test suite: LXC deploy → API config → packet filtering verification
- [ ] Power-loss simulation: kill -9 during commit, verify recovery
- [ ] Fuzz testing on rule compiler inputs
- [ ] Performance benchmarks: measure overhead vs bare nftables (be honest about results)
- [ ] Startup validation: safe mode if config fails to compile on boot
- [ ] Structured logging (JSON) with configurable outputs (stdout, file, syslog)
- [ ] Prometheus metrics endpoint (`/metrics`): commit counts, rule apply times, API latency
- [ ] Security audit: review all input paths for injection, verify TLS, review auth

**Exit criteria:** All tests pass, benchmarks documented, no critical security findings, clean boot from power loss.

---

## Deferred to v2

Per rebuttal recommendations, the following are explicitly **out of scope for v1**:

| Feature | Reason |
|---|---|
| Plugin system | Attack surface, sandboxing unresolved, premature abstraction |
| MCP/AI integration | Focus on solid API first; AI is a wrapper, not a core feature |
| FRRouting | Changes the product class; most users don't need dynamic routing |
| IPv6 | Requires dual-stack throughout; declare IPv4-only for v1 |
| Multi-node / HA | Niche for v1; design hooks but don't implement |
| Additional zones (6+) | Start with wan/lan, let users create more |
| Additional profiles (6+) | Start with desktop/server, let users create more |
| RBAC | API key auth is sufficient for single-admin v1 |
| GraphQL API | REST is sufficient; avoid API surface bloat |
| Mobile app | Web UI with responsive design is sufficient |

---

## Architecture Decisions Log

| Decision | Choice | Rationale |
|---|---|---|
| Language | Go | Single binary, good stdlib, SQLite/nftables libraries |
| Config store | SQLite (WAL mode) | ACID transactions, embedded, no external deps |
| nftables interaction | `google/nftables` (netlink) | No shelling out, per rebuttal |
| Alias implementation | nftables sets | Incremental updates, O(1) membership lookup |
| Web framework | stdlib + chi router | Minimal deps, well-tested |
| UI rendering | Server-side Go templates + htmx | No JS build chain, fast, simple |
| CSS | Tailwind v4 | Utility-first, no custom CSS maintenance |
| Auth (v1) | API key + TLS | Simple, sufficient for single-admin |
| Default zones | 2 (wan, lan) | Per rebuttal: minimal opinionated defaults |
| NAT | Masquerade on wan | Essential for edge firewall, was missing from design |
| Deployment | Privileged LXC, Proxmox | Defined support matrix per rebuttal |

---

## Milestone Summary

| Phase | Milestone | Core Deliverable |
|---|---|---|
| 0 | Project Scaffolding | Buildable Go project with CI |
| 1 | Config Engine | Transactional SQLite config with revisions |
| 2 | Rule Compiler | nftables compilation + atomic apply |
| 3 | REST API | Full CRUD API with auth and validation |
| 4 | CLI | `gk` command-line client |
| 5 | dnsmasq | DHCP/DNS integration |
| 6 | Web UI | Server-rendered dashboard |
| 7 | WireGuard | Basic VPN peer management |
| 8 | Packaging | LXC image for Proxmox |
| 9 | Hardening | Tests, benchmarks, security audit |

---

## V3 Roadmap (Future)

### Multi-Node Proxmox Support
- Cluster-aware deployment across multiple Proxmox nodes
- Centralized policy management with per-node rule compilation
- Config replication between nodes (etcd or built-in Raft consensus)
- Cross-node HA failover with VRRP and conntrack sync
- Distributed firewall rules that follow VM/CT migrations between nodes
- Per-node health monitoring with cluster-wide dashboard
- Proxmox API integration for automatic node discovery and VM tracking
- Split-brain protection and quorum-based leader election
