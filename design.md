# Gatekeeper — Problem Statement & Design Prompt

## The Problem

There is no LXC-native network firewall that was designed for automation.

The firewall/router space has three camps, and all of them leave a gap:

**BSD firewalls (OPNsense, pfSense)** have the best management interfaces — OPNsense
has 2000+ REST API endpoints, alias-based policy, and a mature web UI. But they are
FreeBSD. They cannot run in Linux containers. They require a full virtual machine,
which means hypervisor overhead in the packet path. At 10 Gbps, that overhead is
measurable and permanent.

**Router-first projects (VyOS, FRR)** are Linux-native and could run in LXC, but
they are routers with firewalls bolted on, not firewalls with routing capability.
VyOS has a single-endpoint API that wraps a CLI session. Its config can corrupt on
power loss. Its stable builds are paywalled. Its LXC networking support is broken.
The community is fractured.

**Embedded router firmware (OpenWrt)** runs beautifully in LXC at near-wire speeds.
But its API (ubus) was designed for local bus communication on embedded hardware,
not for external automation. Its firewall configuration is powerful but expressed
in UCI, a format hostile to programmatic manipulation. No MCP server exists.

**What is missing** is a Linux-native, LXC-first firewall that:
- Has an API designed for external consumers, not retrofitted onto a CLI
- Uses aliases as the primary unit of policy, not IP addresses or interfaces
- Ships with opinionated secure defaults that work without configuration
- Exposes a native MCP server so AI agents can manage network policy
- Runs nftables in the host kernel namespace for line-rate packet processing
- Treats configuration as a database transaction, not a text file

This project fills that gap.

---

## Name

**Gatekeeper** (working title). A firewall that knows who belongs where.

---

## Design Principles

1. **Alias-first, not rule-first.** The primary object is the alias (a named group).
   Rules reference aliases. Devices are added to aliases. You never write a rule for
   a device. You never touch a rule after initial setup.

2. **Opinionated defaults, override anything.** Ships with a default zone/policy set
   that is secure out of the box (default-deny inter-zone, allow egress from trusted).
   Every default can be overridden. No blank-slate configuration.

3. **API-first, CLI-second, GUI-third.** The REST API is the source of truth. The CLI
   is a thin client to the API. The web UI is a thin client to the API. There is one
   code path for all mutations.

4. **Don't rebuild what's solved.** nftables is the firewall. dnsmasq is DHCP/DNS.
   WireGuard is VPN. FRRouting is dynamic routing. SQLite is config storage. Tailwind
   is the UI framework. We build the orchestration layer, not the packet engine.

5. **Config is a transaction, not a file.** All config changes go through an ACID
   transaction in SQLite. No config corruption on power loss. Full rollback history.
   Atomic commits. Diff any two states.

6. **MCP is native, not a wrapper.** The MCP server is built into the daemon, not a
   sidecar that screen-scrapes the API. It shares types, validation, and auth with
   the API. An AI agent has the same capabilities as a human operator.

7. **Plugins extend, core is minimal.** The core handles: aliases, zones, firewall
   rules, DHCP, DNS, and WireGuard. Everything else (IDS, traffic shaping, captive
   portal, ad blocking) is a plugin. Plugins register API endpoints, MCP tools, CLI
   commands, and UI pages through a single manifest.

---

## Architecture

```
+------------------------------------------------------------------+
|  LXC Container (Debian/Alpine minimal)                           |
|                                                                  |
|  +------------------+    +------------------+    +-----------+   |
|  |  gatekeperd      |    |  gatekeeper-web  |    |  MCP      |   |
|  |  (daemon)        |    |  (UI server)     |    |  server   |   |
|  |                  |    |                  |    |           |   |
|  |  REST API        |    |  Tailwind CSS    |    |  Native   |   |
|  |  Config engine   |    |  Server-rendered |    |  25+ tools|   |
|  |  nftables driver |    |  Calls REST API  |    |  SSE tx   |   |
|  |  Plugin host     |    |                  |    |           |   |
|  +--------+---------+    +--------+---------+    +-----+-----+   |
|           |                       |                    |         |
|           +----------+------------+--------------------+         |
|                      |                                           |
|  +-------------------v-----------------------------------------+ |
|  |  SQLite (config store)                                      | |
|  |  - Current config (WAL mode, ACID)                          | |
|  |  - Revision history (every commit stored)                   | |
|  |  - Rollback targets                                         | |
|  +-------------------------------------------------------------+ |
|                      |                                           |
|  +-------------------v-----------------------------------------+ |
|  |  System drivers (thin wrappers, no business logic)          | |
|  |                                                              | |
|  |  nftables   dnsmasq   WireGuard   FRRouting   sysctl       | |
|  |  (nft CLI)  (config)  (wg CLI)    (vtysh)     (proc)       | |
|  +-------------------------------------------------------------+ |
|                                                                  |
|  eth0 (zone: wan)    eth1 (zone: lan)    eth2 (zone: lab) ...   |
+------------------------------------------------------------------+
```

### Component Responsibilities

**gatekeeperd** — The daemon. Single Go or Rust binary. Owns:
- REST API (OpenAPI 3.1 spec, generated docs)
- Config engine (SQLite transactions, schema migrations, validation)
- nftables rule compiler (translates aliases/zones/policies into nft rulesets)
- Plugin host (loads plugin manifests, mounts their API routes)
- System driver interface (thin wrappers that shell out to nft, wg, dnsmasq, etc.)

**gatekeeper-web** — The UI. Separate process, optional.
- Server-rendered HTML (no SPA framework, no React, no build step in production)
- Tailwind CSS (utility-first, no custom CSS unless unavoidable)
- Calls the REST API for all data — zero direct DB access
- Designed for: profile cards, zone maps, alias membership, rule visualization
- Works on a phone. Not a dashboard — a control panel.

**MCP server** — Built into gatekeeperd, not a sidecar.
- Exposes 25+ tools matching API surface (alias CRUD, zone management, rule ops,
  config commit/rollback, diagnostics, WireGuard peer management)
- SSE transport for real-time streaming
- TypeScript-compatible tool schemas with Zod-equivalent validation
- Auth: same API key system, scoped permissions

**gatekeeper CLI** — Thin client binary.
- Talks to the REST API (localhost or remote)
- Output: human-readable by default, `--json` for scripting
- Tab completion for aliases, zones, profiles
- `gk alias list`, `gk zone show lab`, `gk commit`, `gk rollback`, `gk diff`

---

## Data Model

### Core Objects

```
Zone
  - name: string (unique)
  - trust_level: enum (full, high, earned, none, hostile)
  - interface: string (eth0, eth1, etc.)
  - vlan: int | null
  - subnet: cidr
  - gateway: ip | null
  - dhcp_enabled: bool
  - dns_enabled: bool
  - default_egress: enum (allow, deny, vpn_only, proxy_only)

Alias
  - name: string (unique)
  - type: enum (host, network, port, mac, nested, external_url)
  - members: list[string]  (IPs, CIDRs, other alias names, URLs)
  - description: string

Policy
  - name: string (unique)
  - rules: list[Rule]

Rule
  - action: enum (allow, deny, reject, log)
  - direction: enum (in, out, forward)
  - source: alias_ref | zone_ref | "any"
  - destination: alias_ref | zone_ref | "any"
  - ports: list[int] | null
  - protocol: enum (tcp, udp, icmp, any)
  - log: bool
  - description: string

Profile
  - name: string (unique)
  - zone: zone_ref
  - aliases: list[alias_ref]  (device gets added to these on assignment)
  - policies: list[policy_ref]
  - dhcp: bool
  - static_ip: ip | null
  - description: string
  - decision_hint: string  (used by decision tree / AI agent)

DeviceAssignment
  - ip: ip
  - mac: mac | null
  - hostname: string | null
  - profile: profile_ref
  - assigned_at: timestamp
  - assigned_by: string (user, api_key, or mcp_agent)

ConfigRevision
  - id: int (monotonic)
  - timestamp: datetime
  - author: string
  - message: string
  - diff: json (what changed)
  - snapshot: json (full config at this point)
  - applied: bool
```

### Relationship: How a New Device Gets Network Policy

```
1. Human or AI agent: "Assign 10.20.0.15 to profile lab-server"

2. Gatekeeper:
   a. Looks up profile "lab-server" → zone: lab, aliases: [lab-machines]
   b. Adds 10.20.0.15 to alias "lab-machines"
   c. Creates DeviceAssignment record
   d. Recompiles nftables ruleset (aliases changed, rules unchanged)
   e. Atomically applies new ruleset via `nft -f`
   f. Commits config revision to SQLite

3. Result: Device is now governed by every rule that references "lab-machines".
   No new rules were created. No human wrote a firewall rule.
```

---

## Opinionated Defaults

Gatekeeper ships with a default config. You can deploy it and have a working,
secure, segmented network without writing a single rule.

### Default Zones

| Zone | VLAN | Subnet | Trust | Default Egress | DHCP |
|------|------|--------|-------|----------------|------|
| wan | null | from upstream | n/a | n/a | client |
| lan | 10 | 10.10.0.0/24 | full | allow | server |
| lab | 20 | 10.20.0.0/24 | high | allow | server |
| iot | 30 | 10.30.0.0/24 | none | 80/443 only | server |
| guest | 40 | 10.40.0.0/24 | none | 80/443 only | server |
| vpn | 50 | 10.50.0.0/24 | earned | vpn_only | server |
| storage | 90 | 10.90.0.0/24 | null | deny (no route) | off |
| range | 99 | 10.99.0.0/16 | hostile | deny (proxy only) | off |

### Default Inter-Zone Policy (applied automatically)

```
lan     -> internet:   ALLOW
lan     -> lab:        ALLOW outbound, DENY inbound
lan     -> iot:        DENY (mDNS proxy exception)
lan     -> guest:      DENY
lan     -> range:      DENY
lan     -> storage:    ALLOW

lab     -> internet:   ALLOW
lab     -> lan:        DENY
lab     -> storage:    ALLOW
lab     -> range:      DENY

iot     -> internet:   ALLOW (80, 443 only)
iot     -> *:          DENY

guest   -> internet:   ALLOW (80, 443 only)
guest   -> *:          DENY

vpn     -> internet:   DENY
vpn     -> wg_tunnel:  ALLOW

range   -> internet:   DENY
range   -> proxy:      ALLOW (3128 only)
range   -> *:          DENY

storage -> *:          DENY (L2 only, no routing)
```

These are the rules. They reference zones, not IPs. They exist before you add
a single device. When you add a device, you pick a profile. Done.

### Default Profiles

| Profile | Zone | Auto-aliases | Decision Hint |
|---------|------|-------------|---------------|
| desktop | lan | lan-devices | "Personal device owned by trusted human" |
| server | lab | lab-machines | "Long-running service I control" |
| workstation | lab | lab-machines | "Ephemeral dev/test VM" |
| iot-device | iot | iot-devices | "Smart home device, camera, sensor" |
| guest-device | guest | guest-devices | "Visitor's device" |
| vpn-client | vpn | vpn-clients | "Device routing through VPN tunnel" |
| range-target | range | range-machines | "Hostile/experimental, contained" |
| storage-node | storage | storage-nodes | "Ceph OSD, NFS server, no routing" |

---

## API Design

### Principles
- OpenAPI 3.1 spec, auto-generated docs at `/api/docs`
- Versioned: `/api/v1/...`
- Auth: API key in header (`X-API-Key`) or HTTP Basic
- All mutations return the affected object + revision ID
- Bulk operations supported (assign 50 devices in one call)
- Dry-run mode: `?dry_run=true` returns what would change without applying

### Key Endpoints

```
# Aliases
GET    /api/v1/aliases                    List all aliases
POST   /api/v1/aliases                    Create alias
GET    /api/v1/aliases/{name}             Get alias with members
PUT    /api/v1/aliases/{name}             Update alias
DELETE /api/v1/aliases/{name}             Delete alias
POST   /api/v1/aliases/{name}/members     Add member(s) to alias
DELETE /api/v1/aliases/{name}/members     Remove member(s) from alias

# Zones
GET    /api/v1/zones                      List zones
POST   /api/v1/zones                      Create zone
GET    /api/v1/zones/{name}               Get zone detail
PUT    /api/v1/zones/{name}               Update zone
GET    /api/v1/zones/{name}/devices       List devices in zone

# Profiles
GET    /api/v1/profiles                   List profiles
POST   /api/v1/profiles                   Create profile
GET    /api/v1/profiles/{name}            Get profile
PUT    /api/v1/profiles/{name}            Update profile

# Device Assignment (the primary workflow)
POST   /api/v1/assign                     Assign device to profile
DELETE /api/v1/assign/{ip}                Unassign device
GET    /api/v1/assign                     List all assignments
GET    /api/v1/assign/{ip}                Get device assignment

# Policies
GET    /api/v1/policies                   List policies
POST   /api/v1/policies                   Create policy
GET    /api/v1/policies/{name}            Get policy with rules
PUT    /api/v1/policies/{name}            Update policy

# Config Management
POST   /api/v1/config/commit              Commit pending changes
POST   /api/v1/config/rollback/{rev}      Rollback to revision
GET    /api/v1/config/revisions           List revision history
GET    /api/v1/config/diff/{a}/{b}        Diff two revisions
GET    /api/v1/config/pending             Show uncommitted changes
POST   /api/v1/config/export              Export full config (JSON/YAML)
POST   /api/v1/config/import              Import config (merge or replace)

# Diagnostics
GET    /api/v1/diag/interfaces            Interface status + counters
GET    /api/v1/diag/routes                Routing table
GET    /api/v1/diag/nft                   Current nftables ruleset
GET    /api/v1/diag/dns                   DNS cache stats
GET    /api/v1/diag/dhcp/leases           Active DHCP leases
GET    /api/v1/diag/ping/{target}         Ping from firewall
GET    /api/v1/diag/trace/{target}        Traceroute from firewall
GET    /api/v1/diag/connections            Active connection table (conntrack)

# WireGuard
GET    /api/v1/wg/interfaces              List WG interfaces
POST   /api/v1/wg/interfaces              Create WG interface
GET    /api/v1/wg/peers                   List peers
POST   /api/v1/wg/peers                   Add peer
DELETE /api/v1/wg/peers/{pubkey}          Remove peer

# Plugins
GET    /api/v1/plugins                    List installed plugins
POST   /api/v1/plugins/{name}/enable      Enable plugin
POST   /api/v1/plugins/{name}/disable     Disable plugin
```

---

## MCP Server Tools

Native MCP tools (not API wrappers — they share validation and types with the API):

```
# Alias Management
alias_list           — List all aliases with member counts
alias_get            — Get alias details and members
alias_create         — Create a new alias
alias_add_member     — Add IP/CIDR/MAC to alias
alias_remove_member  — Remove member from alias

# Device Workflow (the thing agents do most)
device_assign        — Assign IP to a profile (adds to aliases, applies policy)
device_unassign      — Remove device from all aliases
device_lookup        — Find what profile/aliases/zone an IP belongs to
device_suggest       — Given a description, suggest a profile (decision tree)

# Zone Operations
zone_list            — List zones with device counts and status
zone_get             — Get zone details including active rules
zone_create          — Create a new zone

# Policy Inspection
policy_list          — List all policies
policy_test          — Test if traffic from A to B on port P would be allowed
rule_explain         — Explain why a specific connection is allowed/blocked

# Config Management
config_commit        — Commit pending changes with a message
config_rollback      — Roll back to a previous revision
config_diff          — Show diff between two revisions or current vs committed
config_export        — Export full config as JSON

# Diagnostics
diag_ping            — Ping a target from the firewall
diag_trace           — Traceroute from the firewall
diag_interfaces      — Show interface status, counters, errors
diag_connections     — Show active connections (conntrack)
diag_dns_lookup      — Resolve a name using the firewall's DNS
diag_dhcp_leases     — Show current DHCP leases

# WireGuard
wg_list_peers        — List WireGuard peers with handshake status
wg_add_peer          — Add a WireGuard peer
wg_remove_peer       — Remove a WireGuard peer
wg_generate_config   — Generate client config for a peer
```

---

## CLI Design

```bash
# Alias operations
gk alias list
gk alias show lab-machines
gk alias add lab-machines 10.20.0.15
gk alias remove lab-machines 10.20.0.15

# Device assignment (the main workflow)
gk assign 10.20.0.15 --profile lab-server --hostname mydb
gk unassign 10.20.0.15
gk devices                          # list all assignments
gk lookup 10.20.0.15                # what profile/zone is this IP in?
gk suggest "a postgres database"    # returns: lab-server

# Zone operations
gk zone list
gk zone show lab
gk zone create dmz --vlan 60 --subnet 10.60.0.0/24 --trust none

# Policy
gk policy list
gk policy show internet-egress
gk test 10.20.0.15 -> 8.8.8.8:53/udp    # would this be allowed?
gk explain 10.20.0.15 -> 10.10.0.1:22   # why is this blocked?

# Config management
gk status                           # show pending changes
gk diff                             # diff pending vs committed
gk commit -m "added db server"
gk log                              # revision history
gk rollback 42                      # roll back to revision 42

# Diagnostics
gk ping 8.8.8.8
gk interfaces
gk connections --zone lab
gk leases

# WireGuard
gk wg peers
gk wg add-peer --name phone --allowed-ips 10.50.0.10/32
gk wg client-config phone           # generate QR code or .conf

# System
gk apply                            # recompile and apply nftables rules
gk export > config.json
gk import < config.json
gk plugin list
gk plugin enable suricata
```

---

## Web UI

### Technology
- Server-rendered HTML (Go templates or Jinja2, depending on daemon language)
- Tailwind CSS v4 (utility-first, no custom CSS file)
- htmx for interactivity (no JavaScript framework, no build step)
- Minimal JS only where htmx is insufficient (e.g., QR code generation)

### Pages

**Dashboard** — Zone map showing all zones as cards with device counts, traffic
summary, and health status. Not a graph-heavy monitoring dashboard. A status board.

**Zones** — List of zones. Click into a zone to see its devices, aliases, and
the rules that apply to traffic entering/leaving that zone.

**Aliases** — Searchable list of all aliases. Click into one to see members,
which rules reference it, and add/remove members inline.

**Profiles** — The profile cards from the design conversation. Each profile is a
card showing: name, zone, trust level, aliases, policies, and the decision hint.
Assigning a device is: click profile, type IP, done.

**Devices** — Table of all assigned devices. Columns: IP, hostname, profile, zone,
aliases, assigned by, assigned at. Filter by zone or profile. Bulk assign/unassign.

**Rules** — Visual rule table. Source and destination shown as alias names with
expand-to-see-members. Color-coded by action (green=allow, red=deny). "Test"
button: enter source IP, dest IP, port — see which rule matches and why.

**Config** — Revision timeline. Each revision shows timestamp, author, message,
and a diff button. Rollback button with confirmation. Export/import buttons.

**WireGuard** — Peer list with QR codes for mobile. Add peer form. Handshake
status (last seen, transfer stats).

**Plugins** — Installed plugins with enable/disable toggles. Plugin pages
appear in sidebar when enabled.

### Design Language
- Clean, dense, information-rich. Not a marketing site.
- Monospace for IPs, CIDRs, aliases. Sans-serif for labels.
- Dark mode default (network engineers work at night).
- Every page has a CLI equivalent shown in a collapsible footer.
- Every action has an "API call" tooltip showing the equivalent curl command.

---

## Plugin System

### Plugin Manifest (plugin.yaml)

```yaml
name: suricata
version: 1.0.0
description: IDS/IPS via Suricata
author: community
requires:
  gatekeeper: ">=1.0.0"
  system: [suricata]           # apt packages to install

# What the plugin registers
api_routes:
  - prefix: /api/v1/plugins/suricata
    handler: suricata_api      # compiled or script

mcp_tools:
  - name: ids_alerts
    description: "List recent IDS alerts"
  - name: ids_block_ip
    description: "Add IP to blocklist from IDS alert"

cli_commands:
  - name: ids
    subcommands: [alerts, block, unblock, status]

ui_pages:
  - path: /ui/suricata
    title: "IDS Alerts"
    sidebar_section: security
    icon: shield

hooks:
  on_device_assign: suricata_register_device
  on_rule_change: suricata_update_rules
  on_commit: suricata_reload

config_schema:
  type: object
  properties:
    mode:
      type: string
      enum: [ids, ips]
      default: ids
    home_networks:
      type: array
      items: { type: string, format: cidr }
```

### Plugin Hooks

Plugins can hook into lifecycle events:
- `on_device_assign` / `on_device_unassign`
- `on_rule_change`
- `on_commit` / `on_rollback`
- `on_zone_create` / `on_zone_delete`
- `on_interface_up` / `on_interface_down`
- `on_dhcp_lease`

### Candidate Plugins (not in core)

- **suricata** — IDS/IPS
- **ntopng** — Traffic analysis and flow visualization
- **squid** — HTTP proxy (for range zone proxy-only egress)
- **adblock** — DNS-based ad blocking (Pi-hole style, using dnsmasq)
- **captive-portal** — Guest network login page
- **traffic-shaping** — QoS via tc/nftables
- **ddns** — Dynamic DNS updates
- **haproxy** — Reverse proxy / load balancer
- **crowdsec** — Collaborative threat intelligence
- **backup-s3** — Config backup to S3-compatible storage

---

## Config Safety

### The VyOS Problem
VyOS stores config as a text file. On power loss, partial writes corrupt it.
Config can disappear entirely. This is unacceptable for a network device.

### Gatekeeper's Approach

1. **SQLite in WAL mode** — Write-Ahead Logging means the database is always
   consistent, even after a crash. Reads never block writes.

2. **Atomic commits** — A config change is: stage changes in a transaction,
   validate the entire resulting state, compile to nftables, apply atomically
   via `nft -f`, then commit the SQLite transaction. If any step fails,
   everything rolls back.

3. **Every revision stored** — Every commit creates a snapshot. You can diff
   any two points in time. Rollback is: load snapshot, recompile, apply.

4. **Apply-confirm pattern** — `gk commit --confirm 300` applies the config
   but automatically rolls back after 300 seconds unless you run `gk confirm`.
   This prevents lockouts from bad firewall rules. If you lose connectivity,
   the old rules come back automatically.

5. **Config export is a single JSON file** — Human-readable, version-controllable,
   diffable. Can be committed to git. Can be imported on a fresh install.

6. **Startup validation** — On boot, gatekeeperd validates the stored config
   against the schema before applying. If validation fails, it boots into a
   safe mode with only management access.

---

## Build & Distribution

### LXC Image
- Base: Debian minimal or Alpine (configurable at build time)
- Total image size target: < 100MB
- Packages: nftables, dnsmasq, wireguard-tools, sqlite3, frr (optional)
- Single binary daemon (gatekeeperd) + web UI static assets
- Proxmox-compatible rootfs tarball, ostype=unmanaged
- Cloud-init support for initial config (API key, management IP)

### Build System
- Container image built via Dockerfile or shell script (not Packer)
- CI: GitHub Actions, produces rootfs tarball + checksums on release
- Version: CalVer (YYYY.MM.patch) — same as OPNsense

### Installation on Proxmox
```bash
# One-liner install (community-scripts pattern)
bash -c "$(curl -fsSL https://raw.githubusercontent.com/org/gatekeeper/main/install.sh)"

# Or manually
pct create 200 /var/lib/vz/template/cache/gatekeeper-2026.03.tar.zst \
  --hostname gatekeeper \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --net1 name=eth1,bridge=vmbr1,ip=10.20.0.1/24 \
  --unprivileged 0 \
  --features nesting=1 \
  --memory 512 \
  --cores 1 \
  --start 1
```

---

## What We Build vs What We Reuse

| Component | Solution | Build or Reuse |
|-----------|----------|----------------|
| Packet filtering | nftables | **Reuse.** In-kernel, battle-tested, line-rate. |
| DHCP/DNS | dnsmasq | **Reuse.** Millions of deployments. |
| VPN | WireGuard | **Reuse.** In-kernel, fast, simple. |
| Dynamic routing | FRRouting | **Reuse.** Optional plugin. |
| Config storage | SQLite (WAL) | **Reuse.** ACID on a single file. |
| UI framework | Tailwind CSS + htmx | **Reuse.** No build step. |
| REST API | OpenAPI 3.1 | **Reuse** spec. Build implementation. |
| MCP protocol | Anthropic MCP spec | **Reuse** spec. Build server. |
| Rule compiler | aliases -> nft rules | **Build.** This is the core value. |
| Config engine | transactions + revisions | **Build.** This is the safety layer. |
| Plugin host | manifest + hooks | **Build.** This is the extension system. |
| CLI | thin API client | **Build.** Small. |
| Web UI | profile cards, zone maps | **Build.** The UX layer. |
| LXC image | rootfs tarball | **Build.** Packaging. |
| Orchestration | alias-first policy model | **Build.** This is the product. |

---

## Implementation Language

**Recommended: Go**

- Single static binary (no runtime dependencies)
- Excellent HTTP server stdlib
- Good SQLite bindings (modernc.org/sqlite, pure Go)
- Good nftables library (google/nftables, netlink-based — no shelling out)
- Template rendering built in
- Cross-compilation for different architectures
- Fast startup (matters for LXC boot time)

**Alternative: Rust**

- Same advantages as Go plus memory safety guarantees
- Smaller binary, lower memory footprint
- Steeper contributor learning curve
- nftables bindings less mature

Either works. Go is pragmatic for a v1. Rust if you want to be building this
for a decade.

---

## Non-Goals (v1)

- Not a full router OS. No OSPF/BGP in core (FRR plugin exists).
- Not a monitoring system. No Prometheus/Grafana integration in core.
- Not a VPN server product. WireGuard is for site-to-site and VPN zones.
- Not a CDN/WAF. No L7 inspection in core (Suricata plugin exists).
- Not multi-node. Single instance. HA is a future concern.
- Not a container runtime. Runs in an LXC, doesn't manage containers.

---

## Success Criteria

1. Deploy Gatekeeper LXC in under 60 seconds.
2. Without any configuration, inter-zone traffic is default-deny.
3. Assign a device to a profile in one API call. Device has full network
   policy within 1 second.
4. An AI agent with MCP access can provision a VM and assign its network
   policy without human intervention.
5. Power-cycle the host. Gatekeeper boots, validates config, applies rules.
   Zero corruption. Zero manual recovery.
6. Route 10 Gbps between zones with < 5% overhead vs bare nftables.
7. Full config export/import. Blow away the LXC, reimport, identical state.

-----
#Rebuttal
-----
Below is a hard rebuttal of the proposal as written, followed by concrete fixes.

## Core rebuttal

The document is strongest as positioning copy and weakest as systems design. It identifies a real usability gap, but it overstates the technical gap, understates the operational difficulty, and mixes product goals that pull against each other.

The biggest issue is this: it claims to be a **firewall-first, automation-first, LXC-native, AI-manageable, line-rate, safe-by-default appliance**, while also being **minimal, plugin-based, thin-wrapper-oriented, API-pure, and suitable for phone administration**. Those goals conflict in multiple places. The design does not yet resolve the conflicts; it mostly declares them away.

There is probably a product here, but not yet a credible v1 architecture.

---

# 1. The problem statement is overstated

## Claim: “There is no LXC-native network firewall designed for automation”

Problem:

* This is too absolute.
* The real gap is narrower: there is no **widely adopted**, **operator-friendly**, **Linux-native**, **policy-centric**, **container-deployable** firewall appliance with a clean external API and strong UX.
* That is not the same as “nothing exists.”

Why this matters:

* Overstating the gap weakens credibility.
* A skeptical reader will immediately think: “nftables exists, OpenWrt exists, router distros exist, people already build this with Debian + nft + Ansible.”

### Better framing

Replace the problem statement with:

* Existing Linux-native tools provide the primitives but not the productized control plane.
* Existing firewall appliances provide the UX but not the deployment model.
* Existing router projects provide the routing stack but not the alias-centric policy model or transactional control plane.

That is more defensible.

---

# 2. The LXC premise is both a strength and a liability

## Claim: LXC-first is a major advantage

True, but incomplete.

Problems:

1. **LXC is not a neutral runtime choice**

   * A firewall is a privileged network control-plane component.
   * Running it in LXC means you inherit the host kernel, host nftables behavior, host conntrack behavior, host module availability, host sysctls, and host interface semantics.
   * You are not shipping an appliance in the same way a VM appliance ships an appliance.

2. **“Runs nftables in the host kernel namespace” is dangerous wording**

   * If it literally means host netns, this is operationally risky and undermines containment.
   * If it means container netns using host kernel, that is normal Linux behavior and not special.
   * If it requires privileged container behavior, you have materially changed the threat model.

3. **Proxmox/LXC networking edge cases are not a footnote**

   * VLAN trunking, bridge filtering, MAC anti-spoof, DHCP relay, multicast, IPv6 RA, WireGuard MTU, conntrack zones, nftables flowtables, and FRR interaction can all get weird depending on host config.
   * “LXC-first” is not just packaging. It is an operating model with a long tail of support problems.

### Fix

Be explicit about supported deployment modes:

* **Mode A:** privileged LXC on Proxmox, dedicated bridges, host-managed NIC passthrough/trunks
* **Mode B:** bare-metal Debian package
* **Mode C:** VM appliance later

Then define the exact support matrix:

* single-host Proxmox only for v1
* IPv4 only in v1, or dual-stack from day one
* supported NIC/interface topologies
* whether VLAN trunking inside LXC is officially supported
* whether FRR inside LXC is supported in v1

Without this, “LXC-first” becomes “debugging-first.”

---

# 3. The performance argument is weaker than presented

## Claim: VM overhead in the packet path is measurable and permanent

Maybe, but this is doing too much rhetorical work.

Problems:

* Whether the overhead matters depends heavily on NIC features, vhost offloads, virtio, CPU pinning, bridge design, packet sizes, conntrack use, and actual deployment.
* Many users will trade a small performance penalty for dramatically better isolation and appliance semantics.
* If your main differentiator is “a few percent faster than a VM,” that is not enough.

### Fix

Downgrade the claim:

* The advantage is not only lower overhead.
* The bigger advantage is **operational fit for homelab/prosumer/self-hosted Linux environments**, smaller footprint, faster boot, easier backup/restore, and direct integration with existing Proxmox workflows.
* Treat performance as a benchmarked property, not a premise.

---

# 4. “Alias-first” is useful, but the model is underdesigned

This is one of the better ideas in the proposal, but it is not complete.

Problems:

1. **Aliases are not enough**

   * Real network policy needs identity dimensions beyond aliases:

     * user identity
     * device posture
     * service identity
     * time windows
     * FQDN sets
     * schedule-based policy
     * protocol/application classes
   * Alias-first helps organize address groups, but it is not a sufficient universal abstraction.

2. **The proposal confuses grouping with intent**

   * “lab-machines” is a group.
   * “server allowed to reach storage on NFS only” is policy intent.
   * Profiles partially bridge this, but the relationships are not clearly normalized.

3. **Nested aliases and external_url aliases are dangerous**

   * Nested aliases can create cycles, explosion in expansion cost, and debugging complexity.
   * URL-derived aliases introduce freshness, fetch failure, integrity, and reproducibility problems.
   * Those are not small details.

4. **You say rules never change after setup**

   * That is aspirational, not realistic.
   * Environments change; services move; temporary exceptions happen; migrations happen.

### Fix

Refine the model:

* Keep aliases, but split them into typed sets:

  * address sets
  * port/service sets
  * device sets
  * dynamic sets
* Add a first-class **service object** abstraction:

  * `service = { proto, ports, helpers, directionality metadata }`
* Add **policy intents** separate from raw rules:

  * `allow profile:server -> zone:storage service:nfs`
* Compile intent into rules.
* For dynamic feeds, require:

  * fetch policy
  * TTL
  * signature/hash pinning
  * fallback behavior
  * last-known-good caching

Also add hard validation:

* no recursive alias cycles
* max expansion size
* deterministic compilation order

---

# 5. The zone/trust model is semantically muddy

## Problem

The proposal introduces `trust_level` values like:

* full, high, earned, none, hostile

This is human-friendly language, but it is underspecified and likely to rot.

Why it is a problem:

* Does trust_level have semantic effect or is it descriptive only?
* If semantic, how does `earned` differ from `high` in compiled policy?
* If descriptive, it does not belong in the core decision model without defined behavior.
* “hostile” sounds nice in UI copy but is not a precise control-plane input.

The defaults also blur L2/L3/L4 semantics:

* “storage -> * deny (L2 only, no routing)” is not just a firewall rule. It is topology and bridging behavior.
* “proxy only” is not a firewall policy alone; it requires service dependency and possibly transparent or explicit proxy design.

### Fix

Replace vague trust labels with explicit policy traits:

* `east_west_default = allow|deny`
* `internet_egress = allow|deny|restricted`
* `dns_mode = recursive|forwarder|blocked|force-local`
* `dhcp_mode = server|relay|off|client`
* `is_routed = true|false`
* `requires_proxy_for_egress = true|false`

Then let the UI optionally map those into human labels.

---

# 6. The default policy set is opinionated, but not deployable as written

The defaults read well. They are not operationally complete.

Problems:

1. **No DNS policy clarity**

   * If guest/iot get 80/443 only, do they get DNS?
   * TCP/UDP 53? DoH only? forced local resolver? blocked external DNS?
   * Same issue for NTP.

2. **mDNS proxy exception is hand-wavy**

   * mDNS across segments is messy and often implementation-specific.
   * “mDNS proxy exception” is not a firewall rule; it is middleware.

3. **Storage zone as “no routing”**

   * That is not enough detail.
   * Is it a bridge-only segment? Are ARP/ND allowed? Is gateway absent? Are ACLs enforced upstream?

4. **VPN zone semantics are underspecified**

   * `vpn -> internet DENY`, `vpn -> wg_tunnel ALLOW` does not explain split tunnel vs full tunnel, NAT policy, peer isolation, route leaking, or access to internal networks.

5. **80/443-only IoT and guest is naïve**

   * Many devices need NTP, DNS, OCSP, STUN/TURN, vendor-specific ports, QUIC/UDP 443, multicast discovery.
   * The defaults will either break many devices or quietly grow into exceptions.

### Fix

Turn the default policies into tested templates:

* `guest-basic`
* `iot-restricted`
* `lab-open`
* `storage-isolated`
* `vpn-egress-via-tunnel`

Each template should define:

* DNS behavior
* NTP behavior
* ICMP policy
* multicast handling
* NAT behavior
* logging defaults
* IPv6 behavior
* exception model

Also document which defaults are enforced by:

* nftables
* dnsmasq
* routing
* proxy integration
* service plugins

Right now several “rules” are actually multi-subsystem behaviors.

---

# 7. The data model is too thin in some places and too loose in others

## Problems with specific objects

### Zone

* One interface per zone is too restrictive for real use.
* Real zones often span:

  * multiple interfaces
  * VLAN subinterfaces
  * bridge members
  * bonded interfaces
  * WireGuard or tunnel interfaces
* `interface: string` is not enough.

### Alias

* `members: list[string]` is too weakly typed.
* You will regret stringly typed config.
* You need typed members with validation and normalized storage.

### Policy / Rule

* The rule model is too simple for nftables reality.
* Missing:

  * address family
  * state/conntrack matching
  * interface selectors
  * negation
  * rate limits
  * schedules
  * priorities
  * NAT
  * marks
  * sets/maps
  * logging target/level/prefix
  * comments/UUIDs/stable identifiers

### Profile

* A profile mixing zone, aliases, policies, DHCP, static IP, and AI hint is doing too much.
* It is partly a role, partly an onboarding template, partly an IPAM record.

### DeviceAssignment

* Keying by IP is a bad anchor.
* IPs change. Devices have multiple IPs. IPv6 makes this much worse.
* MAC is not always stable or trustworthy.
* The primary entity should be a **device identity record** with bindings.

### ConfigRevision

* Storing full snapshots for every revision is simple, but can become bloated.
* More importantly: what is the transaction boundary between database state and runtime state?

### Fix

Refactor around stronger entities:

* `Zone`

  * multiple attachment points
  * explicit routing/NAT properties
* `AddressObject`, `ServiceObject`, `DeviceObject`
* `PolicyIntent`
* `CompiledArtifact`
* `Assignment`

  * device_id
  * binding type: mac, dhcp fingerprint, static mapping, manual IP, WG pubkey, hostname
* `Revision`

  * desired state hash
  * compiled state hash
  * apply result
  * runtime verification result

And use typed tables, not JSON blobs and string lists everywhere.

---

# 8. The config transaction story is incomplete and partially wrong

This is a major issue.

## Claim: “All config changes go through an ACID transaction in SQLite… compile… apply… commit transaction”

Problem:

* SQLite ACID only protects the database, not the external world.
* `nft -f`, dnsmasq reload, wg peer changes, FRR updates, sysctl changes are not inside the SQLite transaction.
* You do not have one atomic transaction. You have a distributed state transition across DB + kernel + daemons.

The proposal treats this as if it were a single commit domain. It is not.

### Failure cases

* DB transaction succeeds, nft apply fails.
* nft apply succeeds, dnsmasq reload fails.
* nft apply and dnsmasq succeed, FRR partially reloads.
* Runtime state changes, then process crashes before revision metadata updates.
* Network is live on new rules, DB says old revision still active.

### Fix

Adopt a **desired-state / compiled-state / applied-state** model.

For every change:

1. Write desired state revision.
2. Compile candidate artifacts.
3. Validate candidate.
4. Apply in ordered phases with per-subsystem idempotent handlers.
5. Record subsystem results.
6. Mark revision active only after success criteria are met.
7. Support compensation/rollback where safe.

In other words, use an internal reconciler, not the fiction of a global transaction.

Also distinguish:

* **staged changes**
* **committed desired changes**
* **successfully applied changes**
* **runtime drift detected**

That is much more honest and operationally robust.

---

# 9. SQLite is fine, but it is not your safety story by itself

The document leans too hard on SQLite WAL as a solution.

Problems:

* WAL protects against DB corruption, not bad logic, not bad schema migrations, not runtime/apply mismatches, not operator lockout.
* Revision history does not help if rollback itself cannot be applied due to environmental drift.
* A single SQLite file is also a single blast radius unless backup/export/import and migration are excellent.

### Fix

Keep SQLite, but narrow the claim:

* SQLite is the persistence layer.
* Safety comes from:

  * schema validation
  * compilation validation
  * apply-confirm
  * last-known-good artifacts
  * boot-safe-mode
  * deterministic migration testing
  * runtime verification after apply

Also store compiled artifacts and known-good fallback artifacts.

---

# 10. The API-first claim is good, but the API surface is not well designed yet

Problems:

1. **Resource design is inconsistent**

   * `/assign` is action-oriented; others are resource-oriented.
   * `/config/commit` and `/config/import` are command endpoints.
   * That is fine if intentional, but then admit the API is mixed RPC/resource style.

2. **No concurrency model**

   * What happens if two clients mutate aliases simultaneously?
   * Need ETags, revision preconditions, or optimistic concurrency.

3. **No auth model detail**

   * “API key in header or Basic” is not serious enough for a firewall appliance.
   * Need scoped principals, audit trails, expiration, rotation, maybe mTLS for remote admin.

4. **No idempotency guarantees**

   * Bulk operations need request IDs or idempotency keys.
   * Especially important for AI agents and automation retries.

5. **No async job model**

   * Some operations will be fast; some will not.
   * Import, plugin install, route convergence, DNS feed fetch, diagnostics may need job handling.

6. **No formal error contract**

   * Need machine-actionable errors:

     * validation
     * conflict
     * compile failure
     * apply failure
     * partial apply
     * auth denied
     * unsafe operation requires confirm

### Fix

Define API rules:

* resource endpoints for state
* command endpoints for transitions
* optimistic concurrency via revision/version fields
* idempotency keys for mutating requests
* structured error schema
* audit event IDs
* long-running operations as jobs
* explicit dry-run diff response shape

Also add:

* `/api/v1/system/capabilities`
* `/api/v1/system/health`
* `/api/v1/system/runtime-drift`

---

# 11. Native MCP is not a differentiator unless the underlying safety model is strong

This section is marketing-heavy and safety-light.

Problems:

* Giving AI agents “the same capabilities as a human operator” is not a feature by itself. It is a risk statement.
* There is no serious permission model described for MCP:

  * tool scoping
  * zone scoping
  * read-only diagnostic roles
  * approval workflows
  * dangerous action gates
* “device_suggest” based on decision hints is likely to be wrong often enough to cause pain.

### Fix

Treat MCP as a constrained automation interface, not a parity interface.

Add:

* per-tool permissions
* per-zone and per-profile scope restrictions
* approval-required actions
* simulation-required actions
* policy guardrails
* tool-specific rate limits
* mandatory audit logs including prompt context hash / requesting principal

For AI-assisted assignment:

* `device_suggest` should return ranked suggestions plus rationale and confidence.
* It should never silently mutate state.
* High-risk profiles should require explicit confirmation or policy-based authorization.

---

# 12. Plugin system is the biggest architectural risk in the whole document

The plugin story is far too easy on paper.

Problems:

1. **Plugins that register API routes, MCP tools, CLI commands, UI pages, hooks, and system dependencies are not “minimal”**

   * That is a full extension platform.
   * This will dominate complexity.

2. **Hook-based plugins can break core guarantees**

   * If a plugin mutates behavior on commit or rule change, your safety and determinism story gets much harder.
   * Rollback now includes plugin side effects.

3. **System package dependencies inside plugins are operationally messy**

   * `apt install` from plugin manifests is not a stable security model.
   * Version conflicts, restart needs, service ownership, config file collisions.

4. **Compiled vs script handlers**

   * Enormous security and support implications.
   * ABI/API compatibility pain.

5. **UI/plugin surface parity is expensive**

   * API + MCP + CLI + UI registration from one manifest sounds elegant, but actual versioning and validation are hard.

### Fix

Shrink plugins dramatically for v1.

Use three classes:

* **Passive plugins:** add read-only diagnostics/pages
* **Managed integrations:** Gatekeeper-owned adapters to specific external services
* **Unsafe extensions:** disabled by default, explicit warning, no core support guarantees

For v1, support only:

* extra UI pages
* extra diagnostic endpoints
* post-commit notifications

Do **not** allow arbitrary hooks into the policy compiler or apply pipeline in v1.

Suricata, Squid, FRR, HAProxy should probably be **integrations**, not general plugins, until the lifecycle model is mature.

---

# 13. “Thin wrappers” around system tools is a trap

The document says the system drivers are thin wrappers and no business logic lives there.

Problem:

* In network appliances, a lot of the business logic ends up being subsystem-specific sequencing, validation, compatibility, state inspection, and rollback semantics.
* If you force the drivers to stay thin, that logic leaks into the daemon in messy ways.
* If you let the drivers grow smart, they are no longer thin wrappers.

### Fix

Adopt a clear adapter pattern:

* compiler emits subsystem-specific desired artifacts
* adapters own apply/verify/rollback for their subsystem
* daemon orchestrates lifecycle and revision state

That is a better boundary than “thin wrappers.”

---

# 14. The nftables compiler is underspecified, and it is the real product risk

The proposal correctly says the rule compiler is core value. It then does not describe it enough.

Missing:

* chain layout
* table/family strategy
* IPv4/IPv6 handling
* NAT model
* priorities/hooks
* set generation strategy
* atomic replace semantics
* connection tracking/stateful defaults
* logging structure
* rule ordering guarantees
* shadowed/contradictory policy detection
* explanation engine design

The `policy_test` and `rule_explain` features are especially hard. You cannot hand-wave these.

### Fix

Design the compiler first.

Document:

* IR: high-level policy intent -> normalized policy graph -> compiled nft artifacts
* deterministic ordering rules
* explainability metadata mapping compiled rules back to user intent
* runtime counters per compiled object
* static analysis:

  * unreachable rules
  * shadowed rules
  * conflicting intents
  * broad exceptions
  * set explosion risk

Without a serious compiler design, the rest is UI.

---

# 15. Diagnostics are more dangerous than they look

Endpoints like:

* ping
* traceroute
* DNS lookup
* conntrack view

are useful, but also security-sensitive.

Problems:

* They can be abused for reconnaissance.
* They need rate limiting and privilege separation.
* “Ping from firewall” is not a generic safe action.
* Conntrack exposure can leak topology and sessions.

### Fix

Split diagnostics into tiers:

* safe read-only status
* privileged operational diagnostics
* dangerous active probing

Add:

* rate limits
* audit logs
* default disabled for remote/API access unless explicitly enabled
* output redaction options

---

# 16. The CLI examples are nice, but there is hidden product confusion

Examples show:

* aliases
* profiles
* zones
* policies
* tests
* explain
* plugins
* wg
* import/export
* apply/commit/rollback

This is already a large product. The proposal still talks like it is a focused v1.

### Fix

Define a ruthless v1:

* zones
* aliases
* profiles
* assignment
* compiler/apply
* rollback
* diagnostics: interface status, leases, ruleset, policy test
* minimal WireGuard or none
* no FRR in core
* no general plugin system
* no AI suggestion engine in v1

Everything else is phase 2.

---

# 17. The UI philosophy is sensible, but there are contradictions

Good:

* server-rendered
* htmx
* not graph-heavy
* dense and practical

Problems:

1. **“Works on a phone” is probably the wrong optimization**

   * Emergency-safe is good.
   * Full administration on a phone should not drive design.
   * Firewalls benefit from clarity and breadth, not squeezed mobile affordances.

2. **Every page having CLI equivalent and curl tooltips is useful but expensive**

   * This can become maintenance debt fast unless generated from shared descriptors.

3. **Dark mode default**

   * Fine, but not important enough to be in the architecture doc.

### Fix

State:

* desktop-first, mobile-tolerant
* emergency actions optimized for mobile
* UI command equivalences auto-generated from API schemas

---

# 18. The security model is underdeveloped for a firewall product

This is the largest non-performance omission.

Missing:

* secrets storage
* TLS termination
* cert management
* local-only bootstrap
* first-run trust establishment
* audit logging
* tamper evidence
* RBAC
* SSO/OIDC considerations
* key rotation
* safe-mode access semantics
* plugin sandboxing
* supply-chain posture
* signed releases
* secure update channel

This is not optional polish. It is core.

### Fix

Add a security section with explicit v1 decisions:

* local bootstrap token printed once or generated via console
* HTTPS mandatory after bootstrap
* API keys hashed at rest
* RBAC with predefined roles:

  * admin
  * operator
  * auditor
  * diagnostics
  * MCP-agent-limited
* append-only audit log
* release signing and artifact verification
* plugin signature requirement, or no third-party plugins in v1

---

# 19. IPv6 is suspiciously absent

This is a serious design omission.

Problems:

* Modern network products cannot treat IPv6 as an afterthought.
* Zones, aliases, DHCP, DNS, WireGuard, router advertisements, NDP, firewall rules, and explainability all change with IPv6.
* If v1 is IPv4-only, say it explicitly.
* If dual-stack, the model must reflect it everywhere.

### Fix

Choose one:

* **Explicit v1 IPv4-only** and explain why
* or
* dual-stack from the start with family-aware data model and compiler

Do not remain ambiguous.

---

# 20. NAT is missing from a firewall/router design

This is a glaring omission.

Problems:

* Any practical edge firewall/router needs a NAT story:

  * SNAT/masquerade
  * port forwards / DNAT
  * hairpin NAT
  * 1:1 NAT possibly
* Without NAT, many default-zone claims are incomplete.

### Fix

Either:

* declare NAT out of scope for v1 and position this as an internal segmentation firewall, or
* add a minimal NAT model to core:

  * outbound NAT policies per zone
  * port forward objects
  * reflection/hairpin option
  * interaction with policy engine

Right now the design reads like an edge firewall but omits a central edge-firewall capability.

---

# 21. DHCP/DNS reuse via dnsmasq is pragmatic, but the integration model is not trivial

Problems:

* dnsmasq is convenient but becomes a control-plane burden when tied tightly to profiles, static assignments, tags, DNS policy, and per-zone behavior.
* Config generation, reload semantics, lease reconciliation, host reservations, PTR records, split-horizon behavior, and DNS policy exceptions all need design.
* “dns_enabled” is too coarse.

### Fix

Define the dnsmasq integration contract:

* generated files owned by Gatekeeper
* no manual edits
* reload strategy
* lease import/reconciliation model
* host reservation source of truth
* DNS ACL policy model
* local zones/search domains
* upstream resolver model
* forced-local DNS option per zone

---

# 22. FRRouting as “optional” is not simple in practice

Problems:

* FRR changes the product class significantly.
* Dynamic routing impacts interface ownership, redistribution, policy semantics, failover, and support expectations.
* Calling it an optional plugin hides its complexity.

### Fix

Remove FRR from v1 entirely, or treat it as a separate distribution flavor later.

---

# 23. The build/distribution section underestimates support costs

Problems:

* Debian minimal vs Alpine is not just configurable packaging. It impacts libc, tool behavior, package availability, and debugging.
* “<100MB image” is vanity unless it materially improves deployment.
* Cloud-init in LXC/rootfs form is often more annoying than it sounds.
* `unprivileged 0` in the Proxmox example is a major security/operational statement that should not be buried in install docs.

### Fix

Pick one base OS for v1. Debian is the safer operational choice.
Document why privileged LXC is required if it is.
Optimize for supportability, not image-size bragging rights.

---

# 24. Success criteria are partly good, partly misleading

Good:

* deploy quickly
* safe defaults
* one-call assignment
* power-cycle integrity
* export/import reproducibility

Problems:

* “10 Gbps with <5% overhead vs bare nftables” is extremely ambitious and may distract the team into benchmark theater.
* “AI agent can provision and assign policy without human intervention” is not a success criterion for a firewall v1. It is a risk criterion.
* “Without any configuration, inter-zone traffic is default-deny” needs careful qualification or users will lock themselves out.

### Fix

Rewrite success criteria around:

* deterministic policy application
* zero-corruption recovery
* explainability
* operator task completion time
* rollback reliability
* safe remote changes
* reproducible imports/exports
* measured performance targets on reference hardware, not universal claims

---

# 25. The proposal mixes product language with implementation commitments too early

Examples:

* Tailwind
* htmx
* dark mode default
* Go vs Rust
* QR codes
* 25+ MCP tools
* CalVer
* one-liner install

These are fine choices, but too many are premature commitments when core semantics are unsettled.

### Fix

Split the document into:

1. problem / positioning
2. product requirements
3. control-plane model
4. runtime/apply model
5. v1 scope
6. implementation notes

Right now implementation details are compensating for unresolved product architecture.

---

# What the proposal gets right

To be fair, several things are genuinely strong:

* alias/group-centered administration is better than raw rule-centric administration for many users
* API-first with shared backend logic is correct
* server-rendered UI is a sane choice
* config revisioning and apply-confirm are essential
* reusing nftables, dnsmasq, WireGuard, SQLite is the right instinct
* the desire for explainability (`policy_test`, `rule_explain`) is excellent
* packaging for Proxmox/LXC is a real adoption wedge

The issue is not that the idea is bad. The issue is that the current design promises too much without resolving the hard parts.

---

# Recommended redesign

## A credible v1

Build **Gatekeeper v1** as:

### Scope

* Linux-native segmentation firewall and small-network control plane
* Proxmox privileged LXC and bare-metal Debian supported
* IPv4 only in v1, unless team is strong enough for dual-stack from day one
* No general plugin system
* No FRR
* Minimal WireGuard, or defer it
* No AI auto-mutation; only AI-assisted read/suggest

### Core objects

* zones
* device objects
* address sets
* service sets
* profiles
* policy intents
* assignments
* revisions
* compiled artifacts

### Core workflows

* create zone
* create profile
* assign device to profile
* test/explain policy
* commit/apply/rollback
* import/export
* inspect runtime drift

### Runtime model

* desired state in SQLite
* deterministic compiler to nftables + dnsmasq artifacts
* ordered apply phases
* verification after apply
* last-known-good fallback
* apply-confirm

### Security

* local bootstrap
* TLS
* RBAC
* audit log
* scoped API keys
* no third-party plugins in v1

### Diagnostics

* leases
* interfaces
* ruleset
* policy test/explain
* maybe ping
* no traceroute/conntrack unless strongly gated

---

# Recommended technical corrections

## 1. Replace “config transaction” with “reconciliation pipeline”

Use this language everywhere.

## 2. Add an intermediate representation

Do not compile directly from DB rows to nftables.

## 3. Define stable IDs for everything

Names are not sufficient.

## 4. Make assignments identity-based, not IP-based

Support MAC, static lease, WG pubkey, manual binding.

## 5. Clarify runtime ownership

Which subsystem owns:

* IP assignment
* DNS names
* DHCP reservations
* NAT
* route installation
* interface lifecycle

## 6. Reduce “plugin” to “integration”

At least initially.

## 7. Add NAT or explicitly remove edge-router claims

Choose one.

## 8. Decide on IPv6 now

Do not defer ambiguously.

## 9. Treat MCP as constrained automation

Not parity admin.

## 10. Publish a support matrix

Kernel, Proxmox versions, container privileges, network topologies.

---

# A much stronger positioning statement

Here is a more defensible version of the pitch:

> Gatekeeper is a Linux-native network policy control plane for small routed and segmented environments. It runs well in Proxmox LXC or on bare-metal Debian, compiles profile- and alias-based policy into nftables, and provides transactional desired-state management with safe apply/rollback. It is designed for external automation from the start, with a stable REST API and constrained MCP tooling, while reusing proven Linux networking components instead of replacing them.

That says almost the same thing, but sounds like it has been reviewed by an engineer rather than a founder.

---

# Bottom line

## The harsh version

As written, this is not yet an architecture. It is a strong product fantasy attached to a partial implementation sketch. The biggest risks are:

* unclear runtime and privilege model
* underdesigned compiler
* fake atomicity assumptions
* missing security model
* overambitious plugin system
* weak identity and data model
* ambiguous NAT/IPv6/routing story

## The constructive version

There is a real opportunity here if the project is narrowed to:

* profile/alias-based network policy
* deterministic nftables compilation
* safe desired-state apply/rollback
* good UX for assignment and explanation
* clean automation surface
* disciplined scope

That would be credible, useful, and meaningfully differentiated.

I can turn this into a red-team design review memo, a rewritten RFC, or a v1/v2 roadmap.

-----
#Rebuttal
-----
I'll conduct a thorough critical analysis of the Gatekeeper design document, identifying technical problems, architectural flaws, and proposing concrete solutions.I've written a comprehensive technical rebuttal to the Gatekeeper design document. Here are the **critical problems** identified:

---

## Major Architectural Flaws

**1. The "Host Kernel Namespace" Fallacy**
- Claiming to run nftables from an unprivileged LXC container is **technically impossible** without dangerous privilege escalation. True container isolation prevents host network namespace access. The design needs a split architecture: privileged host daemon + unprivileged management container.

**2. Performance Claims Are Misleading**
- "< 5% overhead at 10 Gbps" ignores LXC veth/bridge overhead (3-10%), connection tracking CPU costs, and rule recompilation latency. The "line-rate" promise is marketing, not engineering. Realistic target: **15-20% overhead** with proper hardware.

**3. SQLite as Config Store Has Hidden Traps**
- Storing full JSON snapshots of every revision leads to **gigabytes of bloat** over time. Complex firewall rule evaluation requires graph traversal—relational databases are poor at this. Needs differential storage + in-memory graph.

---

## Network Model Problems

**4. Zone/Interface Binding is Too Rigid**
- 1:1 zone:interface mapping breaks real-world scenarios (bonds, multiple VLANs per zone, dynamic interfaces). Needs interface groups and L2 abstraction.

**5. dnsmasq Integration is Underspecified**
- dnsmasq reloads are **not atomic** and drop leases. Dynamic device assignment requires either Lua scripting or moving to ISC Kea for production use.

**6. "Trust Levels" Are Security Theater**
- Undefined semantics create false confidence. Replace with explicit default policies or implement as packet marking.

---

## Security & Operational Gaps

**7. Missing Critical Security Features**
- No mention of: SYN flood protection, connection rate limiting, ARP inspection, DHCP snooping, GeoIP, or certificate management. These aren't "plugins"—they're baseline requirements.

**8. Plugin System is an Attack Surface**
- Loading dynamic libraries into the daemon with full privileges is dangerous. Needs sandboxing (separate processes + seccomp) and capability-based permissions.

**9. "Apply-Confirm" Pattern is Dangerous**
- A timer doesn't help if you're locked out. Needs pre-flight validation and health-check-based reversion, not just a countdown.

**10. HA is Dismissed, Not Designed**
- "Future concern" ignores that stateful failover requires conntrack synchronization—an architectural decision that can't be bolted on later.

---

## API & Protocol Issues

**11. MCP Server is Vendor Lock-in**
- MCP is Anthropic-specific, not a standard. AI agents can use REST. This adds attack surface for marginal benefit.

**12. REST API is Underspecified**
- No pagination, bulk operations, or async job handling. Won't scale to enterprise device counts.

---

## Revised Recommendations

1. **Accept Host Privileges**: Design a minimal `gatekeeper-netd` on the host with `CAP_NET_ADMIN`, containerize the REST API separately.

2. **Incremental Rule Updates**: Never recompile full nftables rulesets. Use sets and incremental `add element` operations.

3. **Drop AI/MCP (v1)**: Focus on solid API and transactional config first. AI integration is a v2 feature.

4. **Use Rust, Not Go**: `google/nftables` is incomplete. `nftables-rs` or shelling out to `nft` is more reliable.

5. **Simplify Defaults**: Ship with 2 zones (wan/lan), not 8. "Secure by default" requires configuration, not magic.

---

The critique document (`/home/user/gatekeeper_critique.md`) contains detailed technical analysis, proposed solutions, and a revised architecture diagram. Would you like me to expand on any specific area—such as the eBPF/XDP integration, the HA architecture design, or the plugin sandboxing approach?
-----
#Rebuttal
-----
### Architectural and Technical Flaws

1. **Reliance on Shelling Out to External Tools (e.g., nft, wg, dnsmasq)**:
   - **Flaw**: The system drivers are described as "thin wrappers that shell out" to tools like nft CLI, wg CLI, vtysh, etc. This introduces potential security risks (e.g., command injection if inputs aren't sanitized perfectly), performance overhead from process spawning, and fragility if the underlying CLIs change formats or behaviors. It also makes testing harder and could lead to inconsistencies across distributions (Debian vs. Alpine).
   - **Fix/Improvement**: Use native Go/Rust libraries for interactions where possible. For example, adopt Google's nftables Go library (as mentioned) for direct netlink communication instead of shelling to `nft`. For WireGuard, use the `wireguard-go` or equivalent bindings. For dnsmasq, generate config files atomically but manage restarts via signals rather than full respawns. This reduces overhead, improves security, and ensures portability. If shelling is unavoidable, wrap it in a sandboxed subprocess with strict input validation.

2. **SQLite as Config Store in a Network-Critical Path**:
   - **Flaw**: While WAL mode provides ACID properties, SQLite isn't optimized for high-concurrency writes in a multi-user/API scenario. In a busy network (e.g., frequent device assignments via API/MCP), contention could cause delays or locks. Revision history storing full snapshots for every commit could bloat the database over time, leading to storage issues on embedded-like LXC setups. No mention of backups or replication for HA.
   - **Fix/Improvement**: Introduce a caching layer (e.g., in-memory Redis or an embedded KV store like BoltDB) for read-heavy operations like rule lookups. For revisions, store diffs incrementally rather than full snapshots to save space—reconstruct full states on demand. Add built-in backup hooks (e.g., periodic exports to S3 via a plugin) and support for read replicas if scaling to multi-node in future. Benchmark under load to ensure <1ms transaction times for commits.

3. **LXC-Specific Assumptions Limiting Portability**:
   - **Flaw**: The design is "LXC-first," assuming unprivileged containers with nesting, Proxmox compatibility, and host kernel nftables access. This ties it too closely to LXC/Proxmox ecosystems, limiting adoption in Docker, Kubernetes, or bare-metal setups. Networking support in LXC can be tricky (e.g., macvlan/veth bridging), and the document notes VyOS's LXC issues but doesn't address potential similar pitfalls here.
   - **Fix/Improvement**: Abstract the container runtime assumptions into a "deployment mode" flag (e.g., `--mode=lxc`, `--mode=bare-metal`, `--mode=docker`). For non-LXC, provide fallback drivers (e.g., user-space nftables emulation or integration with iptables-nft compat layer). Test and document setups for Kubernetes (as a DaemonSet) to broaden appeal. Add auto-detection for network interfaces during boot to handle dynamic environments.

4. **Performance at Scale (e.g., 10 Gbps Claim)**:
   - **Flaw**: Claims near-wire speeds but relies on host kernel nftables, which is fine for small rulesets. However, with alias expansion (potentially thousands of members), rule compilation could generate massive nft rulesets, leading to O(n) lookup times in the kernel. No mention of optimizing for large aliases or handling dynamic updates without full ruleset reloads, which could drop packets during applies.
   - **Fix/Improvement**: Implement incremental rule updates using nftables' atomic replace feature more granularly (e.g., per-table flushes). Use nft sets for aliases to allow dynamic additions without full recompiles. Benchmark with tools like iperf under simulated loads (e.g., 1000+ devices). Add a "fast-path" mode for high-throughput zones that bypasses unnecessary logging/conntrack.

### Security and Policy Flaws

5. **Default Policies and Zones Are Overly Prescriptive**:
   - **Flaw**: Opinionated defaults (e.g., allowing lan -> internet fully, iot -> 80/443 only) assume a home/SMB network topology, which may not fit enterprise or custom setups. "Hostile" zones like "range" with proxy-only egress could leak data if the proxy is misconfigured. No built-in rate limiting or anti-DoS in defaults. Trust levels (e.g., "full" vs. "none") are enums but lack granular controls like time-based policies.
   - **Fix/Improvement**: Make defaults configurable via a setup wizard (CLI/API) during initial boot, with templates for different environments (home, office, datacenter). Add default anti-DoS rules (e.g., SYN flood protection via sysctl tweaks). Extend trust levels to include conditional policies (e.g., "allow during business hours"). Introduce a "policy auditor" tool that scans for common misconfigurations like open WAN ports.

6. **API and MCP Security Exposures**:
   - **Flaw**: API uses simple API keys or HTTP Basic auth, which is weak for external access (no JWT, no OAuth). MCP is native but shares auth with API, potentially exposing sensitive tools (e.g., config_rollback) to AI agents without fine-grained RBAC. No rate limiting on API to prevent abuse. Dry-run mode is good but doesn't simulate side effects like nft applies.
   - **Fix/Improvement**: Implement JWT-based auth with scopes (e.g., read-only for diagnostics, full for assignments). Add RBAC for users/agents (e.g., MCP agents scoped to device_assign only). Enforce rate limiting (e.g., via middleware like Gorilla's handlers in Go). Extend dry-run to include simulated nft output for validation. Require 2FA for web UI logins and audit logs for all mutations.

7. **Plugin System Risks**:
   - **Flaw**: Plugins can register hooks and API routes, but there's no sandboxing mentioned. A malicious or buggy plugin (e.g., suricata) could crash the daemon or escalate privileges via system package installs. Manifest requires "system" packages, which assumes root access and could conflict across plugins.
   - **Fix/Improvement**: Run plugins in isolated processes or Wasm modules for safety. Validate manifests with strict schemas and require code signing for community plugins. Deprecate "system" package installs in manifests—handle them via a pre-install hook with user confirmation. Add a plugin marketplace with versioning and dependency resolution to avoid fractures.

### Usability and Operational Flaws

8. **Web UI and CLI Ergonomics**:
   - **Flaw**: Web UI is server-rendered with htmx, which is lightweight but may lack smoothness for interactive elements (e.g., real-time diagnostics). CLI is thin but assumes API availability—if the daemon crashes, CLI becomes useless. No mention of offline modes or recovery tools. "Every page has CLI equivalent in footer" is nice but could clutter the UI.
   - **Fix/Improvement**: Enhance htmx with WebSockets for real-time updates (e.g., connection tables). Make CLI fallback to direct SQLite reads if API is down, with a "recovery mode." Consolidate CLI equivalents into a help modal rather than footers. Add accessibility features (e.g., ARIA labels) and internationalization for broader adoption.

9. **Data Model Inconsistencies**:
   - **Flaw**: Aliases support nested types but no cycle detection (e.g., alias A includes B, B includes A). Profiles reference policies, but policies are rule-based—changing a policy could unexpectedly affect multiple profiles without warnings. DeviceAssignment lacks expiration or auto-unassign for stale devices.
   - **Fix/Improvement**: Add validation for alias cycles during commits. Introduce policy inheritance or versioning to prevent cascading changes. Add TTLs to assignments and a garbage collector for inactive devices (e.g., based on DHCP lease expiry). Use GraphQL for API queries to allow flexible fetching of related objects (e.g., device + profile + aliases in one call).

10. **MCP Integration for AI Agents**:
    - **Flaw**: MCP tools are comprehensive but assume AI agents can handle complex decision hints without guidance. "device_suggest" uses a decision tree, but no details on how it's built or updated—could become outdated. SSE for streaming is good, but no error handling for long-running operations.
    - **Fix/Improvement**: Make the decision tree configurable (e.g., via a plugin) and trainable from assignment history. Add MCP tools for "explain_suggestion" to provide reasoning. Implement retries and timeouts in SSE, with fallback to polling. Document MCP schemas in a public repo for easier agent integration.

### Scalability and Maintenance Flaws

11. **Lack of Monitoring and Logging Integration**:
    - **Flaw**: Diagnostics endpoints are present, but no built-in logging to external systems (e.g., syslog, ELK). No metrics export for Prometheus. In a production setup, troubleshooting failures (e.g., failed commits) would require manual API calls.
    - **Fix/Improvement**: Add a core logging driver with configurable outputs (file, syslog, JSON). Expose metrics via /metrics endpoint for Prometheus scraping (e.g., commit counts, rule apply times). Integrate with plugins like ntopng for deeper insights.

12. **Build and Distribution Limitations**:
    - **Flaw**: Targets <100MB image but includes optional components like FRR, which could bloat it. One-liner install is convenient but insecure (curl | bash). CalVer versioning is fine, but no mention of upgrade paths or schema migrations for SQLite.
    - **Fix/Improvement**: Modularize the image with layers (e.g., core vs. full with plugins) using Docker multi-stage builds, even for LXC tarballs. Replace curl | bash with a signed installer script. Automate migrations with tools like Goose (for Go) and test upgrades in CI. Provide air-gapped install options for secure environments.

13. **Non-Goals Limiting Long-Term Viability**:
    - **Flaw**: Explicitly avoids multi-node/HA, monitoring, and full routing, which might make it a niche tool. As networks grow, users may outgrow it and migrate to fuller solutions like OPNsense.
    - **Fix/Improvement**: While keeping v1 minimal, design hooks for future extensions (e.g., config sync via etcd for HA). Document migration paths to/from competitors. Community-driven plugins could fill gaps, but seed a few official ones (e.g., HA plugin using Keepalived).

### Overall Improvements
- **Testing Strategy**: Add end-to-end tests simulating LXC deploys, API loads, and power-loss scenarios. Use fuzzing for rule compilation to catch edge cases.
- **Community and Adoption**: To avoid the "fractured community" flaw of VyOS, focus on open-source governance with clear contribution guidelines. Release under a permissive license (e.g., Apache 2.0) and provide a public roadmap.
- **Benchmarking Success Criteria**: The listed criteria are good, but add quantitative metrics like MTTR for config corruption (target: 0) and API latency (<50ms for assignments).

This design is innovative for filling the LXC firewall gap, but addressing these flaws would make it more robust, secure, and widely adoptable.
