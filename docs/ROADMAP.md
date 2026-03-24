# Kepha Roadmap & Competitive Feature Analysis

**Date:** 2026-03-24
**Current state:** 256 commits, 16/16 test packages pass, 168 open punchlist items

---

## Where We Are

### What Works (Live-Tested on 3-Container Topology)

| Category | Feature | Status |
|----------|---------|--------|
| **Firewall** | Zone/alias/policy/profile model | Working |
| | nftables via netlink (no shell-out) | Working |
| | Bogon filtering on WAN | Working |
| | NAT masquerade | Working |
| | ICMP type restriction (0,3,8,11) | Working |
| | Safe-apply with 60s auto-rollback | Working |
| | Dry-run / ruleset preview | Working |
| **DNS/DHCP** | dnsmasq config generation | Working |
| | Per-zone DHCP ranges | Working |
| | Static leases | Working |
| | Upstream DNS forwarding | Working |
| **VPN** | WireGuard server + peer management | Working |
| | QR code client config | Working |
| | VPN provider integration (30+ providers) | Code exists |
| | VPN policy routing (per-device/domain) | Code exists |
| | Site-to-site VPN legs | Code exists |
| **API** | 103 REST endpoints + OpenAPI spec | Working |
| | Auth (API key + RBAC) | Working |
| | Rate limiting | Working |
| | Audit logging | Working |
| **CLI** | 25+ commands, direct + API mode | Working |
| **Web UI** | 12-page dashboard | Working (with issues) |
| **Services** | 25 registered plugins | Code exists |
| **MCP** | 30+ AI tools | Code exists |

### What's Broken or Missing (Critical Items)

| ID | Issue | Impact |
|----|-------|--------|
| NET-C1 | Forward chain forced WAN oifname | **FIXED** — inter-zone forwarding now works |
| NET-C2 | Port forwarding DNAT missing from netlink | Port forwards silently fail |
| ARCH-C1 | Device-profile rules not enforced | Per-device policies are cosmetic |
| ARCH-C2 | Text compiler vs netlink can diverge | DryRun may not match Apply |
| FE-C4 | No commit/rollback UI | Core workflow requires CLI |
| IPv6 | Compiler doesn't emit IPv6 rules | IPv6 traffic silently dropped |

---

## Competitive Feature Parity

### vs pfSense (~246 features)

| Category | pfSense | Kepha | Gap |
|----------|---------|-------|-----|
| **Firewall/NAT** | 27 features | ~18 | Missing: 1:1 NAT, NAT reflection, floating rules, state limiting, syn proxy, limiters, GeoIP |
| **VPN** | 19 features | ~8 | Missing: IPsec, OpenVPN, L2TP, multi-instance, RADIUS auth for VPN |
| **Routing** | 19 features | ~8 | Missing: VLAN GUI, LAGG, GRE/GIF tunnels, QinQ, PPPoE, interface groups |
| **DNS/DHCP** | 18 features | ~10 | Missing: DHCPv6, DHCP relay, DNS host overrides GUI, DNSSEC validation, split DNS |
| **QoS** | 12 features | ~3 | Missing: ALTQ schedulers, per-IP fairness, DSCP marking, limiter wizard, CoDel/FQ-CoDel |
| **HA** | 7 features | ~1 (stub) | Missing: CARP, pfsync, config sync, state replication |
| **Monitoring** | 24 features | ~6 | Missing: RRD graphs, NetFlow, real-time graphs, SNMP, packet capture GUI |
| **Auth** | 11 features | ~3 | Missing: LDAP, RADIUS, TOTP 2FA, group permissions, per-user VPN |
| **Captive Portal** | 9 features | ~1 | Missing: vouchers, RADIUS portal, multi-zone portals, per-user bandwidth |
| **IDS/IPS** | 14 features | ~3 | Missing: inline IPS mode, multiple rule sources, per-interface IDS, SID management |
| **Content Filter** | 10 features | ~2 | Missing: HTTP proxy, SSL inspection, URL category filtering |
| **Network Services** | 22 features | ~8 | Missing: IGMP proxy, PPPoE server, FTP proxy, load balancer, Wake-on-LAN GUI |
| **Platform** | 14 features | ~3 | Missing: bare metal installer, cloud images, WiFi AP, ZFS |
| **Management** | 18 features | ~10 | Missing: setup wizard, package manager, multi-language, config history GUI |
| **API** | 10 features | ~6 | Missing: XMLRPC sync, Ansible support, SNMP export |
| **PKI** | 12 features | ~3 | Missing: CRL, intermediate CA, CSR GUI, OCSP, cert-based user mapping |

**Kepha's total: ~93 features implemented out of pfSense's ~246 (~38%)**

### vs GL.iNet (from existing docs/glinet-punch-list.md)

| Category | GL.iNet | Kepha | Status |
|----------|---------|-------|--------|
| VPN (WireGuard + policy) | Yes | **Yes** | Parity |
| VPN (OpenVPN) | Yes | No | Gap |
| DNS filtering | Yes (AdGuard) | **Yes** | Parity |
| Encrypted DNS | Yes | **Yes** | Parity |
| Drop-in gateway | Yes | **Yes** | Parity |
| Parental controls | Basic | **Yes** | Ahead |
| Firmware A/B | No | **Yes** | Ahead |
| TLS fingerprinting | No | **Yes** | Ahead |
| IDS/IPS (Suricata) | No | **Yes** | Ahead |
| Active countermeasures | No | **Yes** | Ahead |
| MCP (AI management) | No | **Yes** | Ahead |
| RBAC | No | **Yes** | Ahead |
| Travel router / WiFi | Yes | No | Gap (by design) |
| Mobile app | Yes (GoodCloud) | No | Gap |
| IPv6 + VPN leak prevention | Broken | **Yes** | Ahead |
| Security posture | CVEs | **Clean** | Ahead |

### Where Kepha Wins (vs Both)

1. **No shell-outs** — command injection impossible by architecture
2. **MCP server** — AI-driven management (unique in the space)
3. **TLS fingerprinting** — JA4+ anomaly detection (unique for a router)
4. **Active countermeasures** — tarpit, RST chaos, TTL randomization
5. **Single binary** — no package manager, no dependency hell
6. **Safe-apply with auto-rollback** — pfSense has config rollback but not firewall rule rollback with timer
7. **Audit trail** — every mutation logged with actor, timestamp, resource

---

## Roadmap

### Phase 1 — Fix Critical Bugs (NOW)

Remaining from 17-agent audit. Must complete before any feature work.

| Item | Priority | Effort |
|------|----------|--------|
| NET-C2: DNAT in netlink backend | Critical | Medium |
| ARCH-C1: Per-device rules in compiler | Critical | Large |
| ARCH-C2: Reconcile text/netlink compilers | Critical | Large |
| FE-C4: Commit/rollback UI | Critical | Medium |
| NET-C3: Verify dnsmasq binds to LAN | Critical | Small (verify only) |
| 55 High items from punchlist | High | Medium |

### Phase 2 — Core Feature Gaps (Q2 2026)

Features needed for basic competitive parity with pfSense/GL.iNet.

| Feature | Why | Effort |
|---------|-----|--------|
| **IPv6 firewall rules** | Wire existing ipv6/ package into compiler + netlink backend | Medium |
| **Port forwarding CRUD** | Schema + store + ops + API + UI for DNAT rules | Medium |
| **DHCPv6 server** | Required for IPv6 networks | Medium |
| **VLAN management GUI** | pfSense core feature, needed for multi-network setups | Medium |
| **OpenVPN client** | Many VPN providers still require it | Medium |
| **NAT reflection (hairpin)** | Needed for accessing port-forwards from inside | Small |
| **1:1 NAT** | Required for server hosting scenarios | Small |
| **Config history GUI** | Commit/rollback + diff viewer in web UI | Medium |

### Phase 3 — Monitoring & Observability (Q3 2026)

The biggest gap vs pfSense. Operators need visibility.

| Feature | Why | Effort |
|---------|-----|--------|
| **Real-time traffic graphs** | Per-interface bandwidth (like pfSense RRD) | Medium |
| **Per-device bandwidth history** | "Who's using all the bandwidth?" | Medium |
| **Packet capture GUI** | tcpdump from the web UI | Small |
| **Firewall log viewer** | Searchable, filterable rule hit log | Medium |
| **Gateway quality monitoring** | Latency/loss graphs per WAN | Small |
| **SNMP agent** | Integration with existing monitoring (Zabbix, PRTG) | Medium |
| **Syslog forwarding** | Forward to external SIEM | Small |
| **NetFlow/IPFIX export** | Traffic analysis in external tools | Medium |

### Phase 4 — Authentication & Access Control (Q3 2026)

| Feature | Why | Effort |
|---------|-----|--------|
| **LDAP/AD integration** | Enterprise auth backend | Medium |
| **TOTP 2FA** | Security best practice | Small |
| **RADIUS client** | External auth for VPN and portal | Medium |
| **Per-user VPN access** | Individual VPN configs with RADIUS | Medium |
| **Captive portal vouchers** | Guest access without accounts | Small |

### Phase 5 — Advanced Networking (Q4 2026)

| Feature | Why | Effort |
|---------|-----|--------|
| **HA (VRRP + state sync)** | Production deployments need failover | Large |
| **LAGG / link aggregation** | Bonded interfaces for throughput | Medium |
| **GRE/GIF tunnels** | Site-to-site without VPN overhead | Small |
| **PPPoE client** | Required for many ISPs | Small |
| **IGMP proxy** | IPTV support | Small |
| **QoS wizard** | Auto-configure common shaping scenarios | Medium |
| **FQ-CoDel AQM** | Modern bufferbloat mitigation | Medium |

### Phase 6 — Content Filtering & Proxy (Q1 2027)

| Feature | Why | Effort |
|---------|-----|--------|
| **HTTP proxy (squid)** | Caching + inspection | Large |
| **SSL inspection** | HTTPS content filtering (with CA cert) | Large |
| **URL category filtering** | Block by category (adult, gambling, etc.) | Medium |
| **pfBlockerNG equivalent** | IP + DNS blocklists from published feeds | Medium |

### Phase 7 — Platform & Packaging (Ongoing)

| Feature | Why | Effort |
|---------|-----|--------|
| **Bare metal installer** | Run without Proxmox/LXC | Large |
| **ARM64 support** | GL.iNet hardware, Raspberry Pi | Medium |
| **Cloud images (AWS/Azure)** | Cloud-native firewall | Medium |
| **Setup wizard** | First-time configuration walkthrough | Small |
| **Package manager** | Install optional features on demand | Large |

---

## Feature Count Projection

| Milestone | Kepha Features | pfSense Parity |
|-----------|---------------|----------------|
| **Now** | ~93 | 38% |
| **After Phase 1** (bug fixes) | ~93 | 38% |
| **After Phase 2** (core gaps) | ~110 | 45% |
| **After Phase 3** (monitoring) | ~125 | 51% |
| **After Phase 4** (auth) | ~135 | 55% |
| **After Phase 5** (networking) | ~150 | 61% |
| **After Phase 6** (filtering) | ~160 | 65% |
| **After Phase 7** (platform) | ~175 | 71% |

Note: 100% parity with pfSense is not the goal. Kepha wins on architecture (single binary, no shell-outs, MCP, TLS fingerprinting, active countermeasures) where pfSense wins on breadth (25 years of accumulated features). The target is ~70% feature parity with architectural superiority.

---

## Key Architectural Decisions

| Decision | Kepha | pfSense | GL.iNet | Rationale |
|----------|-------|---------|---------|-----------|
| Firewall engine | nftables (netlink) | pf (FreeBSD) | nftables (shell) | Modern, Linux-native, no shell-outs |
| Language | Go | PHP + C | C + Lua | Single binary, memory-safe, good concurrency |
| Database | SQLite | XML files | UCI | ACID transactions, revision snapshots |
| Platform | Linux LXC | FreeBSD | OpenWrt/Linux | Container-native, Proxmox integration |
| Config model | Zone/alias/policy/profile | Interface/rule | Zone/policy | Richer abstraction, per-device policies |
| VPN | WireGuard-first | IPsec-first | WireGuard + OpenVPN | Modern, high performance |
| AI integration | MCP server (30+ tools) | None | None | Unique differentiator |
