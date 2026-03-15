# GL.iNet Feature Punch List for Gatekeeper

> Cross-referenced against the Gatekeeper codebase as of 2026-03-15.
> Items marked ~~strikethrough~~ are already implemented. Remaining items are the build backlog.

---

## PUNCH LIST

### VPN

- [x] ~~WireGuard server (key gen, peer mgmt, config generation)~~
- [x] ~~WireGuard client / site-to-site tunnels (VPNLegs service)~~
- [x] ~~VPN provider management (Mullvad, ProtonVPN, etc. — VPNProvider service)~~
- [x] ~~VPN kill switch (nftables-based, drop non-tunnel traffic)~~
- [ ] VPN policy routing — per-device or per-domain VPN selection (route some devices through VPN, others direct)
- [ ] VPN cascading — server-connected clients forwarded through client tunnel
- [ ] OpenVPN client & server (GL.iNet ships both; Gatekeeper is WireGuard-only today)
- [ ] Tor integration — route traffic through Tor network
- [ ] Multi-VPN simultaneous — connect to multiple VPN servers at once with policy-based routing

### DNS

- [x] ~~DNS server (dnsmasq integration, per-zone config)~~
- [x] ~~DNS filtering / ad blocking (DNSFilter service)~~
- [x] ~~Encrypted DNS — DNS-over-HTTPS / DNS-over-TLS (EncryptedDNS service via Unbound)~~
- [x] ~~Custom upstream DNS configuration~~
- [ ] DNS-based parental controls — per-device content filtering with schedule
- [ ] DNS allowlist/blocklist GUI management (AdGuard Home-style filter list editor)

### DHCP

- [x] ~~DHCP server with per-zone ranges~~
- [x] ~~Static lease / address reservation~~
- [x] ~~Lease viewer (CLI + API + Web UI)~~
- [ ] Bulk static lease import (CSV/JSON)

### Firewall

- [x] ~~Zone-based firewall (nftables via netlink — no shell-outs)~~
- [x] ~~Policy compiler (zones, aliases, profiles, rules)~~
- [x] ~~Port forwarding (via nftables rules)~~
- [x] ~~DMZ support (via nftables forwarding rules)~~
- [x] ~~MAC address filtering (alias type: mac)~~
- [x] ~~Dynamic alias updates without full recompile~~
- [x] ~~Dry-run / preview compiled ruleset~~
- [x] ~~Auto-rollback timer for risky applies~~
- [ ] MAC allowlist vs blocklist toggle mode (GL.iNet has a simple GUI toggle)
- [ ] Scheduled firewall rules — time-based allow/deny (e.g., kids' internet off at 10pm)

### Wi-Fi

> Gatekeeper is a wired gateway/firewall appliance, not a Wi-Fi router.
> Wi-Fi management is out of scope unless we add hostapd integration.

- [ ] Hostapd integration — manage Wi-Fi radios, SSIDs, WPA3
- [ ] Guest network with AP isolation
- [ ] Band steering (DAWN or equivalent)
- [ ] Scheduled Wi-Fi (on/off per band on a schedule)
- [ ] Repeater/extender mode
- [ ] DFS channel selection
- [ ] Mesh networking

### Network

- [x] ~~Multi-WAN failover with health checks (MultiWAN service)~~
- [x] ~~Load balancing across WAN interfaces~~
- [x] ~~Bridge interface management (Bridge service)~~
- [x] ~~MTU management with PMTUD and MSS clamping~~
- [x] ~~Network interface management via netlink (no shell-outs)~~
- [x] ~~Link/address/route operations~~
- [x] ~~NIC diagnostics (driver, speed, queues, offloads, IRQ)~~
- [ ] Drop-in gateway mode — transparent insertion between existing router and clients without reconfiguration
- [ ] USB tethering as WAN source (phone-as-modem)
- [ ] Cellular/LTE modem support as WAN
- [ ] Captive portal passthrough — handle upstream captive portals (hotels, airports) with MAC cloning
- [ ] VLAN tagging and trunk port support (GUI-managed)

### Routing

- [x] ~~Dynamic routing via FRRouting (BGP/OSPF)~~
- [x] ~~Static route management~~
- [ ] Policy-based routing GUI (source/dest/protocol → specific WAN or VPN)

### QoS / Traffic

- [x] ~~Bandwidth shaping via netlink tc~~
- [x] ~~Per-device bandwidth monitoring (BandwidthMonitor service)~~
- [x] ~~Performance tuning (flowtables, conntrack, sysctl, IRQ affinity, NIC offloads)~~
- [ ] Application-aware QoS (prioritize by app/protocol category)
- [ ] Bandwidth usage history/graphs (per-device, per-day)

### Security

- [x] ~~IDS/IPS (Suricata integration with ET Open rules)~~
- [x] ~~TLS fingerprinting (JA4+ — JA4, JA4S, JA4T, JA4H)~~
- [x] ~~Device fingerprint identification with confidence scoring~~
- [x] ~~Anomaly detection (fingerprint change tracking)~~
- [x] ~~Threat intelligence / IOC store~~
- [x] ~~XDP/eBPF fast-path blocklist~~
- [x] ~~Active countermeasures (tarpit, latency injection, bandwidth throttle, RST chaos, SYN cookies, TTL randomization — disabled by default)~~
- [x] ~~RBAC with 5 roles and granular permissions~~
- [x] ~~Captive portal / splash page for guest networks~~
- [ ] Parental controls — per-device screen time limits + content categories
- [ ] Scheduled access control — per-device internet access schedules
- [ ] WPA3 management (requires hostapd integration)

### Storage & Sharing

- [x] ~~Samba/SMB file sharing (Samba service)~~
- [ ] WebDAV file sharing
- [ ] DLNA media streaming
- [ ] USB storage hotplug management

### Remote Management

- [x] ~~Web UI dashboard (11 pages, session auth)~~
- [x] ~~REST API (full CRUD, OpenAPI 3.1 spec)~~
- [x] ~~CLI tool (25+ commands, direct + API mode)~~
- [x] ~~MCP server (SSE transport, 30+ tools, audit logging)~~
- [x] ~~DDNS (Dynamic DNS via nsupdate)~~
- [x] ~~Certificate store with Let's Encrypt renewal~~
- [ ] Cloud management platform (like GoodCloud — remote admin, batch firmware, multi-device)
- [ ] Mobile app (iOS/Android)
- [ ] Physical toggle switch integration (GPIO-based feature toggle)
- [ ] Firmware upgrade management (staged rollout, A/B partition, auto-update)

### Overlay Networks

- [ ] Tailscale integration (built-in, exit node support)
- [ ] ZeroTier integration (built-in)
- [ ] SD-WAN (like AstroWarp — site-to-site between Gatekeeper nodes with managed overlay)

### Discovery & Services

- [x] ~~mDNS/Bonjour (Avahi service)~~
- [x] ~~UPnP/IGD (miniupnpd integration)~~
- [x] ~~NTP (chrony integration)~~

### High Availability

- [x] ~~VRRP framework (leader election hooks, virtual IP)~~ *(partial — 30%)*
- [ ] Full HA state replication (etcd consensus)
- [ ] Conntrack sync between nodes
- [ ] Config sync between primary/secondary

### IPv6

- [x] ~~IPv6 dual-stack framework~~ *(partial — 40%)*
- [x] ~~Router Advertisement service (radvd)~~
- [ ] Complete IPv6 firewall rule generation
- [ ] DHCPv6 server
- [ ] NDP proxy
- [ ] IPv6 prefix delegation
- [ ] IPv6 + VPN without data leakage (GL.iNet explicitly warns this leaks)

---

## EDGE CASES WHERE GL.iNET ROUTERS FAIL

These are gaps and failure modes in GL.iNet routers — opportunities for Gatekeeper to be better.

### 1. IPv6 + VPN Data Leakage
GL.iNet's own docs warn: *"If you use functions of both VPN and IPv6 at the same time, it's likely to cause IPv6 data leakage."* Their VPN implementation doesn't properly handle IPv6 traffic, causing it to bypass the tunnel entirely. **Gatekeeper opportunity:** When we complete IPv6 support, ensure VPN kill switch covers both stacks.

### 2. DNS Leaks in Repeater/Hotel Scenarios
When VPN is active but DNS is set to "Automatic" (from upstream), DNS queries leak outside the tunnel. Captive portal "Auto Login Mode" explicitly leaks network activity to the hotspot provider. **Gatekeeper opportunity:** Force DNS through tunnel when VPN is active. Our EncryptedDNS service already has the right architecture for this.

### 3. Security Vulnerability Pattern
GL.iNet has disclosed numerous critical CVEs in 2024-2025:
- Unauthenticated remote code execution via SID bruteforce (Aug 2024)
- Authentication bypass via session ID reuse (Apr 2024)
- Shell command injection (CVE-2024-39227)
- Path traversal in OpenVPN client upload leading to arbitrary file writes (Apr 2024)
- ReDoS exploitable without authentication (Apr 2025)
- Directory traversal and unauthorized admin access (Oct 2024)

**Gatekeeper advantage:** Our "no shell-outs" standard eliminates command injection entirely. RBAC with bcrypt-hashed keys, input validation, and the MCP audit trail are architecturally superior.

### 4. Wi-Fi Reliability (Repeater Mode)
The most common complaint across all GL.iNet forums. Multiple models drop connections every 5-10 hours in repeater mode. The Flint 3 has "unacceptable stability issues" with Network Acceleration. The Beryl 7 continuously reboots in repeater mode. **Not directly applicable** to Gatekeeper (wired appliance), but worth noting if we ever add hostapd.

### 5. Firmware Updates Brick Devices
Multiple models (AR300M, AR750S, AX1800, MT3000) bricked by firmware updates, especially major version jumps (3.x → 4.x). Users lose access post-update with Wi-Fi disappearing. Community advice: *"Avoid brand new and pre-order products — you'll be the beta tester, guaranteed."* **Gatekeeper opportunity:** A/B partition firmware with automatic rollback on health check failure.

### 6. Multi-WAN Failover Broken Edge Cases
- Failover fails when both WAN interfaces share the same gateway IP
- Failover gets "stuck" on the backup interface, refusing to switch back
- No support for multiple repeater networks as failover sources

**Gatekeeper advantage:** Our MultiWAN service uses configurable health checks. We should add test coverage for the same-gateway-IP edge case.

### 7. Overlay Network Mutual Exclusivity
Tailscale, ZeroTier, AstroWarp, WireGuard Client, OpenVPN Client, and GoodCloud Site-to-Site **cannot be used simultaneously**. This is a hard architectural limit. **Gatekeeper opportunity:** Design overlay network support to be composable — multiple tunnels with policy routing, not mutually exclusive.

### 8. Guest Network Isolation Gaps
Guest isolation depends on AP Isolation + "Block WAN Subnets" being independently configured. Misconfiguration exposes the main LAN to guest devices. **Gatekeeper advantage:** Our zone-based model with default-deny inter-zone policy handles this architecturally — guests are in a separate zone with explicit policy.

### 9. Double NAT Complications
GL.iNet behind ISP gateways creates double NAT that breaks inbound VPN connections. Users must put upstream routers in bridge mode or use relay services. **Gatekeeper opportunity:** Drop-in gateway mode that handles this transparently, plus STUN/TURN support for inbound connections through NAT.

### 10. Port Forwarding + DMZ Conflict
On some models, enabling DMZ disables all other port forwarding rules. Port forwarding also fails when VPN IP/Domain policies are enabled. **Gatekeeper advantage:** Our nftables compiler handles these as independent rule chains — no conflicts by design.

### 11. Captive Portal Failures
Some hotel networks block the router entirely regardless of MAC cloning. Enabling encrypted DNS breaks captive portal detection. 24-hour re-authentication can fail catastrophically. **Gatekeeper opportunity:** Smart captive portal detection that temporarily disables encrypted DNS, authenticates, then re-enables.

### 12. Band Steering Missing from GUI
Despite dual-band Wi-Fi, band steering requires manual OpenWrt/LuCI SSH configuration. No GUI support for this common feature.

---

## WHAT PEOPLE LOVE ABOUT GL.iNET

Understanding *why* people choose GL.iNet tells us what to prioritize.

### 1. "VPN Just Works"
The #1 reason people buy GL.iNet. Pre-installed WireGuard and OpenVPN with a simple GUI for importing configs from 30+ providers. *"You set up your VPN on the router and every device gets protected automatically."* The Flint 2's 900 Mbps WireGuard throughput is particularly praised.

**Takeaway for Gatekeeper:** VPN provider import (config files from Mullvad, ProtonVPN, etc.) with one-click activation is table stakes. We have VPNProvider service — make sure the UX is dead simple.

### 2. OpenWrt Foundation
The single most praised aspect. *"The most amazing and opensource routers"* with *"extreme software capabilities."* Full LuCI access, 5,000+ packages, can flash vanilla OpenWrt. Advanced users love the escape hatch.

**Takeaway for Gatekeeper:** Our plugin system and MCP server serve a similar role — extensibility without compromising the core. Lean into this.

### 3. Travel Router — No Competition
GL.iNet owns this niche. Key scenarios:
- **Captive portal handling:** *"Most 'normal' routers cannot use an existing wifi network as their WAN. GL.iNet is really best in class."*
- **Device limit bypass:** Router masquerades as one device, broadcasts a mini-network behind it
- **USB-powered:** Pair with 10,000 mAh battery for 4-6 hours portable networking
- **Form factor:** *"Ridiculously small, making it the perfect choice for limited-luggage travelling"*

**Takeaway for Gatekeeper:** If we target travel/portable use, drop-in gateway mode and captive portal passthrough are critical. Our wired appliance form factor is different, but the security-on-untrusted-networks use case still applies.

### 4. Price-to-Performance
- Beryl AX at ~$75: *"Amazing for the price — 2.5G WAN, WiFi 6"*
- Flint 2 at ~$159: *"One of the best value OpenWrt-capable routers"*
- Opal at ~$30: *"Hard to beat for basic travel use"*

**Takeaway for Gatekeeper:** Running on commodity x86 or ARM hardware (LXC container) gives us potentially better price-to-performance since the user picks their own hardware.

### 5. Drop-in Gateway Mode
Place the router between existing router and devices without changing any network config. Instantly adds AdGuard Home, encrypted DNS, and VPN. *"Adds security to networks that don't natively support them."*

**Takeaway for Gatekeeper:** This is a high-value, low-friction adoption path. Implement transparent bridge mode with selective interception.

### 6. Specific Beloved Use Cases
- **Hotel/cruise/airport security** — VPN on untrusted networks without per-device config
- **Digital nomads** — one router, all devices secured, works globally
- **RV/van life** — tethering + cellular failover
- **Homelab gateway** — drop-in mode adds filtering + VPN to existing network
- **Remote access** — WireGuard server at home, travel router abroad, full tunnel back
- **Bypassing one-device-at-a-time restrictions** — conference/airline/hotel Wi-Fi with device caps

### 7. Flint 2 as Home Router Replacement
Multiple users report replacing mesh systems (Deco M5) because the Flint 2 alone *"covers all the house."* ServeTheHome praised it. The 2x 2.5GbE + quad-core + 1GB RAM makes it legitimate, not just a travel device.

---

## PRIORITY MATRIX

Based on what people love and where GL.iNet fails, here's the suggested implementation priority:

### P0 — Must Have (Core Differentiators)
| Feature | Why |
|---------|-----|
| VPN policy routing (per-device/domain) | #1 loved feature, we have the foundation |
| IPv6 + VPN leak prevention | GL.iNet's biggest security gap |
| Drop-in gateway mode | Lowest-friction adoption path |
| Parental controls / scheduled access | Massive consumer demand |
| Firmware A/B with auto-rollback | GL.iNet's biggest reliability gap |

### P1 — Should Have (Competitive Parity)
| Feature | Why |
|---------|-----|
| OpenVPN client & server | Many VPN providers still require it |
| Tailscale integration | Increasingly expected |
| DNS blocklist GUI management | AdGuard Home is beloved |
| Bandwidth usage history/graphs | Everyone wants visibility |
| Policy-based routing GUI | Power user essential |
| Scheduled firewall rules | Parental controls dependency |
| Bulk static lease import | Quality of life |

### P2 — Nice to Have (Extended Value)
| Feature | Why |
|---------|-----|
| ZeroTier integration | Niche but loyal users |
| Tor integration | Privacy-focused users |
| Cloud management platform | Multi-site deployments |
| Mobile app | Consumer convenience |
| SD-WAN (site-to-site managed overlay) | Enterprise/prosumer |
| WebDAV / DLNA | Storage use cases |
| USB tethering as WAN | Travel/mobile use |

### P3 — Wi-Fi (Only if We Add hostapd)
| Feature | Why |
|---------|-----|
| Hostapd integration | Prerequisite for all Wi-Fi features |
| Guest network with AP isolation | Very common request |
| Band steering | Quality of life |
| Scheduled Wi-Fi | Energy/parental controls |
| Mesh networking | Home coverage |

---

*This document is a living punch list. Strike through items as they are implemented.*
