# Portable Kepha/Gatekeeper Device: Hardware Requirements & Supply Chain Analysis

**Status:** Thought Experiment / Design Study
**Date:** 2026-03-15

---

## 1. What Kepha Actually Demands from Hardware

Before picking parts, we need to understand the load profile. Kepha is not a toy
firewall — it runs nftables via netlink, optional Suricata IDS/IPS, WireGuard
tunnels, dnsmasq, eBPF/XDP fast-path processing, and an SQLite-backed config
store with full audit logging. In a travel router form factor, we're compressing
what normally lives on a Proxmox host into something that fits in a bag.

### Compute Requirements

| Workload | CPU Impact | Notes |
|----------|-----------|-------|
| nftables rule compilation | Burst (on config change) | Single-threaded Go, fast on any modern core |
| WireGuard Curve25519 | Sustained per-tunnel | ~1 Gbps on ARMv8 with crypto extensions |
| Suricata IDS/IPS | Heavy, multi-threaded | Rule matching is CPU-bound; 2+ cores minimum |
| XDP/eBPF packet processing | Kernel fast-path | Needs Linux 5.10+, BTF support, CAP_BPF |
| SQLite WAL writes | Negligible | Pure Go SQLite (modernc.org/sqlite), no CGo |
| dnsmasq DNS/DHCP | Negligible | Lightweight daemon |
| Web UI / REST API | Light | Go HTTP server, template rendering |

**Minimum:** 4x ARMv8.2-A cores @ 1.8 GHz with AES/SHA/PMULL crypto extensions
**Recommended:** 4x Cortex-A76 (or newer) cores @ 2.2+ GHz for comfortable Suricata headroom

### Memory Requirements

| Consumer | Footprint | Notes |
|----------|-----------|-------|
| Kepha daemon (gatekeeperd) | ~30-50 MB | Go binary, alias cache, RBAC key cache |
| Suricata (with ET Open rules) | 500 MB - 1.5 GB | Rule loading is the killer; scales with ruleset size |
| Conntrack table | ~256 entries/MB RAM | Auto-scaled by performance tuner |
| dnsmasq | ~10-20 MB | Per-zone config, lease tables |
| Kernel + eBPF maps | ~100-200 MB | XDP programs, BPF maps, flowtables |
| OS overhead (Alpine) | ~50-80 MB | Minimal userspace |

**Minimum:** 2 GB (no Suricata, basic zones)
**Recommended:** 4 GB (full Suricata with ET Open, 9 zones, XDP maps)
**Ideal:** 8 GB (future headroom, large conntrack tables, DNS filter lists)

### Storage Requirements

| Data | Size | Access Pattern |
|------|------|----------------|
| Kepha binary + Alpine rootfs | ~200 MB | Read-heavy, boot |
| SQLite config DB | ~5-50 MB | Write bursts on config changes |
| Audit log (append-only, SHA-256 chained) | Grows ~1 MB/day under active use | Sequential writes |
| Suricata rules + EVE JSON logs | 200 MB rules + logs grow fast | Write-heavy when IDS enabled |
| WireGuard keys | < 1 MB | Rare writes |

**Minimum:** 8 GB eMMC
**Recommended:** 32 GB eMMC + microSD slot for log offload
**Ideal:** 64 GB eMMC or NVMe M.2 2230

### Network Interface Requirements

This is the critical constraint. A travel router running Kepha needs:

1. **WAN uplink** — connects to hotel/airport/hostile WiFi or Ethernet
2. **LAN downlink** — serves your devices (WiFi AP + wired)
3. **Management** — ideally out-of-band, but can share LAN in portable mode

At minimum, we need:
- **1x Gigabit Ethernet** (WAN, wired uplink when available)
- **1x WiFi radio as STA** (WAN, wireless uplink to hostile networks)
- **1x WiFi radio as AP** (LAN, serving your devices)
- **1x Gigabit Ethernet** (LAN, optional but valuable for wired device)

VLAN trunking on a single Ethernet port is acceptable for the travel use case
but introduces a managed-switch dependency. Two physical Ethernet ports is
strongly preferred.

### Kernel Requirements

- Linux 5.15+ LTS (5.10 absolute minimum for XDP)
- `CONFIG_NF_TABLES=y` (nftables)
- `CONFIG_NETFILTER_XT_*` (conntrack, NAT)
- `CONFIG_BPF=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_XDP_SOCKETS=y`
- `CONFIG_WIREGUARD=y`
- `CONFIG_VLAN_8021Q=y`
- `CONFIG_BRIDGE=y`
- BTF (BPF Type Format) support for CO-RE eBPF programs
- Kernel crypto API with hardware acceleration (`CONFIG_CRYPTO_AES_ARM64_CE`)

---

## 2. Hardware Platform Selection: The Explicit Build

### Primary SoC: Rockchip RK3588S or RK3568B2

**Why Rockchip and not Qualcomm/MediaTek/Broadcom:**

| Factor | Rockchip RK3588S | Qualcomm IPQ8074 | MediaTek MT7986 (Filogic 830) |
|--------|-----------------|-------------------|-------------------------------|
| Core arch | 4x A76 + 4x A55 (big.LITTLE) | 4x A53 | 4x A53 |
| Clock | 2.4 GHz (A76) | 2.0 GHz | 2.0 GHz |
| Crypto extensions | Full ARMv8.2-A CE | Yes | Yes |
| RAM support | LPDDR4x/LPDDR5 up to 32 GB | DDR4 up to 2 GB (typical) | DDR4 up to 2 GB |
| PCIe | PCIe 3.0 x4 | PCIe Gen2 | PCIe Gen3 |
| Mainline Linux | 6.x (upstream, active) | Vendor BSP (OpenWrt) | Vendor BSP (OpenWrt) |
| NPU | 6 TOPS (not needed but free) | None | None |
| TAA compliant | Possible (see §5) | No (designed in San Diego, fabbed TSMC) | No (MediaTek is Taiwanese — TAA-compliant but DFARS is complicated) |
| Documentation | Open TRM, open schematics | NDA-walled | Partially open |

**The RK3588S wins** because:
1. Mainline Linux support means we control the kernel, not a vendor BSP
2. 4x A76 cores give Suricata real headroom
3. Up to 32 GB LPDDR5 means no memory ceiling
4. PCIe 3.0 lanes let us add a dedicated NIC or NVMe
5. Supply chain is tractable (see §5)

**Alternative for cost-constrained builds:** RK3568B2 (4x A55 @ 2.0 GHz, up to 8 GB, PCIe 3.0 x1). This is the "good enough" option — it runs Kepha without Suricata comfortably, and with Suricata on a reduced ruleset.

### WiFi: Qualcomm QCN9074 (WiFi 6E) or MediaTek MT7922 (WiFi 6E)

**Why two radios:**
- Radio 1 (STA mode): connects to upstream hostile WiFi
- Radio 2 (AP mode): serves your devices

| Option | QCN9074 | MT7922 | Intel AX210 |
|--------|---------|--------|-------------|
| Interface | M.2 E-key (PCIe) | M.2 E-key (PCIe) | M.2 E-key (PCIe) |
| Bands | 2.4/5/6 GHz | 2.4/5/6 GHz | 2.4/5/6 GHz |
| Linux driver | ath11k (mainline) | mt76 (mainline) | iwlwifi (mainline) |
| AP mode support | Excellent (hostapd) | Good (hostapd) | Poor (Intel limits AP) |
| STA mode support | Excellent | Excellent | Excellent |
| Country of design | USA (San Diego) | Taiwan (Hsinchu) | USA (Santa Clara) / Israel (Haifa) |

**Recommendation:**
- **AP radio:** QCN9074 — best hostapd support, proven in enterprise APs
- **STA radio:** MT7922 — excellent STA stability, cheaper, mainline mt76 driver

Intel AX210 is a trap for AP mode. iwlwifi's AP implementation is limited and
buggy. Do not use Intel for the AP radio.

### Ethernet: Realtek RTL8125BG (2.5 GbE) or Intel I226-V

| Option | RTL8125BG | Intel I226-V |
|--------|-----------|--------------|
| Speed | 2.5 GbE | 2.5 GbE |
| Interface | PCIe Gen2 x1 | PCIe Gen2 x1 |
| Linux driver | r8169 (mainline) | igc (mainline) |
| TSO/GRO offload | Yes | Yes |
| Cost | ~$2.50 | ~$5.00 |
| Country of origin | Taiwan (Realtek HQ) | USA design, various fab |
| XDP support | Basic | Full (igc driver has native XDP) |

**Recommendation:** Intel I226-V for two ports. The `igc` driver has native XDP
support, which means Kepha's eBPF fast-path runs at full line rate with zero-copy.
RTL8125BG works but XDP falls back to generic mode (slower).

For a travel router, we want **two I226-V** ports: one WAN, one LAN. This can be
achieved via a dual-port PCIe card (like the Intel I226-based mini-PCIe/M.2
modules) or by using the SoC's native GMAC for one port and PCIe for the other.

### RAM: SK Hynix or Samsung LPDDR4x/LPDDR5

- **4 GB LPDDR4x** — minimum viable for travel use with Suricata
- **8 GB LPDDR5** — recommended; future-proof, conntrack headroom
- Soldered (PoP or on-board), not DIMM — this is an embedded device

**Source:** SK Hynix (South Korea) or Samsung (South Korea). Both are TAA-compliant countries of origin.

### Storage: Samsung/Kioxia eMMC 5.1 + microSD

- **32 GB eMMC 5.1** for OS + config + Suricata rules
- **microSD slot** for log rotation and offload
- Optional: **M.2 2230 NVMe** (if PCIe lanes available after WiFi radios)

**Source:** Samsung (South Korea), Kioxia (Japan), or Western Digital (USA). All TAA-compliant.

### Power

- **USB-C PD** input (5V/3A minimum, 9V/3A recommended for peak Suricata load)
- **Total system draw:** 8-15W typical, 20W peak (RK3588S under full load + 2 radios + 2 NICs)
- **Optional:** Internal Li-Po battery (3.7V, 5000-10000 mAh) for graceful shutdown and brief portable operation
- **Battery management IC:** Texas Instruments BQ25895 or similar (USA design)

### Physical Form Factor

- **Target size:** ~130mm x 90mm x 30mm (slightly larger than a GL.iNet Beryl)
- **Weight:** < 350g with battery, < 200g without
- **Ports exposed:**
  - 2x RJ45 (WAN + LAN)
  - 1x USB-C (power)
  - 1x USB-A 3.0 (future: USB Ethernet dongle, cellular modem)
  - 1x microSD slot
  - Reset button (recessed)
  - 3x status LEDs (power, WAN link, activity)
- **Cooling:** Passive heatsink with thermal pad to aluminum enclosure. No fan.
  The A76 cores will thermal-throttle before damage. Suricata workloads may
  require duty-cycling in hot environments (>40°C ambient).

### Reference Board: FriendlyElec NanoPC-T6 or Radxa ROCK 5B

Rather than a full custom PCB for prototyping, start with:

| Board | SoC | RAM | Ethernet | PCIe | Price |
|-------|-----|-----|----------|------|-------|
| NanoPC-T6 | RK3588 | 4/8/16 GB LPDDR4x | 2x 2.5GbE (RTL8125) | M.2 M-key + M.2 E-key | ~$120-180 |
| Radxa ROCK 5B | RK3588 | 4/8/16 GB LPDDR4x | 1x GbE (RTL8211F) | M.2 E-key + M.2 M-key | ~$80-150 |
| FriendlyElec NanoPi R6S | RK3588S | 8 GB | 2x 2.5GbE + 1x GbE | None exposed | ~$80 |

**Best starting point:** NanoPi R6S — it already has the dual 2.5GbE + GbE topology
we need, 8 GB RAM, RK3588S, and a compact form factor. Add a USB WiFi adapter
(MT7921AU for STA) and a USB WiFi adapter (QCN9074-based for AP) or use the single
M.2 slot for one WiFi radio and USB for the other.

**For custom PCB production run:** Derive from the NanoPC-T6 open schematics,
adding dual I226-V Ethernet and dual M.2 E-key slots for WiFi.

---

## 3. Bill of Materials (Prototype)

| Component | Part | Qty | Unit Cost (est.) | Source |
|-----------|------|-----|-------------------|--------|
| SBC | NanoPi R6S (8GB) | 1 | $79 | FriendlyElec (Shenzhen) |
| WiFi AP radio | QCN9074 M.2 module | 1 | $35 | Wallys Communications or Compex |
| WiFi STA radio | MT7921AU USB adapter | 1 | $15 | Various (MediaTek reference) |
| M.2 to USB adapter | For QCN9074 if no M.2 slot | 1 | $8 | Amazon/AliExpress |
| microSD | Samsung EVO Plus 64GB | 1 | $10 | Samsung authorized |
| USB-C PD charger | 30W GaN | 1 | $20 | Anker / CUI Inc |
| Enclosure | CNC aluminum, custom | 1 | $25 | Prototype: PCBWay/JLCPCB |
| Thermal pad | Fujipoly 11 W/mK | 1 | $5 | Digi-Key |
| Antennas | 2x dual-band PCB antenna | 2 | $3 ea | Taoglas (Ireland) or Molex |
| **Total** | | | **~$203** | |

For a custom PCB production run (MOQ 100+), component cost drops to ~$90-120/unit,
enclosure tooling amortizes to ~$5/unit, and final COGS is around $130-150.

---

## 4. Software Stack for Portable Mode

Kepha currently assumes an LXC privileged container on Proxmox. For a portable
device, we run bare-metal (or in a lightweight systemd-nspawn container):

```
┌─────────────────────────────────────────┐
│           Kepha (gatekeeperd)            │
│  nftables │ WireGuard │ XDP │ REST API  │
├─────────────────────────────────────────┤
│         Alpine Linux (musl libc)        │
│   dnsmasq │ hostapd │ suricata │ wpa_s  │
├─────────────────────────────────────────┤
│        Linux 6.x (mainline kernel)      │
│  nf_tables │ wireguard │ bpf │ vlan     │
├─────────────────────────────────────────┤
│      RK3588S + I226-V + QCN9074/MT7921  │
└─────────────────────────────────────────┘
```

### Portable-Specific Additions

1. **hostapd** — manages the AP radio (replaces Proxmox bridge networking)
2. **wpa_supplicant** — manages the STA radio (upstream WiFi connection)
3. **Captive portal detection** — Kepha already has a captive portal service;
   extend it to detect *upstream* captive portals and proxy authentication
4. **Reduced zone profile** — travel mode with 3 zones instead of 9:
   - `wan` — hostile upstream (hotel/airport WiFi or wired)
   - `lan` — your devices (WiFi AP + wired LAN port)
   - `vpn` — WireGuard tunnel back to home Kepha instance
5. **Cellular failover** — USB cellular modem (Sierra Wireless EM9191 or Quectel
   RM520N) as backup WAN, managed via ModemManager + NetworkManager

---

## 5. TAA Compliance & DFARS/FIPS Considerations

### Trade Agreements Act (TAA) — 19 U.S.C. § 2512

TAA compliance means the product must be manufactured or "substantially
transformed" in a TAA-designated country. The key designated countries:

- **USA, Canada, Mexico** (USMCA)
- **EU member states, UK, Norway, Switzerland**
- **Japan, South Korea, Australia, New Zealand**
- **Taiwan** (designated country)
- **Israel**
- **Singapore, Hong Kong**

**NOT designated:** China, Vietnam, Thailand, India, Malaysia (for most purposes)

### The China Problem

Here's the uncomfortable truth: almost every SoC vendor fabs in TSMC (Taiwan)
but designs in various countries, and almost every board-level assembly happens in
Shenzhen. TAA cares about "substantial transformation," not component origin.

**Strategy for TAA compliance:**

| Layer | Component | Origin | TAA Status | Mitigation |
|-------|-----------|--------|-----------|------------|
| SoC | RK3588S | Designed: China (Fuzhou) | **Non-compliant** | See below |
| SoC alt | NXP i.MX 8M Plus | Designed: Netherlands/USA | **Compliant** | Lower perf, but TAA-clean |
| SoC alt | TI AM6254 | Designed: USA (Dallas) | **Compliant** | 4x A53 @ 1.4 GHz, limited |
| WiFi | QCN9074 | Designed: USA (San Diego) | **Compliant** | Qualcomm is US-headquartered |
| WiFi | MT7922 | Designed: Taiwan (Hsinchu) | **Compliant** | Taiwan is TAA-designated |
| Ethernet | Intel I226-V | Designed: USA/Israel | **Compliant** | Intel fabs: USA, Ireland, Israel |
| RAM | SK Hynix LPDDR5 | South Korea | **Compliant** | |
| Storage | Samsung eMMC | South Korea | **Compliant** | |
| PMIC | TI TPS65219 | Designed: USA | **Compliant** | |
| PCB fab | JLCPCB/PCBWay | China | **Non-compliant** | Use US/EU PCB fab |
| PCB fab alt | TTM Technologies | USA (Santa Ana, CA) | **Compliant** | 3-5x cost increase |
| PCB fab alt | Schweizer Electronic | Germany | **Compliant** | |
| Assembly | FriendlyElec | China (Shenzhen) | **Non-compliant** | |
| Assembly alt | Jabil | USA (various) | **Compliant** | MOQ 1000+, expensive |
| Assembly alt | Benchmark Electronics | USA (Angleton, TX) | **Compliant** | |
| Enclosure | CNC aluminum | China (typical) | **Non-compliant** | US machine shop |
| Enclosure alt | Protocase | Canada (Nova Scotia) | **Compliant** | |

### The TAA-Compliant Build (Realistic)

If you must be TAA-compliant for government procurement (GSA Schedule, DoD, etc.):

**Option A: Substantial Transformation in USA**
- Import components (SoC, WiFi, NIC chips are all <$10 each, under de minimis)
- PCB fabrication: TTM Technologies (USA) or Advanced Circuits (USA)
- Board assembly (SMT): Jabil (USA), Benchmark Electronics (USA), or IEC Electronics (Newark, NY)
- Enclosure: Protocase (Canada) or local CNC shop
- Final assembly + firmware flash + QA: USA facility
- **Result:** Substantially transformed in USA. TAA-compliant.
- **Cost impact:** 3-5x BOM for assembly. Unit cost ~$400-600 at MOQ 500.

**Option B: Use a TAA-Compliant SoC**
- Switch from RK3588S to **NXP i.MX 8M Plus** (designed in Netherlands/USA, fabbed TSMC)
- NXP has a clean TAA story — headquartered in Eindhoven, Netherlands
- 4x Cortex-A53 @ 1.8 GHz, 6 GB LPDDR4 max
- **Trade-off:** Significantly less CPU. Suricata will struggle. WireGuard ~500 Mbps max.
- Pair with reduced Suricata ruleset or disable IDS in portable mode.
- **Reference hardware:** Variscite VAR-SOM-MX8M-PLUS (SoM), Toradex Verdin iMX8MP

**Option C: Hybrid — COTS + Software**
- Buy a TAA-compliant mini PC (e.g., Protectli Vault FW4C — Intel, assembled in USA)
- Install Alpine Linux + Kepha
- **Trade-off:** Not a travel router form factor. Larger, heavier, higher power.
- But immediately TAA-compliant and available today.
- Protectli is a known vendor on GSA Advantage.

### FIPS 140-3 Considerations

If operating in a FIPS-required environment (FedRAMP, DoD IL4+):

- **WireGuard is NOT FIPS-validated.** ChaCha20-Poly1305 is not in the FIPS approved
  algorithm list. You'd need to replace WireGuard with IPsec (AES-GCM) using a
  FIPS-validated module (e.g., Linux kernel FIPS module, or strongSwan with
  OpenSSL FIPS provider).
- **Go's crypto/tls:** Not FIPS-validated by default. Use `GOEXPERIMENT=boringcrypto`
  to link against BoringSSL's FIPS-validated module for the REST API TLS.
- **SQLite encryption:** If config-at-rest encryption is required, use SQLCipher
  with a FIPS-validated AES implementation. Current pure-Go SQLite has no encryption.

---

## 6. Third-Party Risk Management

### Hardware Supply Chain Risks

#### Tier 1: Silicon (SoC, NIC, WiFi, PMIC)

| Risk | Impact | Mitigation |
|------|--------|------------|
| Backdoor in SoC firmware | Total compromise | Use SoCs with open-source boot firmware (RK3588 has open ATF + U-Boot). Avoid SoCs requiring binary blobs for boot. |
| Single-source dependency | Supply disruption | Qualify two SoC platforms (RK3588S primary, NXP i.MX8MP secondary). Different architectures, same Kepha binary (Go cross-compiles trivially). |
| Counterfeit components | Unpredictable failure, potential implant | Buy from authorized distributors only (Digi-Key, Mouser, Arrow). Never broker market for security-critical components. |
| End-of-life / allocation | Can't build more units | Choose SoCs with 10+ year longevity programs. RK3588 is rated for industrial (10yr). NXP i.MX8MP has 15yr longevity commitment. |
| Export controls (EAR) | Can't ship to certain customers | Kepha uses standard crypto (AES, Curve25519). Likely ECCN 5A992.c (mass market) or 5D992.c (software). File a commodity classification request with BIS. |

#### Tier 2: Board-Level Assembly

| Risk | Impact | Mitigation |
|------|--------|------------|
| Implant during assembly | Hardware backdoor | Use trusted assembly partners. For high-assurance: X-ray inspection of assembled boards (Nordson DAGE or similar). Require assembly partner to be ITAR-registered or IPC-1791 (Trusted Electronics Manufacturer) certified. |
| Process variation / yield | Cost overruns, delays | Get DFM review from assembler before committing design. Use standard 0402/0603 passives, QFN/BGA packages with proven reflow profiles. |
| Firmware supply chain | Malicious bootloader | Build all firmware from source. U-Boot, ARM Trusted Firmware (ATF), and Linux kernel compiled in CI with reproducible builds. Sign firmware images with Ed25519 keys held in hardware (YubiKey/Nitrokey). |

#### Tier 3: Software Dependencies

| Dependency | Risk | Mitigation |
|------------|------|------------|
| Go standard library | Upstream compromise | Pin Go version in CI. Verify Go release signatures. Consider using `govulncheck` in CI pipeline. |
| `google/nftables` | Abandoned / backdoored | Fork and vendor. It's 5k lines. We can maintain it. |
| `vishvananda/netlink` | Same | Fork and vendor. ~15k lines but well-understood. |
| `modernc.org/sqlite` | Same | Pure Go, large but auditable. Pin version, verify checksums. |
| Suricata | Binary dependency, complex C codebase | Use Alpine's packaged version. Verify package signatures. Suricata is OISF-maintained with known governance. |
| dnsmasq | Same | Simon Kelley is sole maintainer (bus factor: 1). Consider long-term migration to CoreDNS + Kea DHCP (both have organizational backing). |
| Linux kernel | Enormous attack surface | Use LTS kernels only (6.6 LTS, 6.12 LTS). Apply CIP (Civil Infrastructure Platform) patches if available for chosen SoC. Enable lockdown mode (`lockdown=integrity`). |

#### Tier 4: Firmware & Boot Chain

```
┌──────────────────────────────────────────────┐
│  Threat: Evil Maid / Supply Chain Implant     │
│                                               │
│  Boot Chain (must be verified end-to-end):    │
│                                               │
│  1. BootROM (mask ROM in SoC) ──── immutable  │
│  2. TPL/SPL (U-Boot SPL) ──────── signed      │
│  3. ATF (ARM Trusted Firmware) ─── signed      │
│  4. U-Boot proper ─────────────── signed      │
│  5. Linux kernel + initramfs ──── signed      │
│  6. Root filesystem (Alpine) ──── dm-verity   │
│  7. Kepha binary ─────────────── signed       │
│  8. Config (SQLite) ──────────── encrypted    │
│                                               │
│  RK3588 supports: Secure Boot via eFuse OTP   │
│  NXP i.MX8MP: HABv4 (High Assurance Boot)    │
└──────────────────────────────────────────────┘
```

**Secure boot is non-negotiable for a travel security device.** If someone can
reflash your firmware at a border crossing, your firewall is their firewall.

### Operational Third-Party Risks

| Risk | Scenario | Mitigation |
|------|----------|------------|
| Hostile WiFi upstream | Hotel/airport does MITM | WireGuard tunnel to trusted Kepha instance at home. All traffic exits via tunnel. DNS over tunnel (not local resolver). |
| Captive portal credential theft | Portal clones login page | Isolate captive portal interaction to STA interface. Never expose LAN credentials. Kepha's captive portal service should detect and warn. |
| USB attack (charging port) | Malicious USB device at hotel | Disable USB data lines on charging port (power-only). Use USB-C PD with no data negotiation. Or: hardware USB data blocker. |
| Firmware update MITM | Attacker serves malicious OTA | All OTA updates must be signed. Ed25519 signature verification before applying. Pin update server TLS certificate. |
| Physical theft / seizure | Device confiscated at border | Full disk encryption (LUKS2 with hardware-backed key or passphrase). Config DB encryption. Kepha should support "duress mode" — alternate passphrase that boots a clean/decoy config. |
| Rubber-hose cryptanalysis | Compelled to unlock | Duress mode (above). Or: remote wipe capability via WireGuard dead-man switch. If device doesn't phone home within X hours, home Kepha instance revokes all VPN keys. |

---

## 7. Supplier Strategy & Logistics

### Authorized Distributors (Components)

| Distributor | HQ | Strengths | TAA |
|-------------|------|-----------|-----|
| **Digi-Key** | Thief River Falls, MN, USA | Massive catalog, fast shipping, no MOQ | Yes |
| **Mouser** | Mansfield, TX, USA | Same tier as Digi-Key, owned by Berkshire | Yes |
| **Arrow Electronics** | Centennial, CO, USA | Better for volume, engineering support | Yes |
| **Avnet** | Phoenix, AZ, USA | Strong in embedded SoMs | Yes |
| **Rutronik** | Ispringen, Germany | European distribution, strong NXP/Infineon | Yes |

**Rule:** Never buy security-critical components from unauthorized channels
(AliExpress, eBay, Alibaba, broker markets). The counterfeit risk is not
theoretical — it's routine.

### SoM (System-on-Module) vs Custom PCB

For volumes under 1000 units, a **SoM + carrier board** approach is superior:

- **SoM:** Buy from Variscite, Toradex, or FriendlyElec. They handle the
  high-density BGA routing, DDR4/5 signal integrity, and power sequencing.
- **Carrier board:** Custom PCB with connectors (RJ45, USB-C, M.2, antenna).
  Simple 4-layer board, any competent PCB house can do it.
- **Benefit:** SoM vendor handles silicon errata, thermal validation, and BSP.
  You focus on Kepha software.

| SoM Vendor | SoM | SoC | TAA Origin | Price |
|------------|-----|-----|-----------|-------|
| FriendlyElec | CM3588 | RK3588 | China (Shenzhen) | ~$80 |
| Radxa | CM5 | RK3588S | China (Shenzhen) | ~$70 |
| Toradex | Verdin iMX8MP | NXP i.MX8MP | Switzerland/India assembly | ~$130 |
| Variscite | VAR-SOM-MX8M-PLUS | NXP i.MX8MP | Israel | ~$100 |

**For TAA:** Variscite (Israel) or Toradex (Switzerland) SoMs are substantially
transformed in TAA-designated countries. FriendlyElec/Radxa are not.

### Lead Times & Contingency (as of 2026)

| Component | Typical Lead Time | Risk Level | Contingency |
|-----------|-------------------|------------|-------------|
| RK3588S SoC | 12-16 weeks | Medium | Pre-buy buffer stock. Qualify NXP alt. |
| QCN9074 WiFi | 8-12 weeks | Low-Medium | MT7915 as fallback (WiFi 6, not 6E) |
| Intel I226-V | 4-8 weeks | Low | RTL8125BG as fallback |
| LPDDR5 | 8-12 weeks | Low | LPDDR4x as fallback |
| eMMC 32GB | 4-8 weeks | Low | Multiple qualified sources |
| PCB fab (USA) | 3-5 weeks | Low | TTM, Advanced Circuits, Sunstone |
| SMT assembly (USA) | 4-8 weeks | Medium | Jabil, Benchmark, IEC Electronics |
| CNC enclosure (USA/Canada) | 2-4 weeks | Low | Protocase, local machine shops |

### Dual-Source Strategy

Every critical component should have a qualified alternate:

| Primary | Alternate | Qualification Effort |
|---------|-----------|---------------------|
| RK3588S | NXP i.MX 8M Plus | High (different BSP, different perf profile) |
| QCN9074 | MT7916 | Medium (different driver, same hostapd config) |
| I226-V | RTL8125BG | Low (both have mainline drivers, XDP difference) |
| SK Hynix LPDDR5 | Samsung LPDDR5 | Trivial (interchangeable, same JEDEC spec) |
| Samsung eMMC | Kioxia eMMC | Trivial (same JEDEC spec) |

---

## 8. Cost Summary by Compliance Tier

| Tier | Description | Unit Cost (MOQ 100) | Unit Cost (MOQ 1000) |
|------|-------------|--------------------|--------------------|
| **Hobbyist** | NanoPi R6S + USB WiFi, Chinese assembly | ~$120 | N/A |
| **Commercial** | Custom carrier + RK3588S SoM, Chinese assembly | ~$200 | ~$150 |
| **TAA-Compliant** | NXP SoM (Variscite) + US PCB/assembly | ~$500 | ~$350 |
| **TAA + FIPS** | Same + FIPS-validated crypto module + IPsec | ~$650 | ~$450 |
| **High Assurance** | Secure boot, X-ray inspection, trusted fab, FIPS | ~$900 | ~$600 |

---

## 9. Recommendations

### If building one for yourself (travel use):

1. Buy a **NanoPi R6S** ($79, 8GB RAM, 2x 2.5GbE + 1x GbE)
2. Add a **MT7921AU USB WiFi adapter** for upstream STA ($15)
3. Use the built-in Ethernet for LAN, USB WiFi for WAN
4. If you need WiFi AP: add a second USB WiFi (RT5572-based for 2.4/5GHz AP)
5. Flash Alpine Linux, build Kepha for `arm64`, deploy
6. Total: ~$100, 2 hours of setup

### If building for commercial sale:

1. Start with NanoPi R6S as reference design for Kepha-portable validation
2. Design custom carrier board for RK3588S SoM (CM3588) with:
   - 2x I226-V Ethernet
   - 2x M.2 E-key for WiFi radios
   - USB-C PD power
   - Aluminum enclosure with integrated heatsink
3. Qualify NXP i.MX8MP as TAA-compliant alternate platform
4. Target $200 retail, $350 TAA-compliant

### If building for government/DoD:

1. **Variscite VAR-SOM-MX8M-PLUS** (Israel, TAA-compliant)
2. US PCB fab (TTM Technologies) and US assembly (Benchmark Electronics)
3. Replace WireGuard with IPsec (strongSwan + kernel FIPS module)
4. Build Kepha with `GOEXPERIMENT=boringcrypto`
5. Secure boot via NXP HABv4
6. Get FIPS 140-3 validation for the crypto module (budget: $50k-150k, 12-18 months)
7. File ECCN classification with BIS
8. Target GSA Schedule listing

---

## 10. Open Questions

1. **Cellular WAN:** Should the portable device include a cellular modem (5G/LTE)
   as a third WAN option? Adds ~$50 BOM cost, significant regulatory cost (FCC/CE
   certification for intentional radiator), but eliminates dependency on hostile WiFi.

2. **Bluetooth:** BLE for initial device setup (phone app → Kepha config)?
   Most WiFi modules include BT. Low incremental cost but increases attack surface.

3. **GPS:** Useful for travel logging and automatic zone profile switching
   (e.g., "conference mode" vs "hotel mode"). Adds ~$5 BOM, antenna routing complexity.

4. **Display:** Small OLED (128x64 or 128x32) for status? Useful for showing VPN
   status, connected clients, WAN IP without needing to open the web UI.

5. **Kepha portable mode:** Should `gatekeeperd` have a `--portable` flag that
   automatically configures a 3-zone model (wan/lan/vpn) with sane travel defaults?
