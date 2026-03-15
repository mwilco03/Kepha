# Portable Kepha/Gatekeeper Device: Hardware Requirements & Supply Chain Analysis

**Status:** Thought Experiment / Design Study
**Date:** 2026-03-15
**Revision:** 2 — Added x86_64 platform analysis, on-device AI/MCP, competitor
landscape, white-label strategy, Intel vs AMD deep dive

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
| **Local LLM (MCP co-pilot)** | **Heavy, GPU-bound** | **3-7B model for policy analysis, threat detection, MCP tool orchestration** |

**Minimum:** 4x ARMv8.2-A cores @ 1.8 GHz with AES/SHA/PMULL crypto extensions
**Recommended (ARM):** 4x Cortex-A76 (or newer) cores @ 2.2+ GHz for comfortable Suricata headroom
**Recommended (x86_64):** AMD Ryzen 8840U/8845HS or Intel Core Ultra 155H — eliminates ARM downstream pain, adds iGPU for local AI inference

### Memory Requirements

| Consumer | Footprint | Notes |
|----------|-----------|-------|
| Kepha daemon (gatekeeperd) | ~30-50 MB | Go binary, alias cache, RBAC key cache |
| Suricata (with ET Open rules) | 500 MB - 1.5 GB | Rule loading is the killer; scales with ruleset size |
| Conntrack table | ~256 entries/MB RAM | Auto-scaled by performance tuner |
| dnsmasq | ~10-20 MB | Per-zone config, lease tables |
| Kernel + eBPF maps | ~100-200 MB | XDP programs, BPF maps, flowtables |
| OS overhead (Alpine) | ~50-80 MB | Minimal userspace |

| **Local LLM (3-7B Q4)** | 2-6 GB | iGPU shared memory (UMA). 3B model ~2GB, 7B ~4-5GB |

**Minimum:** 2 GB (no Suricata, no AI, basic zones)
**Recommended:** 16 GB DDR5 (Suricata + 3B model for MCP, iGPU allocation)
**Ideal:** 32 GB DDR5 (full Suricata + 7B model + large conntrack tables)

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
- Kernel crypto API with hardware acceleration (`CONFIG_CRYPTO_AES_ARM64_CE` or
  `CONFIG_CRYPTO_AES_NI_INTEL` for x86_64)
- For x86_64 with iGPU AI: `CONFIG_DRM_AMDGPU=m` (AMD) or `CONFIG_DRM_XE=m` (Intel)

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

---

# Part 2: x86_64 Platform Analysis — Why Not ARM

**Revision 2 addition.** The ARM analysis above is preserved for reference, but
the strong recommendation is to abandon ARM for this device category. x86_64 in
a mobile-efficient package solves every downstream problem ARM creates, and the
mobile gaming industry has already proven the power envelope is viable.

---

## 11. The Case Against ARM for a Portable Kepha Device

| Problem | ARM Reality | x86_64 Reality |
|---------|-------------|----------------|
| Kernel | Vendor BSP, device tree maintenance, patch backporting | Fedora/RHEL stock kernel boots unmodified |
| FIPS kernel module | Not validated for most distros on ARM | RHEL x86_64 kernel FIPS module is already validated |
| Driver support | "Does this chip have an ARM build?" | Everything targets x86 first |
| Suricata SIMD | ARM NEON path exists, less optimized | AVX2/SSE4.2 is the primary development target |
| WireGuard throughput | Good (~1 Gbps on A76 w/ crypto ext) | AVX2 ChaCha20 + Poly1305 = 3-5 Gbps on Zen 4 |
| Container images | Multi-arch? Maybe. | Every OCI image supports amd64 |
| Tooling | Cross-compilation, QEMU, emulation headaches | Native build. `go build`. Done. |
| Local AI/LLM | No iGPU. CPU-only inference. Slow. | iGPU (RDNA 3 or Arc) accelerates inference 2-5x |
| LXC/systemd-nspawn | Works but BSP kernel compatibility varies | Stock kernel, everything just works |

**The iGPU is the killer argument.** ARM SoCs have no meaningful GPU compute for
LLM inference. x86 APUs from AMD and Intel include iGPUs that turn a 7B model
from unusable (~5 t/s CPU-only) to interactive (~20 t/s iGPU-accelerated).

---

## 12. On-Device AI: The GPU Is Not Dead Weight

Kepha already has an MCP server with 25+ tools. Today, MCP tool orchestration
requires a cloud LLM. A portable security device phoning home to Claude/GPT for
policy decisions defeats the purpose. The iGPU enables **fully local, fully
private AI-driven network management.**

### What Models Fit on a Portable Device

| Model | Params | Quant | VRAM Needed | 780M (AMD) t/s | Arc 140V (Intel) t/s | Use Case |
|-------|--------|-------|-------------|----------------|---------------------|----------|
| Qwen 2.5 1.5B | 1.5B | Q4_K_M | ~1.2 GB | ~40-50 | ~35-45 | Fast log classifier, alert triage |
| Llama 3.2 3B | 3B | Q4_K_M | ~2 GB | ~25-35 | ~30-35 | MCP tool use, policy Q&A |
| Phi-4-mini | 3.8B | Q4_K_M | ~2.5 GB | ~25-35 | ~28-32 | Best reasoning/size ratio. 98.7% recall on threat detection w/ RAG |
| Qwen 2.5 7B | 7B | Q4_K_M | ~4.5 GB | ~19-20 | ~12-18 | Full MCP orchestration, complex policy analysis |
| Llama 3.2 3B | 3B | Q8_0 | ~3.5 GB | ~20-28 | ~22-28 | Higher quality at slight speed cost |

### Why Phi-4-mini (3.8B) Is the Default Choice

Research shows Phi-4-mini with retrieval-augmented generation (RAG) achieves
**98.7% recall on network threat detection** (UNSW-NB15 dataset). At 3.8B
parameters in Q4 quantization, it:

- Fits in ~2.5 GB iGPU shared memory
- Runs at ~25-35 tokens/sec on AMD Radeon 780M (interactive speed)
- Has the best reasoning-to-parameter ratio of any open model at this size
- Can reliably parse MCP tool schemas, construct API calls, interpret results
- Does NOT require internet access — fully air-gapped capable

### Minimum Viable Model Size for MCP Tool Use

For a model to reliably orchestrate Kepha's MCP tools (parse JSON, understand
tool schemas, construct correct API calls, interpret structured results):

- **3B parameters** — basic tool use (single-tool calls, simple queries)
- **3.8B parameters** — reliable structured output (Phi-4-mini sweet spot)
- **7B parameters** — complex multi-step orchestration (chains of tool calls)
- **Below 3B** — classification and parsing only, cannot do reliable tool calling

### Architecture: Local LLM + Kepha MCP

```
┌──────────────────────────────────────────────────────┐
│  User (phone/laptop on LAN)                          │
│  "Block all IoT devices from reaching the internet"  │
├──────────────────────────────────────────────────────┤
│  Kepha Web UI / REST API                             │
│  └─► MCP Server (internal/mcp/)                      │
│      └─► Local LLM (Phi-4-mini, iGPU-accelerated)   │
│          └─► MCP Tool Calls:                         │
│              1. list_zones() → identifies iot zone   │
│              2. create_alias(iot_devices, ...)        │
│              3. create_policy(iot→wan, deny, ...)     │
│              4. apply_config()                        │
├──────────────────────────────────────────────────────┤
│  No cloud. No API keys. No exfiltration risk.        │
│  Inference runs on iGPU at 25-35 t/s.                │
│  Total latency for above: ~3-5 seconds.              │
└──────────────────────────────────────────────────────┘
```

### Software Stack for Local AI

- **llama.cpp** with Vulkan backend (not ROCm — Vulkan sees full UMA memory,
  ROCm only sees BIOS-allocated VRAM and misses GTT)
- **llama-server** (HTTP API compatible with OpenAI chat completions format)
- Kepha MCP server connects to local llama-server instead of cloud API
- Model files stored on NVMe (~3-5 GB for Phi-4-mini Q4)
- Optional: multiple models hot-swappable via llama-server model loading API

---

## 13. AMD vs Intel: The x86_64 Platform Showdown

### Three Intel Tiers (Deep Dive)

#### Tier 1: Intel N100/N305 — The Budget Firewall Workhorse

| Spec | N100 | N305 | N150 (2025) | N355 (2025) |
|------|------|------|-------------|-------------|
| Cores | 4C/4T (E-cores) | 8C/8T (E-cores) | 4C/4T | 8C/8T |
| Boost | 3.4 GHz | 3.8 GHz | 3.6 GHz | 3.9 GHz |
| TDP | **6W** | **15W** | **6W** | **15W** |
| GPU | 24 EU (Xe Gen12) | 32 EU (Xe Gen12) | 24 EU | 32 EU |
| NPU | **None** | **None** | **None** | **None** |
| Memory | Single-channel DDR5 | Single-channel DDR5 | Single-channel DDR5 | Single-channel DDR5 |
| PCIe | 9x Gen3 | 9x Gen3 | 9x Gen3 | 9x Gen3 |
| AES-NI | Yes | Yes | Yes | Yes |
| 7B LLM | ~6-9 t/s (CPU only) | ~10-13 t/s (CPU only) | Similar | Similar |

**Verdict:** Excellent pure firewall. Terrible for AI. Single-channel memory is
the killer — ~19 GB/s bandwidth starves even small models. No NPU. The iGPU is
too weak for meaningful inference offload. This is Protectli territory: a box
that runs pfSense/OPNsense/Kepha as a firewall and nothing else.

**Where to buy:** CWWK, Topton, Protectli VP2430. $100-300 range. Dozens of
4x 2.5GbE i226-V fanless options on Amazon/AliExpress.

#### Tier 2: Intel Core Ultra 7 155H (Meteor Lake) — The Sweet Spot

| Spec | Value |
|------|-------|
| Cores | 16C/22T (6P + 8E + 2LP) |
| Boost | 4.8 GHz |
| TDP | **28W base** (configurable down, 115W MTP) |
| GPU | 8 Xe cores (128 EUs), Xe-LPG, **~18 TOPS INT8** |
| NPU | NPU 3.0, **11 TOPS** |
| Platform TOPS | **34** (5 CPU + 18 GPU + 11 NPU) |
| Memory | **Dual-channel** DDR5-5600 / LPDDR5x-7467. Upgradeable SO-DIMM. Up to 96 GB. |
| PCIe | **8x Gen5 + 20x Gen4 = 28 lanes** |
| AES-NI | Yes |
| WiFi | Wi-Fi 7, Thunderbolt 4, USB4 |
| 3B LLM | ~20-30 t/s (iGPU) |
| 7B LLM | ~8-15 t/s (iGPU) |

**Verdict:** This is the networking + AI sweet spot for Intel. 28 PCIe lanes
means you can hang 8x 2.5GbE NICs and still have room for NVMe and WiFi.
Dual-channel DDR5 with up to 96 GB. The iGPU is weaker than AMD's 780M but
usable for 3B models. The NPU handles background classification at 11 TOPS
while the CPU runs Suricata.

**Where to buy:** CWWK F28 (8x i226-V 2.5GbE, ~$700-1,160 configured). Topton
Ultra 7 155H firewall board (6x 2.5G + optional 10G SFP+, ~$400+ barebones).

#### Tier 3: Intel Core Ultra 7 258V (Lunar Lake) — AI Beast, Network Hobbled

| Spec | Value |
|------|-------|
| Cores | 8C/8T (4P Lion Cove + 4E Skymont, NO hyperthreading) |
| Boost | 4.8 GHz |
| TDP | **17W base** (8W minimum, 30W MTP) |
| GPU | Arc 140V, 8 Xe2 cores (Battlemage), **~67 TOPS INT8**, XMX matrix units |
| NPU | NPU 4.0, **48 TOPS** |
| Platform TOPS | **120** (5 CPU + 67 GPU + 48 NPU) |
| Memory | **On-package LPDDR5x-8533**. 16 or 32 GB. **NOT upgradeable.** |
| PCIe | **4x Gen5 + 4x Gen4 = 8 lanes total** |
| AES-NI | Yes |
| 3B LLM | ~32-35 t/s (iGPU+NPU) |
| 7B LLM | ~12-18 t/s (iGPU+NPU) |

**Verdict:** The NPU (48 TOPS) and Xe2 GPU (67 TOPS) are incredible for AI.
The 8-lane PCIe limit is fatal for a multi-NIC appliance. You can physically
fit maybe 2x 2.5GbE ports before running out of lanes. On-package RAM means
16 or 32 GB, fixed at purchase. Only 8 threads (no SMT).

**This is an AI co-processor, not a firewall platform.** Could be paired with
an N305 firewall box over 2.5GbE, with Lunar Lake running the LLM and the
N305 running the packet path. But that's two boxes.

**Where to buy:** MSI Cubi NUC AI+ 2MG (dual 2.5GbE, ~$600-1,000). ASUS NUC 14
Pro AI. No dedicated firewall appliances exist with Lunar Lake.

### AMD Comparison: Ryzen 8840U / 8845HS (Zen 4 + RDNA 3)

| Spec | Ryzen 7 8840U | Ryzen 7 8845HS |
|------|---------------|----------------|
| Cores | 8C/16T (Zen 4) | 8C/16T (Zen 4) |
| Boost | 5.1 GHz | 5.2 GHz |
| cTDP | **9-28W** | **15-54W** |
| GPU | Radeon 780M, 12 CUs RDNA 3, **~17.8 TFLOPS FP16** | Same |
| NPU | Ryzen AI (XDNA 1), ~10 TOPS | Same |
| Memory | Dual-channel DDR5-5600, SO-DIMM, up to 64 GB | Same |
| PCIe | 20x Gen4 | 20x Gen4 |
| AES-NI | Yes | Yes |
| 3B LLM | ~25-35 t/s (iGPU Vulkan) | Same |
| 7B LLM | ~19-20 t/s (iGPU Vulkan) | Same |

### AMD Strix Point: Ryzen AI 9 HX 370 (Zen 5 + RDNA 3.5 + XDNA 2)

| Spec | Value |
|------|-------|
| Cores | 12C/24T (4x Zen 5 + 8x Zen 5c) |
| GPU | Radeon 890M, 16 CUs RDNA 3.5, **41% faster than 780M** |
| NPU | XDNA 2, **50 TOPS** |
| Memory | Dual-channel LPDDR5x-7500 |
| 7B LLM | ~17-20 t/s (iGPU, ~400 t/s prefill with NPU assist) |

### The Head-to-Head

| Factor | AMD 8840U | Intel 155H | Intel 258V | Intel N305 |
|--------|-----------|------------|------------|------------|
| **Best 7B LLM t/s** | **~19-20** | ~8-15 | ~12-18 | ~10-13 (CPU) |
| **Best 3B LLM t/s** | **~25-35** | ~20-30 | ~32-35 | ~5-10 (CPU) |
| **PCIe lanes** | 20x Gen4 | **28 (8x5+20x4)** | 8 total | 9x Gen3 |
| **Max RAM** | 64 GB | **96 GB** | 32 GB (fixed) | 32 GB |
| **Configurable TDP** | **9-28W** | 28W base | 17W base | 6W base |
| **Multi-NIC boards** | Limited (4x 2.5G) | **Excellent (8x 2.5G)** | Poor (2x max) | **Excellent** |
| **Firewall + AI** | **Best balance** | Good firewall, OK AI | Best AI, weak firewall | Best firewall, no AI |
| **Price range** | $200-400 | $400-1,200 | $600-1,000 | **$100-300** |

**Winner for Kepha portable:** AMD Ryzen 7 8840U at 9W cTDP.

- Best iGPU AI inference of any platform at this power level
- 20 PCIe Gen4 lanes — enough for 4x 2.5GbE + NVMe + WiFi
- Dual-channel DDR5 up to 64 GB — Suricata + 7B model + headroom
- 9W configurable TDP — 100Wh battery bank lasts 12-20 hours at idle, 8-12 under load
- The mobile gaming industry proved this chip runs at 9W in a fanless handheld (Steam Deck, ROG Ally)

**Runner-up:** Intel Core Ultra 7 155H if you need maximum PCIe lane count
(8x 2.5GbE + 10G SFP+) and are OK with weaker AI inference. Better for a
desk/rack appliance than a battery-powered travel device.

---

## 14. Competitor Landscape & Pricing

### What People Are Actually Buying

| Product | Price | CPU | NICs | Key Differentiator |
|---------|-------|-----|------|--------------------|
| GL.iNet Beryl AX (MT3000) | $90 | MediaTek MT7981B 1.3GHz dual-core | 1x 2.5G + 1x 1G | USB-C, travel-sized, OpenWrt |
| GL.iNet Beryl 7 (MT3600BE) | $140 | MediaTek quad-core 2.0GHz | 2x 2.5G | WiFi 7, USB-C powered, 1.1Gbps WireGuard |
| GL.iNet Slate 7 (BE3600) | $170 | Same | 2x 2.5G | Same + built-in display |
| **Firewalla Orange** | **$339** | **4-core ARM** | **2x 2.5GbE** | **WiFi 7, USB-C, 244g. First batch sold out.** |
| Firewalla Purple SE | $179-199 | ARM quad-core | 2x 1GbE | Entry-level IPS appliance |
| Firewalla Purple | $319-349 | 6-core ARM | 2x 1GbE | Full IPS + short-range WiFi |
| Firewalla Gold SE | $439-469 | RK3568 (4x A55) | 2x 2.5G + 2x 1G | Flagship home firewall |
| Firewalla Gold Plus | $569-619 | x86 Intel | 4x 2.5GbE | SMB segment |
| Firewalla Gold Pro | $889 | Intel N97 | 2x 10GbE + 2x 2.5GbE | Enterprise/prosumer |
| Protectli VP2430 | $299 (bare) | Intel N150 | 4x 2.5GbE i226-V | US-based, coreboot, no OS |
| Protectli VP2440 | $400-500 | Intel N150 | 2x 10G SFP+ + 2x 2.5G | First Protectli with 10G |
| Netgate 1100 | $225 | ARM A53 dual-core | 3x 1GbE | pfSense Plus included |
| Netgate 2100 | $369-412 | ARM A53 dual-core | 4x 1GbE + 1 SFP | Mid-range pfSense |
| Peplink BR1 Mini 5G | $500-600 | ARM | 1x GbE | Cellular (5G modem built-in) |
| pcEngines APU | **Discontinued (2023)** | — | — | Nothing replaced it at its price point |

### Where the Money Is

| Tier | Price | Volume | Margin | Key Players |
|------|-------|--------|--------|-------------|
| < $40 | Impulse buy travel router | **Massive** | Razor-thin | GL.iNet Mango ($25), Shadow ($30), Opal ($35) |
| $40-100 | Considered travel router | Very High | Thin | GL.iNet Beryl AX ($89), TP-Link WR1502X ($60) |
| $100-200 | Prosumer / homelab | High | Moderate | CWWK N100 4-port ($117 all-in), GL.iNet Beryl 7 ($140), Firewalla Purple SE ($199) |
| $200-500 | SMB / Professional | Medium | High (65-75%) | Firewalla Orange ($339), Gold SE ($439), Protectli VP2430 ($299) |
| $500+ | Enterprise edge | Low | Highest | Firewalla Gold Plus/Pro, Netgate |

### Price Reality Check

A GL.iNet Mango is **$25 delivered same-day from Amazon.** An Opal is $35. A
Beryl AX is $89. These are impulse purchases — the same buying decision as a
USB hub or a phone cable. No research. No reviews. Add to cart, done.

At $100, you've crossed into a different purchase psychology. At $200, you need
a reason. At $300+, you need a justification. At $500+, you're writing a
business case.

**The $300-500 tier is where Firewalla lives**, but Firewalla earned the right
to charge that by starting at $49 on Kickstarter in 2017 and building brand
trust over 9 years. They didn't enter the market at $339.

**The actual competitive floor:**
- CWWK N100 4-port 2.5GbE barebone: **$89-110 on Amazon**
- Add 8GB DDR5 + 128GB NVMe: **$117 total, delivered same-day**
- Dell Wyse 5070 Extended + used Intel quad-NIC: **$65-75 on eBay**
- GL.iNet Beryl AX (WiFi 6, WireGuard, OpenWrt): **$89 on Amazon**

Anyone can build a pfSense/OPNsense box for $117. The hardware is not the moat.
The software is the moat. The UX is the moat. The "I don't need to know
networking" is the moat.

### Firewalla: The Model to Study

Firewalla went from a $90K Kickstarter in 2017 to an estimated $15-30M annual
revenue. Their playbook:

1. **No subscription fees** — one-time hardware purchase (key differentiator vs enterprise)
2. **Mobile app UX** — consumer-friendly, hides complexity
3. **Crowdfunding for market validation** — each new product launched via Kickstarter/Indiegogo
4. **Software is the moat** — hardware is commodity ARM/Intel
5. **Direct-to-consumer** — no enterprise sales team
6. **Open-source device code** — builds community trust

**Estimated Firewalla BOM (Gold SE at $439):**
- RK3568 SoC: ~$12-15
- 4GB DDR4: ~$8-10
- 32GB eMMC: ~$4-5
- Ethernet PHYs: ~$15-20
- PCB + passives + enclosure + PSU: ~$20-30
- **Estimated BOM: ~$60-80**
- **Landed cost: ~$90-120**
- **Gross margin: ~70-75%**

**The Firewalla Orange ($339) directly validates the portable security appliance
category.** It's a pocket-sized WiFi 7 firewall with USB-C power, 2x 2.5GbE,
full IPS/VPN/microsegmentation. First batch sold out immediately.

### What Kepha Brings That They Don't

| Capability | Firewalla | GL.iNet | Kepha |
|------------|-----------|---------|-------|
| Firewall | nftables, basic rules | OpenWrt nftables | nftables via netlink, alias-first policy engine |
| IDS/IPS | Yes (custom) | No | Suricata (full ET Open rules) |
| VPN | WireGuard, OpenVPN | WireGuard, OpenVPN | WireGuard with full peer management + QR |
| Zone model | Microsegmentation | Basic WAN/LAN | 9 configurable zones with inter-zone policies |
| API | Proprietary app API | LuCI REST | 40+ endpoint REST API + OpenAPI 3.1 |
| AI/MCP | No | No | **25+ MCP tools, local LLM orchestration** |
| Config management | App-driven | Web/SSH | Transactional SQLite, full rollback, audit log |
| XDP/eBPF | No | No | Full fast-path packet processing |
| Active countermeasures | No | No | Tarpit, latency injection, RST chaos (disabled by default) |
| LXC/container isolation | No | Docker (limited) | Native LXC, systemd-nspawn, full service isolation |

**The MCP + local AI story is the differentiator nobody else has.** "Talk to
your firewall in English, it configures itself, no cloud required" is a pitch
that Firewalla cannot match without shipping GPU-capable hardware.

---

## 15. White-Label & Rebrandable Hardware

### ODM Manufacturers Who Will Rebrand

| Vendor | HQ | Products | Custom Branding | MOQ | Notes |
|--------|------|----------|----------------|-----|-------|
| **CWWK** | Shenzhen | Multi-NIC x86 mini PCs (N100-Core Ultra) | Free logo printing | 10-50 units | Also sells on Amazon. Same factory as Topton. |
| **Topton** | Shenzhen | Same as CWWK (same OEM, different brand) | Free logo printing | 10-50 units | Also appears as HUNSN, Glovary, EGSMTPC |
| **GL.iNet** | Shenzhen | Travel routers (ARM, WiFi) | **Full white-label service**: hardware + firmware + branding + cloud platform | Case-by-case | Most turnkey option. They handle everything. |
| **Qotom** | Shenzhen | Intel multi-NIC mini PCs | OEM/ODM services | ~50+ | Consistent quality among Chinese ODMs |
| **Yanling** | Shenzhen | Industrial fanless PCs | OEM services | ~100+ | Industrial-grade |
| **Axiomtek** | **Taiwan** | Enterprise network appliance platforms | Formal OEM/ODM programs | ~100+ | Higher quality/price, TAA-friendly (Taiwan) |

### The Practical White-Label Strategy

**Phase 1 — Prove the product ($0 hardware cost):**
- Publish a "Kepha Certified Hardware" list
- Recommend Protectli VP2430 ($299) or CWWK N305 4-port ($180)
- Sell Kepha as software subscription / support contract
- Users buy their own hardware, install Kepha

**Phase 2 — Pre-configured units ($5k-10k investment):**
- Buy 50x CWWK/Topton AMD 8840U 4-port boards (~$200 ea = $10k)
- Custom logo on boot screen and enclosure
- Pre-flash Kepha firmware (Fedora IoT + Kepha + Phi-4-mini model)
- Sell as "Kepha Gateway" at $449-599
- Margin: 50-70%

**Phase 3 — TAA-compliant SKU ($25-50k investment):**
- Source from Axiomtek (Taiwan, TAA-designated) or commission
  Protectli-style US final assembly
- Same software stack
- Sell as "Kepha Gateway GOV" at $699-899
- List on GSA Schedule via Carahsoft/Immix reseller

### GL.iNet White-Label — Same Kepha, Pocket-Sized

GL.iNet explicitly offers white-label service with:
- Small batch for market validation
- Full customization (hardware + firmware + branding + cloud management)
- GoodCloud remote management platform (customizable with your branding)
- Their ImageBuilder tool for custom OpenWrt firmware

#### What's Actually Inside GL.iNet Devices

| Device | Price | SoC | CPU | Arch | RAM | Storage | OpenWrt |
|--------|-------|-----|-----|------|-----|---------|---------|
| Opal (SFT1200) | $35 | SiFlower SF19A2890 | 2C MIPS 1.0GHz | **MIPS32** | 128 MB | 128 MB NAND | **No upstream** |
| Beryl AX (MT3000) | $89 | MediaTek MT7981BA | 2C A53 1.3GHz | AArch64 | 512 MB | 256 MB NAND | **Yes (filogic)** |
| Slate AX (AXT1800) | $89 | Qualcomm IPQ6000 | 4C A53 1.2GHz | AArch64 | 512 MB | 128 MB NAND | Snapshot only |
| Brume 2 (MT2500) | $90 | MediaTek MT7981B | 2C A53 1.3GHz | AArch64 | **1 GB** | **8 GB eMMC** | Yes (filogic) |
| Beryl 7 (MT3600BE) | $140 | MediaTek (TBD) | 4C A53 2.0GHz | AArch64 | 512 MB | 512 MB NAND | Not yet |
| Flint 2 (MT6000) | $130 | MediaTek MT7986AV | 4C A53 2.0GHz | AArch64 | **1 GB** | **8 GB eMMC** | **Yes (filogic)** |

Key findings:
- **Everything except the $35 Opal is AArch64 ARM Cortex-A53.** The Opal is
  MIPS32 with 128MB RAM — dead end, ignore it.
- **U-Boot is unlocked on all models.** Serial console access via 3.3V UART header.
  The Flint 2 also has a JTAG header.
- **The Flint 2 and Brume 2 have 1GB RAM + 8GB eMMC.** That's enough for LXC.
- All MediaTek models are fully supported in upstream OpenWrt (filogic target,
  kernel 6.12.x).
- GL.iNet's white-label program customizes **their** OpenWrt fork — you get
  their build system, add packages, change branding. For full firmware
  replacement you'd negotiate an ODM agreement, but the hardware supports it
  (unlocked U-Boot, standard MediaTek DTS in mainline Linux).

#### The Same Architecture — Not a Different Product

```
On Proxmox (current):                On GL.iNet (portable):

┌──────────────────────┐            ┌──────────────────────┐
│   Kepha (gatekeeperd)│            │   Kepha (gatekeeperd)│
│   Go binary, arm64   │            │   Go binary, arm64   │
├──────────────────────┤            ├──────────────────────┤
│   Alpine Linux LXC   │            │   Alpine Linux LXC   │
├──────────────────────┤            ├──────────────────────┤
│   LXC runtime        │            │   LXC runtime        │
├──────────────────────┤            ├──────────────────────┤
│   Proxmox VE (Debian)│            │   OpenWrt (musl libc)│
│   x86_64 or aarch64  │            │   aarch64 (MT7986)   │
├──────────────────────┤            ├──────────────────────┤
│   Proxmox host HW    │            │   GL.iNet Flint 2    │
│   (server/PC)        │            │   ($130, pocket-size) │
└──────────────────────┘            └──────────────────────┘
```

**It's the same stack.** Kepha runs in an Alpine LXC container. The container
doesn't care if the host is Proxmox on a rack server or OpenWrt on a travel
router. The Go binary cross-compiles to `GOARCH=arm64` trivially. The nftables
netlink API is architecture-independent. The SQLite database is portable.

What changes:
- Host OS: Proxmox → OpenWrt (or bare Alpine/Armbian)
- LXC management: Proxmox GUI → `liblxc` CLI or Incus
- Network interfaces: veth on Proxmox bridge → veth on OpenWrt bridge
- WiFi management: not applicable → hostapd (already on OpenWrt)
- WAN uplink: Ethernet → WiFi STA (wpa_supplicant, already on OpenWrt)

What doesn't change:
- Kepha binary (same Go code, `GOOS=linux GOARCH=arm64`)
- nftables rules (same netlink calls)
- WireGuard (same kernel module)
- dnsmasq (same config generation)
- SQLite config store (same file)
- REST API / Web UI / MCP server (same code)
- XDP/eBPF (same kernel programs, if kernel supports it)

#### LXC on ARM: What's Actually Needed

LXC runs natively on any Linux with kernel cgroup and namespace support.
**You do not need Proxmox.** You need:

- Kernel with `CONFIG_NAMESPACES`, `CONFIG_CGROUPS`, `CONFIG_USER_NS`
- `liblxc` userspace (available as OpenWrt package or Alpine `apk add lxc`)
- That's it.

Alpine LXC containers run in as little as **64MB RAM**. On a 1GB device
(Flint 2, Brume 2), the memory budget is:

| Component | RAM Usage |
|-----------|-----------|
| OpenWrt host + WiFi drivers | ~80-100 MB |
| LXC runtime overhead | ~0 (shares host kernel) |
| Alpine container rootfs | ~20-30 MB |
| Kepha binary (gatekeeperd) | ~30-50 MB |
| dnsmasq | ~10-15 MB |
| nftables/conntrack kernel | ~20-50 MB |
| **Total** | **~160-245 MB** |
| **Free for conntrack/caches** | **~755-840 MB** |

No Suricata (needs 500MB+). No local AI. But full Kepha firewall with zones,
aliases, policies, WireGuard, XDP (if kernel supports it), web UI, API, MCP
server. On a $130 device that fits in your pocket.

On 512MB devices (Beryl AX, Beryl 7): tighter but workable. ~300MB free
after Kepha. Enough for basic operation, not for heavy conntrack tables.

#### The Turris Precedent

The Turris Omnia already ships LXC container management in a router's web UI.
1GB RAM, ARM, OpenWrt-derivative. Users run Home Assistant, Pi-hole, and other
services in LXC containers on their router. This is not experimental — it's
a shipping product since 2016.

#### Lightweight LXC Management (No Proxmox)

| Option | Weight | Features |
|--------|--------|----------|
| Raw `liblxc` + `lxc-*` CLI | Zero overhead | Manual config files, CLI management |
| **Incus** (LXD fork) | Light Go daemon | REST API, CLI, optional web UI, image management |
| systemd-nspawn + machinectl | Zero extra packages | Basic container management, systemd-native |
| Kepha manages its own LXC | Zero extra packages | Kepha calls liblxc directly from Go |

**The cleanest path:** Kepha manages its own container lifecycle via `liblxc`
Go bindings. No external management tool needed. Kepha already owns the network
config — it should own the container too.

---

## 16. Revised Strategy: Meet the Market Where It Is

### The Wrong Approach

Selling a $449 box into a market where $89 is "expensive" and $39 is "normal."
Nobody cares about your iGPU inference benchmarks when the GL.iNet Opal does
90% of what they need for $35.

### The Right Approach

**Software is the product. Hardware is someone else's problem.**

The Firewalla lesson isn't "charge $339 for hardware." The Firewalla lesson
is "software is the moat, hardware is commodity." They just also happen to
sell the hardware. You don't have to.

### Tier 0: Free firmware image ($0 investment)

Kepha as a downloadable image. Flash it to:
- **CWWK/Topton N100 4-port ($117 all-in)** — the homelab crowd
- **Protectli VP2430 ($299)** — the "I want US support" crowd
- **Dell Wyse 5070 + used quad-NIC ($70)** — the budget crowd
- **Any x86_64 box with 2+ NICs** — the "I have old hardware" crowd

This is how pfSense and OPNsense built their user bases. Zero hardware cost.
Zero inventory. Zero logistics. Pure software distribution.

**What you're competing with at this tier:**
- pfSense CE (free)
- OPNsense (free)
- OpenWrt (free)

**What Kepha has that they don't:**
- MCP server (AI-ready policy management)
- Transactional config with rollback
- Alias-first zone model (simpler than raw nftables rules)
- XDP/eBPF fast-path
- Active countermeasures
- REST API with OpenAPI 3.1 spec

**Investment:** 12 weeks for the firmware image (Fedora IoT + Kepha). This is
the firmware work discussed in Part 1. No hardware spend.

### Tier 1: "Kepha Certified" hardware list ($0 investment)

Publish a compatibility matrix. Tested hardware. Installation guides.
Community support. Same model as pfSense's hardware compatibility list.

| Hardware | Price | Arch | Where to Buy | Kepha Rating |
|----------|-------|------|-------------|--------------|
| **GL.iNet Brume 2** | $90 | arm64 | Amazon | **Portable pick** (1GB, 8GB eMMC, headless) |
| **GL.iNet Flint 2** | $130 | arm64 | Amazon | **Portable + WiFi** (1GB, 8GB eMMC, WiFi 6) |
| GL.iNet Beryl AX | $89 | arm64 | Amazon | Portable (512MB — tight but works) |
| Dell Wyse 5070 Ext + Intel quad-NIC | $70 | x86_64 | eBay | Budget x86 |
| CWWK N100 4x 2.5GbE | $117 | x86_64 | Amazon | Recommended x86 |
| CWWK N305 4x 2.5GbE | $160 | x86_64 | Amazon | Best value x86 |
| Protectli VP2430 | $299 | x86_64 | Amazon | US-supported x86 |
| CWWK AMD 8840U 4x 2.5GbE | $305 | x86_64 | Amazon | AI-capable x86 |

People buy their own hardware. You don't touch it. No inventory, no returns,
no RMA, no shipping, no customs, no TAA headache.

### Tier 2: Support subscription ($0 hardware investment)

Once the free image has users:
- **Community tier:** Free. Forum support. Community wiki.
- **Pro tier ($8-15/month):** Priority support, automatic updates,
  pre-built Suricata rulesets, threat intelligence feeds, optional
  cloud dashboard for monitoring (not required — fully local by default).
- **Business tier ($30-50/month):** Multi-site management, SSO/LDAP,
  SLA, phone support.

This is the Netgate model (pfSense CE is free, pfSense Plus is paid) and
the Canonical model (Ubuntu is free, Ubuntu Pro is paid).

### Tier 3: Pre-configured hardware (only after Tier 0-2 prove demand)

**Only if** the firmware image gets traction (1000+ downloads, 100+ active
installs, community forming):
- Buy 20x CWWK N100 4-port ($117 ea = $2,340)
- Pre-flash Kepha firmware
- Sell as "Kepha Box" at **$179-199** (not $449)
- Margin: ~35-40% (thin, but you're selling convenience, not hardware)
- **This competes with Firewalla Purple SE ($199), not Gold SE ($439)**

The AI-capable AMD 8840U box at $449-599? That's Tier 4. Maybe. After you
have brand trust. After people know what Kepha is. After someone has run the
$117 version for 6 months and wants more. You earn the right to charge more.

### Tier 4: The Premium Play (12-18 months out)

**Only if** Tier 3 sells and users are asking for more:
- AMD 8840U or Ryzen AI 9 with on-device LLM
- $349-449 price point (competing with Firewalla Orange/Gold SE)
- Local AI is the differentiator that justifies the premium
- TAA-compliant variant for government ($699-899)

### The Critical Realization

pcEngines APU died in 2023. Their product was $150-200, 3-port, AMD, fanless,
open-source friendly. **Nothing has replaced it at that price point.** The
CWWK N100 at $117 is close but nobody has built the "pfSense appliance for
normal people" around it. That gap is the opportunity.

The gap is not "expensive AI firewall." The gap is "pfSense that doesn't
require a networking degree, at a price that doesn't require a business case."

---

## 17. Honest Cost Comparison

| What You're Competing With | Price | What They Get |
|---------------------------|-------|---------------|
| GL.iNet Opal | $35 | Travel WiFi, WireGuard, OpenWrt. Impulse buy. |
| GL.iNet Beryl AX | $89 | WiFi 6, 2.5G WAN, WireGuard 300Mbps. |
| TP-Link WR1502X | $60 | WiFi 6, USB-C, VPN. |
| CWWK N100 + pfSense (DIY) | $117 | 4x 2.5GbE, full firewall, manual setup. |
| Firewalla Purple SE | $199 | IPS, VPN, app-driven UX. "It just works." |
| Firewalla Orange | $339 | Portable WiFi 7 firewall + IPS. Premium. |
| Kepha firmware (free) | $0 + hardware | Everything Kepha does. You assemble. |
| Kepha Box (Tier 3, future) | $179-199 | Pre-configured, tested, supported. |

The playbook: **undercut Firewalla Purple SE at $179-199 with dramatically more
capable software on slightly better hardware.** Or just give the software away
and let the $117 CWWK box be the hardware recommendation.

---

## 18. Revised Open Questions

1. **Is the firmware image enough?** pfSense and OPNsense prove software-only
   distribution works. But both have terrible UX for non-experts. If Kepha's
   web UI + MCP tools make it genuinely accessible to non-networking people,
   that alone is the differentiator — no hardware play needed.

2. **OpenWrt port:** Should Kepha run on GL.iNet travel routers? That puts it
   on $35-89 hardware with WiFi. The trade-off: ARM, limited RAM (128MB-512MB
   on cheap models), OpenWrt kernel constraints. Kepha's Go binary and SQLite
   may be too heavy for a 128MB MIPS device. The Beryl AX (512MB) might work
   with a stripped-down Kepha (no Suricata, no XDP, basic zones only).

3. **"Kepha Lite" for constrained hardware:** A reduced Kepha build that runs
   on 256-512MB ARM devices. No Suricata, no XDP, no local AI. Just nftables
   zones + WireGuard + dnsmasq + web UI + API. This is what would run on a
   $35 GL.iNet Opal and compete directly in the travel router space.

4. **Local AI as an upgrade path:** Start with Kepha Lite on cheap hardware.
   Users who want AI-driven management upgrade to x86_64 hardware where the
   iGPU enables local LLM. The MCP tools work with cloud LLMs in the meantime
   (user provides their own API key). Local AI is a feature, not the product.

5. **The $70 Dell Wyse play:** Should the "getting started" guide literally be
   "buy a $50 Dell Wyse 5070 on eBay, add a $20 quad-NIC, flash this image"?
   That's the kind of accessible entry point that builds a community.

6. **Crowdfunding for validation:** Firewalla launched every product on
   Kickstarter/Indiegogo first. The first Firewalla Red raised $90K. Is a
   Kickstarter for a "Kepha Box" ($179 pre-configured N100) the right way to
   test market demand before committing to inventory?
