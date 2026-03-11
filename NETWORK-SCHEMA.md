# Gatekeeper Network Schema — 192.168.4.0/22

## Supernet: 192.168.4.0/22 (1024 addresses: 192.168.4.0 – 192.168.7.255)

Gateway: 192.168.4.1 (eero — upstream/WAN until gatekeeper takes over)

---

## Zone Map

| Zone          | Subnet             | Usable Range                | Hosts | VLAN | GK Trust  | Purpose                                    |
|---------------|--------------------|-----------------------------|-------|------|-----------|--------------------------------------------|
| **mgmt**      | 192.168.4.0/26     | .4.1 – .4.62                | 62    | 2    | full      | BMC/IPMI/iLO/iDRAC, switches, PDUs, UPS    |
| **infra**     | 192.168.4.64/26    | .4.65 – .4.126              | 62    | 1    | full      | Proxmox hosts, gatekeeper, PXE, services   |
| **house**     | 192.168.4.128/25   | .4.129 – .4.254             | 126   | 10   | full      | Laptops, phones, workstations              |
| **dalec**     | 192.168.5.0/24     | .5.1 – .5.254               | 254   | 20   | full      | DALEC stack (server, gpu, compute)         |
| **iot**       | 192.168.6.0/25     | .6.1 – .6.126               | 126   | 30   | minimal   | Smart home, cameras, thermostats           |
| **guest**     | 192.168.6.128/25   | .6.129 – .6.254             | 126   | 40   | none      | Visitor WiFi, isolated                     |
| **vpn**       | 192.168.7.0/25     | .7.1 – .7.126               | 126   | —    | full      | WireGuard tunnel clients                   |
| **pxe**       | 192.168.7.128/26   | .7.129 – .7.190             | 62    | 50   | minimal   | Provisioning/PXE boot staging              |
| **lab**       | 192.168.7.192/26   | .7.193 – .7.254             | 62    | 60   | minimal   | Dev/test throwaway VMs                     |

---

## Static Assignments — mgmt (192.168.4.0/26)

| IP             | Hostname           | Role                         |
|----------------|--------------------|------------------------------|
| 192.168.4.1    | eero               | Upstream gateway (WAN)       |
| 192.168.4.2    | (reserved)         | Future secondary gateway     |
| 192.168.4.10   | sw-core-mgmt       | Core switch management       |
| 192.168.4.11   | sw-poe-mgmt        | PoE switch management        |
| 192.168.4.20   | trouble-ipmi       | Proxmox host BMC/IPMI        |
| 192.168.4.21–29| (reserved)         | Future server BMCs           |
| 192.168.4.30   | ups-mgmt           | UPS management card          |
| 192.168.4.31   | pdu-mgmt           | PDU management               |
| 192.168.4.32–39| (reserved)         | Future power/environment     |
| 192.168.4.40   | kvm-mgmt           | KVM-over-IP                  |
| 192.168.4.50–62| (DHCP pool)        | Mgmt DHCP (auto-discovered)  |

## Static Assignments — infra (192.168.4.64/26)

| IP             | Hostname           | Role                         |
|----------------|--------------------|------------------------------|
| 192.168.4.65   | trouble            | Proxmox VE host (target IP)  |
| 192.168.4.66   | gatekeeper         | CT 107 — firewall/DNS        |
| 192.168.4.67   | pxe                | CT 108 — PXE boot server     |
| 192.168.4.68   | (reserved)         | Future infra service         |
| 192.168.4.70   | alpine-docker      | CT 103 — Docker host         |
| 192.168.4.71   | rubot              | CT 105                       |
| 192.168.4.72   | homeschool         | CT 106                       |
| 192.168.4.73   | eero-mcp           | CT 9001                      |
| 192.168.4.90–120| (DHCP pool)       | Infra DHCP range             |

### Migration Notes (current → target)

| Host       | Current IP       | Target IP       | Status    |
|------------|------------------|-----------------|-----------|
| trouble    | 192.168.4.168    | 192.168.4.65    | pending   |
| gatekeeper | 192.168.7.117    | 192.168.4.66    | pending   |
| pxe        | (not created)    | 192.168.4.67    | pending   |
| dalec-*    | 192.168.7.30-32  | 192.168.5.10-12 | pending   |
| homeschool | 192.168.7.116    | 192.168.4.72    | pending   |

## Static Assignments — dalec (192.168.5.0/24)

| IP             | Hostname           | Role                         |
|----------------|--------------------|------------------------------|
| 192.168.5.1    | (gateway)          | Gatekeeper on this zone      |
| 192.168.5.10   | dalec-server       | CT 100                       |
| 192.168.5.11   | dalec-gpu          | CT 101                       |
| 192.168.5.12   | dalec-compute      | CT 102                       |
| 192.168.5.50–99| (DHCP pool)        | DALEC DHCP range             |

## Static Assignments — house (192.168.4.128/25)

| IP             | Hostname           | Role                         |
|----------------|--------------------|------------------------------|
| 192.168.4.129  | (gateway)          | Gatekeeper on this zone      |
| 192.168.4.130–148 | (static pool)   | Reserved for known devices   |
| 192.168.4.150–240 | (DHCP pool)     | House DHCP range             |

## VPN (192.168.7.0/25)

| IP             | Hostname           | Role                         |
|----------------|--------------------|------------------------------|
| 192.168.7.1    | gk-wg0             | WireGuard endpoint           |
| 192.168.7.2–126| (dynamic)          | VPN client pool              |

---

## DHCP Ranges per Zone

| Zone    | DHCP Start     | DHCP End       | Lease  |
|---------|----------------|----------------|--------|
| mgmt    | 192.168.4.50   | 192.168.4.62   | 24h    |
| infra   | 192.168.4.90   | 192.168.4.120  | 24h    |
| house   | 192.168.4.150  | 192.168.4.240  | 12h    |
| dalec   | 192.168.5.50   | 192.168.5.99   | 24h    |
| iot     | 192.168.6.20   | 192.168.6.120  | 1h     |
| guest   | 192.168.6.150  | 192.168.6.240  | 2h     |
| pxe     | 192.168.7.140  | 192.168.7.180  | 30m    |
| lab     | 192.168.7.200  | 192.168.7.240  | 4h     |

---

## Firewall Policy Summary

| From → To   | mgmt  | infra | house | dalec | iot   | guest | vpn   | pxe   | lab   | WAN   |
|-------------|-------|-------|-------|-------|-------|-------|-------|-------|-------|-------|
| **mgmt**    | allow | allow | deny  | deny  | deny  | deny  | deny  | deny  | deny  | allow |
| **infra**   | allow | allow | allow | allow | allow | allow | allow | allow | allow | allow |
| **house**   | deny  | deny  | allow | allow | deny  | deny  | —     | deny  | deny  | allow |
| **dalec**   | deny  | deny  | deny  | allow | deny  | deny  | —     | deny  | deny  | allow |
| **iot**     | deny  | deny  | deny  | deny  | allow | deny  | deny  | deny  | deny  | allow |
| **guest**   | deny  | deny  | deny  | deny  | deny  | allow | deny  | deny  | deny  | allow |
| **vpn**     | deny  | allow | allow | allow | deny  | deny  | allow | deny  | allow | allow |
| **pxe**     | deny  | allow | deny  | deny  | deny  | deny  | deny  | allow | deny  | allow |
| **lab**     | deny  | deny  | deny  | deny  | deny  | deny  | deny  | deny  | allow | allow |

**Key policy decisions:**
- **mgmt → infra only** — BMCs can reach infra (for PXE, DNS) but nothing else. No lateral to house/dalec/iot.
- **infra → everything** — gatekeeper, PXE, monitoring need full reach.
- **mgmt is a sink** — only infra and mgmt itself can reach mgmt. VPN excluded (VPN into BMC = use infra jump box).
- **iot/guest remain jailed** — egress to WAN only, nothing internal.

---

## PXE Server Answer

**CT 108 static IP: 192.168.4.67**

Tell the PXE team:
- IP: `192.168.4.67`
- Gatekeeper dhcp-boot target: `192.168.4.67`
- iPXE HTTP base URL: `http://192.168.4.67/`

---

## Implementation Notes

- All zones are **logical today** — single vmbr0, no VLANs yet
- VLANs get added when gatekeeper gets multi-NIC + 802.1Q trunking
- IoT and guest get strict egress-only (DNS + HTTPS out, nothing in)
- PXE zone is ephemeral — machines boot there, then land in their real zone
- VPN zone is overlay (WireGuard), not tied to a physical bridge
- Short DHCP leases on iot/guest/pxe by design (fast churn, stale prevention)
- mgmt zone is physically isolated where possible (dedicated switch port, no wireless)
- IP migrations tracked above — execute when gatekeeper gets multi-NIC + VLANs
