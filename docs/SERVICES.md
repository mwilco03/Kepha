# Gatekeeper Service Plugins

Gatekeeper includes 17+ service plugins that extend the base firewall functionality.

## Managing Services

```bash
gk service list                              # Show all available services
gk service enable <name>                     # Enable a service
gk service disable <name>                    # Disable a service
gk service configure <name> '<json-config>'  # Set service configuration
```

Or via API:
```bash
curl -X PUT -H "X-API-Key: $KEY" \
  -d '{"enabled": true, "config": {"blocklists": ["ads"]}}' \
  https://localhost:8080/api/v1/services/dns-filter
```

## Available Services

### Network Services
| Service | Description | Key Config |
|---------|-------------|------------|
| `dns-filter` | Ad/tracker blocking via DNS | `blocklists`, `custom_blocklist` |
| `encrypted-dns` | DoH/DoT via Unbound | `upstream_type` (doh/dot), `upstream_url` |
| `ntp` | NTP server for LAN | `servers`, `allow_networks` |
| `upnp` | UPnP/NAT-PMP port mapping | `allow_interfaces`, `deny_ports` |
| `ddns` | Dynamic DNS updates | `provider`, `hostname`, `token` |
| `avahi` | mDNS/DNS-SD discovery | `interfaces`, `publish_addresses` |

### Security Services
| Service | Description | Key Config |
|---------|-------------|------------|
| `ids` | Suricata IDS/IPS | `mode` (ids/ips), `interfaces`, `home_net` |
| `content-filter` | Content category filtering | `categories`, `action` (block/log) |
| `captive-portal` | Guest network portal | `redirect_url`, `allowed_macs` |

### VPN Services
| Service | Description | Key Config |
|---------|-------------|------------|
| `vpn-legs` | Site-to-site WireGuard tunnels | `peers`, `allowed_ips` |
| `vpn-provider` | Commercial VPN (Mullvad, PIA, etc.) | `provider`, `credentials` |

### Infrastructure Services
| Service | Description | Key Config |
|---------|-------------|------------|
| `multiwan` | Multi-WAN failover | `wan1_gateway`, `wan2_gateway`, `mode` |
| `bridge` | VLAN bridging | `interfaces`, `vlan_ids`, `stp` |
| `bandwidth` | Bandwidth monitoring | `interfaces`, `interval` |
| `traffic-shaping` | QoS / traffic shaping | `rules`, `default_class` |
| `frrouting` | BGP/OSPF via FRRouting | `bgp_asn`, `neighbors` |
| `certstore` | Certificate management (ACME) | `domains`, `email`, `provider` |

### Plugin Tiers

Services are categorized into safety tiers:
- **Passive**: Read-only monitoring (bandwidth, discovery)
- **Managed**: Controlled system changes (dns-filter, ntp)
- **Unsafe**: Significant system impact (ids in IPS mode, multiwan)

## Example: DNS Filtering

```bash
# Enable DNS filtering with ad and malware blocklists
gk service enable dns-filter
gk service configure dns-filter '{
  "blocklists": ["ads", "malware", "tracking"],
  "custom_blocklist": "/etc/gatekeeper/custom-blocklist.txt",
  "update_interval": "24h"
}'

# Check status
gk service list | grep dns-filter
```

## Example: IDS/IPS

```bash
# Enable Suricata in IDS mode (monitor only)
gk service enable ids
gk service configure ids '{
  "mode": "ids",
  "interfaces": "eth1",
  "home_net": "10.10.0.0/24",
  "rule_update": true
}'

# Switch to IPS mode (active blocking) — requires nfqueue
gk service configure ids '{"mode": "ips"}'
```
