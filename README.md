# Gatekeeper

Network firewall appliance for Alpine Linux LXC containers. Single Go binary providing nftables firewall management, DHCP/DNS (dnsmasq), WireGuard VPN, and a web management UI — all driven from a SQLite configuration store.

## Features

- **nftables compiler** — zone/alias/policy model compiled to nftables rulesets with safe-apply and auto-rollback
- **DHCP & DNS** — dnsmasq integration with per-zone DHCP ranges, static leases, and upstream DNS
- **WireGuard VPN** — key generation, peer management, client config with QR codes
- **Web UI** — 11-page management dashboard (zones, devices, aliases, policies, firewall rules, DHCP leases, WireGuard peers, services)
- **REST API** — full CRUD for all configuration objects, dry-run, path testing, audit log
- **CLI** (`gk`) — direct-mode (SQLite) or API-mode with HTTPS auto-detection
- **MCP server** — optional Model Context Protocol endpoint for AI-driven management
- **Service plugins** — DNS filtering, IDS (Suricata), UPnP, DDNS, NTP, bandwidth monitoring, multi-WAN, and more

## Quickstart (Alpine LXC)

### Prerequisites

- Proxmox VE (or any LXC host)
- Alpine Linux container template

### 1. Create the container

```sh
pct create 107 local:vztmpl/alpine-3.23-default_20260116_amd64.tar.xz \
  --hostname gatekeeper \
  --cores 2 --memory 256 --swap 0 \
  --storage local-lvm --rootfs local-lvm:2 \
  --net0 name=eth0,bridge=vmbr0,ip=dhcp \
  --unprivileged 0 --start 1
```

### 2. Push source and install

```sh
# From the host:
tar czf /tmp/gatekeeper-src.tar.gz --exclude='.git' -C /path/to/gatekeeper .
pct push 107 /tmp/gatekeeper-src.tar.gz /root/gatekeeper-src.tar.gz

# Inside the container:
pct exec 107 -- sh -c '
  mkdir -p /root/gatekeeper && cd /root/gatekeeper
  tar xzf /root/gatekeeper-src.tar.gz
  sh scripts/install-alpine.sh
  rc-service gatekeeperd start
'
```

### 3. Access

```
Web UI:   https://<container-ip>:8080
API:      https://<container-ip>:8080/api/v1/
API Key:  cat /etc/gatekeeper/api.key   (inside container)
CLI:      gk status
```

The web UI requires the API key to log in. The CLI works in direct mode (reads SQLite) by default, or set `GK_MODE=api` for remote access.

## Architecture

```
                     +------------------+
                     |   Web Browser    |
                     +--------+---------+
                              |
                    HTTPS :8080 (TLS)
                              |
            +-----------------+------------------+
            |                 |                  |
        /api/v1/*         /mcp/*              /*
     (REST + auth)     (MCP server)      (Web UI + session)
            |                 |                  |
            +-----------------+------------------+
                              |
                     +--------+---------+
                     |   gatekeeperd    |
                     +--------+---------+
                              |
        +----------+----------+----------+----------+
        |          |          |          |          |
    SQLite     nftables   dnsmasq   WireGuard  Services
    (config)   (firewall) (DHCP/DNS) (VPN)     (plugins)
```

## Configuration Model

**Zones** define network segments (wan, lan, iot, guest, vpn, etc.) with interfaces and trust levels.

**Aliases** are named sets of IPs, networks, MACs, or ports used in policy rules.

**Policies** contain ordered rules that match traffic by protocol, ports, and aliases. Each policy has a default action (allow/deny/reject).

**Profiles** bind a policy to a zone. Devices are assigned to profiles.

Changes are committed to revision history and applied atomically. Auto-rollback protects against lockouts.

## CLI

```sh
gk status                    # Health check
gk zone list                 # List zones
gk alias list                # List aliases
gk policy list               # List policies with rules
gk commit "add iot zone"     # Commit and apply config
gk rollback 3                # Rollback to revision 3
gk test --src 10.0.1.5 --dst 8.8.8.8 --proto tcp --port 443
gk explain --src 10.0.1.5 --dst 8.8.8.8
gk wg peers                  # List WireGuard peers
gk wg prune                  # Remove stale peers
gk service list              # List available services
gk leases                    # Show DHCP leases
gk audit                     # Show audit log
```

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `GK_MODE` | `direct` (SQLite) or `api` (REST) | `direct` |
| `GK_DB` | SQLite path (direct mode) | `/var/lib/gatekeeper/gatekeeper.db` |
| `GK_API_URL` | API base URL (auto-detects HTTP/HTTPS) | auto |
| `GK_API_KEY` | API key (api mode) | - |
| `GK_OUTPUT` | `json` or `table` | `json` |

## API

All endpoints under `/api/v1/` require the `X-API-Key` header or a valid web session cookie (except health checks). The API has 100+ endpoints. Key endpoints:

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/healthz` | Liveness probe |
| GET | `/api/v1/readyz` | Readiness probe (DB + firewall) |
| GET/POST | `/api/v1/zones` | List/create zones |
| GET/POST | `/api/v1/aliases` | List/create aliases |
| GET/POST | `/api/v1/policies` | List/create policies with rules |
| GET/POST | `/api/v1/profiles` | List/create profiles |
| POST | `/api/v1/assign` | Assign device to profile |
| POST | `/api/v1/config/commit` | Commit and apply config |
| POST | `/api/v1/config/rollback/{rev}` | Rollback to revision |
| GET | `/api/v1/wg/peers` | List WireGuard peers |
| GET | `/api/v1/diag/dry-run` | Preview compiled nftables |
| POST | `/api/v1/test` | Test packet path |
| GET | `/api/v1/services` | List available services |
| GET | `/api/v1/audit` | Audit log |
| GET | `/api/v1/metrics` | Prometheus-style metrics |

Full API documentation: see `api/openapi.yaml`.

## Daemon Flags

```
gatekeeperd [flags]

  --listen          API listen address (default :8080)
  --db              SQLite database path
  --api-key         API key for authentication (required unless --enable-rbac)
  --api-key-file    File containing API key (avoids ps exposure)
  --log-level       Log level: debug, info, warn, error (default info)
  --ruleset-dir     nftables ruleset output directory
  --dnsmasq-dir     dnsmasq config output directory
  --upstream-dns    Comma-separated upstream DNS servers
  --local-domain    Local DNS domain (default gk.local)
  --wg-interface    WireGuard interface name (enables VPN)
  --pxe-server      PXE server IP for dhcp-boot
  --tls-cert        TLS certificate file (enables HTTPS)
  --tls-key         TLS private key file
  --enable-mcp      Enable MCP server
  --enable-rbac     Enable role-based access control
```

## Directory Layout

```
/usr/local/bin/gatekeeperd     Daemon binary
/usr/local/bin/gk              CLI binary
/etc/gatekeeper/api.key        API key
/etc/gatekeeper/tls/           TLS certificate and key
/etc/gatekeeper/dnsmasq/       Generated dnsmasq config
/var/lib/gatekeeper/           SQLite DB, rulesets, plugins
/var/log/gatekeeper/           Daemon logs
/etc/init.d/gatekeeperd        OpenRC init script
```

## Building

```sh
make build     # Builds bin/gatekeeperd and bin/gk
make test      # Runs unit tests
```

Requires Go 1.22+.

## License

See LICENSE file.
