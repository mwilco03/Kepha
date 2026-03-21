# Gatekeeper Admin Guide

## Authentication

Authentication is **mandatory**. The daemon refuses to start without credentials.

### API Key Authentication (default)
```bash
# Generated automatically by install-alpine.sh at:
cat /etc/gatekeeper/api.key

# Use in API requests:
curl -H "X-API-Key: $(cat /etc/gatekeeper/api.key)" https://localhost:8080/api/v1/zones

# Web UI: enter the API key at the login page
```

### RBAC (multi-user)
```bash
gatekeeperd --enable-rbac
# Create keys via API: POST /api/v1/keys
```

## Common Operations

### Add a new zone
```bash
gk zone create --name iot --interface eth2 --cidr 10.20.0.0/24 --trust low
gk commit "add iot zone"
```

### Assign a device
```bash
gk assign 10.10.0.50 --profile desktop --hostname workstation1
gk commit "assign workstation"
```

### Test a packet path
```bash
gk test --src 10.10.0.50 --dst 8.8.8.8 --proto tcp --port 443
gk explain --src 10.10.0.50 --dst 8.8.8.8
```

### Rollback a bad change
```bash
gk diff           # see current vs previous
gk rollback 5     # rollback to revision 5
```

The daemon has a 60-second auto-rollback timer on config commits. If you don't call `gk confirm` within 60 seconds, the change is automatically reverted.

### WireGuard VPN
```bash
gk wg add-peer --name "phone" --allowed-ips 10.50.0.2/32
gk wg peers      # list peers
gk wg prune       # remove stale peers (no handshake in 24h)
```

### Service Management
```bash
gk service list          # available services
gk service enable dns-filter
gk service configure dns-filter '{"blocklists":["ads","malware"]}'
gk service disable dns-filter
```

## Backup & Restore

```bash
# Export full config
gk export > gatekeeper-backup.json

# Restore
gk import < gatekeeper-backup.json
gk commit "restore from backup"
```

### Database backup
```bash
cp /var/lib/gatekeeper/gatekeeper.db /var/lib/gatekeeper/gatekeeper.db.bak
```

## Troubleshooting

### Daemon won't start
```bash
# Check log
cat /var/log/gatekeeper/gatekeeperd.log

# Common causes:
# - Missing API key: generate with install-alpine.sh or provide --api-key
# - Port in use: ss -tlnp | grep 8080
# - Database locked: check for stale processes
```

### Locked out by firewall rules
The auto-rollback timer (60s) should revert. If not:
```bash
# Emergency: flush all gatekeeper rules
nft flush table inet gatekeeper

# Restart daemon to re-apply last known good config
rc-service gatekeeperd restart
```

### Web UI blank/broken
Check that htmx.min.js is loaded (vendored in /static/). If CSP errors appear in browser console, the security headers may need adjustment.

## Log Rotation

Logs at `/var/log/gatekeeper/gatekeeperd.log` are rotated daily (14-day retention, 50MB max) via the installed logrotate config.

## Maintenance

Daily SQLite maintenance runs automatically:
- WAL checkpoint (reclaims disk)
- Revision pruning (keeps last 100)
- Audit log trimming (keeps last 10,000 entries)
