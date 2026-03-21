# Gatekeeper Deployment Plan

**Date:** 2026-03-21
**Target:** Alpine Linux LXC container on Proxmox VE
**Status:** All Critical items RESOLVED. Proceeding with HIGH items.

---

## Container Environment

- **CT 107** — Build/test container. Alpine 3.22, Go 1.24.13, 3.2G free, nftables installed.
- **CT 112** — Validation container. Has 2 NICs (vmbr0 + vmbr1) for multi-interface smoke tests.
- **Deployment IP:** 192.168.7.131:8080 (CT 107, confirmed working)

CT 107 is NOT corrupted. Reuse it for builds.

---

## Pre-Deployment: Code Fixes (CRITICAL — DONE)

| Commit | Fix | Status |
|--------|-----|--------|
| `697325d` | C4: Mandatory auth — refuse to start without `--api-key` or `--enable-rbac` | DONE |
| `a7611b1` | C1: NftablesBackend per-rule forwarding — `compileRuleExprs()` | DONE |
| `29b63ab` | C3: Vendor htmx+qrcode.js, fix CSP | DONE |
| `a9ad17f` | C2: Multi-WAN recovery counter — dedicated `wan*Recovery` counters | DONE |
| `2f34460` | C5: mergedThreats `atomic.Value` — fix data race | DONE |

## HIGH Priority (in progress)

| Fix | Description | Owner |
|-----|-------------|-------|
| H1 | MCP server auth — route through API middleware | erudite-ukulele |
| H2 | XSS in WireGuard innerHTML | erudite-ukulele |
| H3 | htmx-to-API auth mismatch | erudite-ukulele |
| H5 | Anti-spoof rules on WAN | manager |
| H6 | ICMP restrict to types 0,3,8,11 | manager |
| H14 | API port hardcoded 8080 | DONE (erudite `8e894ea`) |

---

## Build-Test Loop

```bash
# 1. Edit on host (/root/kepha)
# 2. Push to CT 107
tar czf /tmp/kepha-src.tar.gz --exclude='.git' --exclude='bin' -C /root/kepha .
pct push 107 /tmp/kepha-src.tar.gz /tmp/kepha-src.tar.gz
pct exec 107 -- sh -c 'cd /root/kepha && tar xzf /tmp/kepha-src.tar.gz && rm /tmp/kepha-src.tar.gz'

# 3. Build
pct exec 107 -- sh -c 'cd /root/kepha && make build 2>&1'

# 4. Test
pct exec 107 -- sh -c 'cd /root/kepha && make test 2>&1'

# 5. Commit + push
git add <files> && git commit -m "..." && git push origin main
```

## Deployment Sequence

```bash
# Install runtime deps (not build deps)
pct exec <VMID> -- apk add --no-cache nftables dnsmasq iproute2 openssl wireguard-tools bash

# Run install script
pct exec <VMID> -- sh -c 'cd /root/kepha && sh scripts/install-alpine.sh'

# Start service
pct exec <VMID> -- rc-service gatekeeperd start

# Get API key
pct pull <VMID> /etc/gatekeeper/api.key /tmp/gk-api.key && cat /tmp/gk-api.key
```

## Post-Deployment Validation

1. `curl -sfk https://127.0.0.1:8080/api/v1/healthz` — expect `{"status":"ok"}`
2. `curl -sf -H "X-API-Key: <key>" https://127.0.0.1:8080/api/v1/zones` — expect wan+lan
3. `nft list table inet gatekeeper` — verify input/forward/postrouting chains
4. `dnsmasq --test` — config validates
5. Web UI at `https://<ip>:8080` — login page renders, scripts load
6. `gk status` — daemon health check

## Rollback Plan

1. **Daemon won't start:** Check `/var/log/gatekeeper/gatekeeperd.log`. Missing API key is most common cause.
2. **Firewall lockout:** Auto-rollback timer (60s) reverts. Manual: `nft flush table inet gatekeeper`.
3. **Binary rollback:** `cp /usr/local/bin/gatekeeperd.bak /usr/local/bin/gatekeeperd && rc-service gatekeeperd restart`
4. **Database backup:** `cp /var/lib/gatekeeper/gatekeeper.db /var/lib/gatekeeper/gatekeeper.db.bak` before each deploy.

## Smoke Test Note

After C4 fix, `scripts/smoke-test.sh` needs updating to pass `--api-key` flag. The daemon now refuses to start without auth.
