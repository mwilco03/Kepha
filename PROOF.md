# Gatekeeper Proof of Functionality

**Date:** 2026-03-22
**Build:** 250 commits on main
**Test environment:** 3-container Proxmox topology (CT 150/151/152)

---

## Build

```
CGO_ENABLED=0 go build -o bin/gatekeeperd ./cmd/gatekeeperd  ✅
CGO_ENABLED=0 go build -o bin/gk ./cmd/gk                    ✅
```

Both binaries compile clean with zero CGO dependencies.

---

## Live Topology Test (scripts/test-topology.sh)

Three Alpine LXC containers on isolated bridges:

```
[outside:172.16.0.2] ── vmbr1 (WAN) ── [gatekeeper eth0:172.16.0.1]
                                       [gatekeeper eth1:10.10.0.1] ── vmbr2 (LAN) ── [inside:10.10.0.2]
```

### Connectivity (6/6 PASS)

| Test | Result | Evidence |
|------|--------|----------|
| inside → gatekeeper LAN | PASS | 3/3 packets, TTL=64 |
| outside → gatekeeper WAN | PASS | 3/3 packets, TTL=64 |
| gatekeeper → outside | PASS | 3/3 packets |
| gatekeeper → inside | PASS | 3/3 packets |
| inside → outside (routed) | PASS | 3/3 packets, TTL=63 (decremented = forwarded) |
| outside → inside (blocked) | PASS | 0/2 packets, 100% loss (deny-all policy) |

### Nmap Scans from WAN (6/6 PASS)

| Scan | Result |
|------|--------|
| Xmas (-sX FIN+PSH+URG) | All 1026 ports: silent drop |
| SYN (-sS) | Only 8080 open, rest filtered |
| NULL (-sN) | All silent drop |
| FIN (-sF) | All silent drop |
| ACK (-sA) | 8080 unfiltered, rest filtered |
| TLS ciphers | Grade A — TLS 1.2+1.3, ECDHE+AES-GCM+ChaCha20 only |

### API Functional Tests (18/18 PASS)

| Operation | Result |
|-----------|--------|
| Zone CRUD (create/read/delete) | PASS |
| Alias CRUD + member add/remove | PASS |
| Policy CRUD + rule add/delete | PASS |
| Service enable/disable (NTP) | PASS |
| Config commit/confirm/rollback | PASS |
| Config export (5 sections) | PASS |
| Audit log captures mutations | PASS |
| Duplicate zone → 409 Conflict | PASS |
| Invalid CIDR → 400 Bad Request | PASS |
| Empty name → 400 Bad Request | PASS |
| 25 services registered | PASS |

### Security Tests (7/7 PASS)

| Test | Result |
|------|--------|
| API without auth → 401 | PASS |
| API with bad key → 401 | PASS |
| /debug/pprof → login redirect | PASS |
| /metrics without auth → 401 | PASS (fixed this session) |
| Security headers (CSP/HSTS/XFO/XCTO/RP) | PASS |
| TLS cipher grade A | PASS |
| No weak ciphers | PASS |

### Network Tests (8/8 PASS)

| Test | Result |
|------|--------|
| IP forwarding = 1 | PASS |
| ICMP types 0,3,8,11 only | PASS |
| NAT masquerade on WAN | PASS |
| Interface MTUs = 1500 | PASS |
| Routing table correct | PASS |
| Dnsmasq config valid | PASS |
| DNS/DHCP filtered from WAN | PASS |
| DNS open from LAN (port 53) | PASS |

### Path Test / Explain API

```
LAN → WAN tcp/443: action=allow   (via lan-outbound policy)
WAN → LAN tcp/22:  action=drop    (no zone for source)
```

### Config Rollback

Rollback restores zones, policies, profiles with correct ID remapping.
Forward chain rules regenerated. Routing verified working post-rollback.

---

## nftables Ruleset (verified on live system)

```
table inet gatekeeper {
    set bogons { 0.0.0.0/8, 10.0.0.0/8, 100.64.0.0/10, 127.0.0.0/8,
                 169.254.0.0/16, 172.16.0.0/12, 192.0.0.0/24, 192.0.2.0/24,
                 192.168.0.0/16, 198.18.0.0/15, 198.51.100.0/24,
                 203.0.113.0/24, 224.0.0.0/4, 240.0.0.0/4 }

    chain input    { policy drop;  ct state est/rel accept; ICMP 0,3,8,11; tcp 8080; LAN dns/dhcp }
    chain forward  { policy drop;  ct state est/rel accept; bogon drop on WAN; LAN→WAN allow }
    chain output   { policy accept }
    chain postrouting { masquerade on WAN oifname }
}
```

---

## Security Checklist

| Category | Status | Detail |
|----------|--------|--------|
| Input validation | ✅ | CIDR, zone names, DNS labels, interface names validated |
| Authentication | ✅ | Mandatory --api-key or --enable-rbac; refuses to start without |
| Injection protection | ✅ | No shell-outs for controlled ops; netlink API; parameterized SQL |
| Secrets management | ✅ | --api-key-file (not ps-visible); SHA-256 cache keys |
| Output escaping | ✅ | DOM construction (no innerHTML); CSP; X-Frame-Options DENY |
| Error handling | ✅ | Sentinel errors; no stack traces to clients; audit log |
| Rate limiting | ✅ | Per-endpoint rate limiters; login rate limiting |
| TLS | ✅ | Self-signed EC P-256; TLS 1.2+1.3; Grade A ciphers |
| HSTS | ✅ | max-age=31536000; includeSubDomains |
| Audit logging | ✅ | All mutations logged with actor, timestamp, resource |
| Safe apply | ✅ | 60s auto-rollback on commit; manual confirm required |

---

## Unit Test Status — 16/16 PASS

```
ok   internal/api       9.789s
ok   internal/backend   0.016s
ok   internal/cli       0.059s
ok   internal/compiler  0.010s
ok   internal/config    12.742s
ok   internal/driver    1.912s
ok   internal/ha        0.006s
ok   internal/inspect   0.016s
ok   internal/ipv6      0.021s
ok   internal/mcp       0.022s
ok   internal/ops       16.160s
ok   internal/plugin    0.019s
ok   internal/rbac      15.309s
ok   internal/service   1.585s
ok   internal/web       5.988s
ok   internal/xdp       0.009s
```

All 16 packages pass. Zero failures.

---

## Known Gaps

1. **Lint**: Cannot run inside isolated test container (no internet for golangci-lint download).
   Runs clean on CT 107 (production container with internet).
2. **IPv6**: Compiler TODO — IPv4 only for v1.
3. **HA**: Stubs acknowledged in PLAN.md — not production-ready.
4. **XDP**: Experimental stub — control plane only, no BPF programs attached.

---

## Bugs Found & Fixed This Session

| Bug | Fix | Commit |
|-----|-----|--------|
| `gk ping` shelled out to `/bin/ping` | Native ICMP via backend.Ping() | 3e1afd3 |
| `getClockTicks()` shelled out to `getconf` | Constant 100 (Linux USER_HZ guarantee) | 3e1afd3 |
| Rollback broke zone_id foreign keys | Remap by name during Import() | 3e1afd3 |
| `/api/v1/metrics` exposed without auth | Removed from auth exemption list | 3774015 |
