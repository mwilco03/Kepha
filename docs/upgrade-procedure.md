# Gatekeeper Upgrade Procedure

## Current: Rolling Restart (Brief Downtime)

The daemon currently requires a restart to upgrade. Typical downtime is
under 5 seconds — nftables rules persist in the kernel across daemon
restarts, so traffic forwarding continues uninterrupted.

```sh
# 1. Build new binary
make build

# 2. Copy to install path
cp bin/gatekeeperd /usr/local/bin/gatekeeperd

# 3. Restart the daemon (nftables rules persist in kernel)
rc-service gatekeeperd restart   # Alpine OpenRC
# or: systemctl restart gatekeeperd  # systemd
```

**Traffic impact**: None. The nftables ruleset lives in the kernel and
is not affected by daemon restarts. Only API/web UI access is briefly
unavailable during the restart window.

## Future: Socket Activation (Zero Downtime)

For true zero-downtime upgrades, the daemon could support systemd socket
activation or a file-descriptor handoff protocol:

1. **systemd socket activation**: systemd holds the listen socket. The new
   daemon receives it via `LISTEN_FDS`. No connection is dropped.
   Requires adding `sd_listen_fds()` support to the Go HTTP server.

2. **Graceful restart (tableflip)**: The `cloudflare/tableflip` library
   implements file-descriptor passing between old and new processes.
   The old process passes its listen socket to the new one, then drains
   in-flight requests before exiting.

3. **Blue-green with load balancer**: Run two instances behind a reverse
   proxy (nginx/haproxy). Upgrade one at a time.

### Implementation Notes

For option 2 (recommended for LXC deployments without systemd):

```go
import "github.com/cloudflare/tableflip"

upg, _ := tableflip.New(tableflip.Options{})
defer upg.Stop()

ln, _ := upg.Listen("tcp", *listen)
go srv.Serve(ln)

if err := upg.Ready(); err != nil { ... }
<-upg.Exit()
```

This is tracked as a future enhancement. The current restart approach
is acceptable for appliance deployments where sub-5-second API downtime
during upgrades is tolerable.
