#!/bin/bash
# Build an LXC rootfs tarball for Proxmox.
# This creates a container template with Gatekeeper pre-installed,
# cloud-init support, and first-boot auto-provisioning.
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUTPUT="gatekeeper-${VERSION}.tar.zst"
ROOTFS=$(mktemp -d)

echo "Building LXC image ${OUTPUT}..."

# Build binaries.
bash scripts/build.sh

# Create rootfs directory structure.
mkdir -p "${ROOTFS}"/{usr/local/bin,var/lib/gatekeeper/rulesets,etc/gatekeeper/tls}
mkdir -p "${ROOTFS}"/{etc/gatekeeper/dnsmasq,etc/gatekeeper/wireguard}
mkdir -p "${ROOTFS}"/{etc/systemd/system,etc/sysctl.d,etc/dnsmasq.d}
mkdir -p "${ROOTFS}"/{var/cache/gatekeeper/dns,var/log/gatekeeper}
mkdir -p "${ROOTFS}"/etc/cloud/cloud.cfg.d

# Copy binaries.
cp bin/gatekeeperd "${ROOTFS}/usr/local/bin/"
cp bin/gk "${ROOTFS}/usr/local/bin/"

# Copy first-boot script.
cp scripts/first-boot.sh "${ROOTFS}/usr/local/bin/gatekeeper-first-boot.sh"
chmod +x "${ROOTFS}/usr/local/bin/gatekeeper-first-boot.sh"

# Copy cloud-init config (for platforms that support it).
cp scripts/cloud-init.yaml "${ROOTFS}/etc/cloud/cloud.cfg.d/99-gatekeeper.cfg"

# Copy install script for manual use.
cp scripts/install.sh "${ROOTFS}/opt/gatekeeper-install.sh"

# Write sysctl forwarding config.
cat > "${ROOTFS}/etc/sysctl.d/99-gatekeeper.conf" <<'EOF'
net.ipv4.ip_forward=1
net.core.netdev_max_backlog=4096
net.core.somaxconn=16384
net.ipv4.tcp_fastopen=3
EOF

# Create systemd service unit.
cat > "${ROOTFS}/etc/systemd/system/gatekeeperd.service" <<'EOF'
[Unit]
Description=Gatekeeper Firewall Daemon
After=network.target

[Service]
Type=simple
EnvironmentFile=-/etc/gatekeeper/gatekeeperd.env
ExecStart=/usr/local/bin/gatekeeperd \
    --listen=:8080 \
    --db=/var/lib/gatekeeper/gatekeeper.db \
    --api-key-file=/var/lib/gatekeeper/api.key \
    --ruleset-dir=/var/lib/gatekeeper/rulesets
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Create OpenRC init script for Alpine.
mkdir -p "${ROOTFS}/etc/init.d"
cat > "${ROOTFS}/etc/init.d/gatekeeperd" <<'EOF'
#!/sbin/openrc-run
description="Gatekeeper Firewall Daemon"
command="/usr/local/bin/gatekeeperd"
command_args="--listen=:8080 --db=/var/lib/gatekeeper/gatekeeper.db --api-key-file=/var/lib/gatekeeper/api.key --ruleset-dir=/var/lib/gatekeeper/rulesets"
command_background=true
pidfile="/run/gatekeeper/gatekeeperd.pid"
start_stop_daemon_args="--make-pidfile"
depend() {
    need net
    after firewall
}
EOF
chmod +x "${ROOTFS}/etc/init.d/gatekeeperd"

# Package as tarball.
tar -cf - -C "${ROOTFS}" . | zstd -19 -o "${OUTPUT}"

# Cleanup.
rm -rf "${ROOTFS}"

echo "LXC image built: ${OUTPUT}"
ls -lh "${OUTPUT}"
echo ""
echo "Deploy on Proxmox:"
echo "  pct create 200 local:vztmpl/${OUTPUT} \\"
echo "    --net0 name=eth0,bridge=vmbr0,ip=dhcp \\"
echo "    --net1 name=eth1,bridge=vmbr1,ip=192.168.1.1/24 \\"
echo "    --features nesting=1 \\"
echo "    --unprivileged 0"
echo ""
echo "Then start and run first-boot:"
echo "  pct start 200"
echo "  pct exec 200 -- /usr/local/bin/gatekeeper-first-boot.sh"
