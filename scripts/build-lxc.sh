#!/bin/bash
# Build an LXC rootfs tarball for Proxmox.
set -euo pipefail

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
OUTPUT="gatekeeper-${VERSION}.tar.zst"
ROOTFS=$(mktemp -d)

echo "Building LXC image ${OUTPUT}..."

# Build binaries.
bash scripts/build.sh

# Create minimal rootfs structure.
mkdir -p "${ROOTFS}"/{usr/local/bin,var/lib/gatekeeper,etc/gatekeeper,etc/systemd/system}

# Copy binaries.
cp bin/gatekeeperd "${ROOTFS}/usr/local/bin/"
cp bin/gk "${ROOTFS}/usr/local/bin/"

# Copy install script.
cp scripts/install.sh "${ROOTFS}/opt/gatekeeper-install.sh"

# Create systemd service.
cat > "${ROOTFS}/etc/systemd/system/gatekeeperd.service" <<'EOF'
[Unit]
Description=Gatekeeper Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gatekeeperd --listen=:8080 --db=/var/lib/gatekeeper/gatekeeper.db --ruleset-dir=/var/lib/gatekeeper/rulesets
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Create first-boot script.
cat > "${ROOTFS}/etc/gatekeeper/first-boot.sh" <<'SCRIPT'
#!/bin/bash
# First-boot configuration.
set -e
if [ ! -f /etc/gatekeeper/api.key ]; then
    head -c 32 /dev/urandom | base64 | tr -d '=' > /etc/gatekeeper/api.key
    chmod 600 /etc/gatekeeper/api.key
fi
echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
sysctl -w net.ipv4.ip_forward=1
systemctl enable gatekeeperd
systemctl start gatekeeperd
SCRIPT
chmod +x "${ROOTFS}/etc/gatekeeper/first-boot.sh"

# Package as tarball.
tar -cf - -C "${ROOTFS}" . | zstd -19 -o "${OUTPUT}"

# Cleanup.
rm -rf "${ROOTFS}"

echo "LXC image built: ${OUTPUT}"
ls -lh "${OUTPUT}"
echo ""
echo "Deploy on Proxmox:"
echo "  pct create 200 local:vztmpl/${OUTPUT} --net0 name=eth0,bridge=vmbr0 --net1 name=eth1,bridge=vmbr1"
