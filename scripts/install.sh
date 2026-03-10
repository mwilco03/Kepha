#!/bin/bash
# Gatekeeper installation script for Debian/Ubuntu LXC containers.
set -euo pipefail

INSTALL_DIR="/opt/gatekeeper"
DATA_DIR="/var/lib/gatekeeper"
CONF_DIR="/etc/gatekeeper"
BIN_DIR="/usr/local/bin"

echo "Installing Gatekeeper..."

# Check root.
if [ "$(id -u)" -ne 0 ]; then
    echo "Error: must run as root" >&2
    exit 1
fi

# Install system dependencies.
echo "Installing system packages..."
apt-get update -qq
apt-get install -y -qq nftables dnsmasq wireguard-tools sqlite3 avahi-daemon samba miniupnpd chrony curl >/dev/null

# Stop dnsmasq default instance (we manage our own config).
systemctl stop dnsmasq 2>/dev/null || true
systemctl disable dnsmasq 2>/dev/null || true

# Create directories.
mkdir -p "${INSTALL_DIR}" "${DATA_DIR}" "${DATA_DIR}/rulesets" "${DATA_DIR}/qos" "${DATA_DIR}/captive-portal" "${CONF_DIR}" "${CONF_DIR}/dnsmasq" "${CONF_DIR}/wireguard"
mkdir -p /var/cache/gatekeeper/dns /var/log/gatekeeper /srv/samba/share

# Copy binaries.
if [ -f bin/gatekeeperd ]; then
    cp bin/gatekeeperd "${BIN_DIR}/gatekeeperd"
    cp bin/gk "${BIN_DIR}/gk"
    chmod +x "${BIN_DIR}/gatekeeperd" "${BIN_DIR}/gk"
elif [ -f "${INSTALL_DIR}/gatekeeperd" ]; then
    echo "Binaries already installed."
else
    echo "Error: no binaries found. Run 'make build' first." >&2
    exit 1
fi

# Generate API key if not exists.
if [ ! -f "${CONF_DIR}/api.key" ]; then
    head -c 32 /dev/urandom | base64 | tr -d '=' > "${CONF_DIR}/api.key"
    chmod 600 "${CONF_DIR}/api.key"
    echo "API key generated: ${CONF_DIR}/api.key"
fi

# Install systemd service.
cat > /etc/systemd/system/gatekeeperd.service <<'EOF'
[Unit]
Description=Gatekeeper Firewall Daemon
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/gatekeeperd \
    --listen=:8080 \
    --db=/var/lib/gatekeeper/gatekeeper.db \
    --api-key-file=/etc/gatekeeper/api.key \
    --ruleset-dir=/var/lib/gatekeeper/rulesets
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable gatekeeperd

# Enable IP forwarding.
if ! grep -q "net.ipv4.ip_forward=1" /etc/sysctl.conf 2>/dev/null; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    sysctl -w net.ipv4.ip_forward=1 >/dev/null
fi

echo ""
echo "Gatekeeper installed successfully."
echo ""
echo "  Start:    systemctl start gatekeeperd"
echo "  Status:   systemctl status gatekeeperd"
echo "  API key:  cat ${CONF_DIR}/api.key"
echo "  CLI:      gk status"
echo "  Web UI:   http://localhost:8080"
echo ""
