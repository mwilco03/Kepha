#!/bin/bash
# Gatekeeper first-boot setup script.
# Run once on initial deployment to generate API key, TLS cert, and seed config.
set -euo pipefail

GATEKEEPER_DIR="/var/lib/gatekeeper"
CERT_DIR="/etc/gatekeeper/tls"
ENV_FILE="/etc/gatekeeper/gatekeeperd.env"

echo "=== Gatekeeper First Boot Setup ==="

# Create directories.
mkdir -p "$GATEKEEPER_DIR/rulesets" "$CERT_DIR" /etc/gatekeeper /etc/dnsmasq.d

# Generate API key if not exists.
API_KEY_FILE="$GATEKEEPER_DIR/api.key"
if [ ! -f "$API_KEY_FILE" ]; then
    API_KEY=$(head -c 32 /dev/urandom | base64 | tr -d '/+=' | head -c 32)
    echo "$API_KEY" > "$API_KEY_FILE"
    chmod 600 "$API_KEY_FILE"
    echo "Generated API key: $API_KEY"
    echo "Save this key — it is required for API access."
else
    echo "API key already exists at $API_KEY_FILE"
fi

# Generate self-signed TLS certificate if not exists.
if [ ! -f "$CERT_DIR/server.crt" ]; then
    HOSTNAME=$(hostname -f 2>/dev/null || hostname)
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
        -keyout "$CERT_DIR/server.key" \
        -out "$CERT_DIR/server.crt" \
        -days 3650 -nodes \
        -subj "/CN=$HOSTNAME/O=Gatekeeper" \
        -addext "subjectAltName=DNS:$HOSTNAME,DNS:localhost,IP:127.0.0.1" \
        2>/dev/null
    chmod 600 "$CERT_DIR/server.key"
    echo "Generated self-signed TLS certificate for $HOSTNAME"
else
    echo "TLS certificate already exists at $CERT_DIR/server.crt"
fi

# Write environment file for systemd.
if [ ! -f "$ENV_FILE" ]; then
    cat > "$ENV_FILE" <<ENVEOF
# Gatekeeper daemon environment.
# Uncomment to enable TLS:
# GATEKEEPER_TLS_CERT=$CERT_DIR/server.crt
# GATEKEEPER_TLS_KEY=$CERT_DIR/server.key
ENVEOF
    chmod 600 "$ENV_FILE"
    echo "Environment file created at $ENV_FILE"
fi

# Enable and start the service.
if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
    systemctl enable gatekeeperd
    systemctl start gatekeeperd
    echo "gatekeeperd service enabled and started."
else
    echo "systemd not available — start gatekeeperd manually."
fi

echo ""
echo "=== First Boot Complete ==="
echo "API URL: https://$(hostname):8080"
echo "API Key: $(cat "$API_KEY_FILE")"
