#!/bin/sh
# scripts/test-topology.sh — Three-container routing test on Proxmox.
#
# Topology:
#   [outside:172.16.0.2] ── vmbr1 (WAN) ── [gatekeeper eth0:172.16.0.1]
#                                          [gatekeeper eth1:10.10.0.1] ── vmbr2 (LAN) ── [inside:10.10.0.2]
#
# Usage:
#   scripts/test-topology.sh up      — build bridges, create containers, install, test
#   scripts/test-topology.sh down    — destroy everything
#   scripts/test-topology.sh test    — run connectivity tests only (containers must exist)
#   scripts/test-topology.sh status  — show container and bridge state
#
# All containers are privileged Alpine LXC. Gatekeeper is built from source
# and installed with the standard install-alpine.sh script.

set -eu

# ---------------------------------------------------------------------------
# Configuration (override via environment)
# ---------------------------------------------------------------------------
TEMPLATE="${TEMPLATE:-local:vztmpl/alpine-3.23-default_20260116_amd64.tar.xz}"
CT_GW="${CT_GW:-150}"
CT_OUT="${CT_OUT:-151}"
CT_IN="${CT_IN:-152}"
BR_WAN="${BR_WAN:-vmbr1}"
BR_LAN="${BR_LAN:-vmbr2}"
WAN_GW="172.16.0.1"
WAN_OUT="172.16.0.2"
WAN_CIDR="24"
LAN_GW="10.10.0.1"
LAN_IN="10.10.0.2"
LAN_CIDR="24"
STORAGE="${STORAGE:-local-lvm}"
SRC_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
info()  { printf '\033[1;34m=> %s\033[0m\n' "$*"; }
ok()    { printf '\033[1;32m   PASS: %s\033[0m\n' "$*"; }
fail()  { printf '\033[1;31m   FAIL: %s\033[0m\n' "$*"; }
die()   { printf '\033[1;31mERROR: %s\033[0m\n' "$*" >&2; exit 1; }

wait_boot() {
    # Wait for container networking to come up.
    local ct="$1" max=30 i=0
    while [ "$i" -lt "$max" ]; do
        if pct exec "$ct" -- true 2>/dev/null; then return 0; fi
        sleep 1; i=$((i + 1))
    done
    die "CT $ct did not start within ${max}s"
}

ct_exists() { pct status "$1" >/dev/null 2>&1; }

# ---------------------------------------------------------------------------
# cmd: up — create bridges, containers, install gatekeeper, run tests
# ---------------------------------------------------------------------------
cmd_up() {
    # ---- Bridges ----
    info "Ensuring bridge ${BR_WAN}"
    if ! ip link show "$BR_WAN" >/dev/null 2>&1; then
        ip link add name "$BR_WAN" type bridge
        ip link set "$BR_WAN" up
        info "Created $BR_WAN"
    fi

    info "Ensuring bridge ${BR_LAN}"
    if ! ip link show "$BR_LAN" >/dev/null 2>&1; then
        cat >> /etc/network/interfaces.d/gk-test <<EOF

auto ${BR_LAN}
iface ${BR_LAN} inet manual
	bridge-ports none
	bridge-stp off
	bridge-fd 0
	# Gatekeeper test LAN bridge — no physical uplink
EOF
        ip link add name "$BR_LAN" type bridge
        ip link set "$BR_LAN" up
        info "Created $BR_LAN (persisted to /etc/network/interfaces.d/gk-test)"
    fi

    # ---- Containers ----
    # Strategy: gatekeeper starts with a temporary vmbr0 NIC for internet
    # access during install (apk add + go build). After install, we stop it,
    # reconfigure to the isolated WAN/LAN topology, and restart.

    info "Creating gatekeeper CT ${CT_GW} (with temporary internet NIC)"
    if ct_exists "$CT_GW"; then
        pct stop "$CT_GW" 2>/dev/null || true
        pct destroy "$CT_GW" --force 2>/dev/null || true
    fi
    pct create "$CT_GW" "$TEMPLATE" \
        --hostname gk-test \
        --cores 2 --memory 2560 --swap 0 \
        --storage "$STORAGE" --rootfs "${STORAGE}:4" \
        --net0 "name=eth0,bridge=vmbr0,ip=dhcp,type=veth" \
        --unprivileged 0 --features nesting=1 --start 0

    info "Creating outside CT ${CT_OUT}"
    if ct_exists "$CT_OUT"; then
        pct stop "$CT_OUT" 2>/dev/null || true
        pct destroy "$CT_OUT" --force 2>/dev/null || true
    fi
    pct create "$CT_OUT" "$TEMPLATE" \
        --hostname outside \
        --cores 1 --memory 64 --swap 0 \
        --storage "$STORAGE" --rootfs "${STORAGE}:1" \
        --net0 "name=eth0,bridge=${BR_WAN},ip=${WAN_OUT}/${WAN_CIDR},gw=${WAN_GW},type=veth" \
        --unprivileged 0 --start 0

    info "Creating inside CT ${CT_IN}"
    if ct_exists "$CT_IN"; then
        pct stop "$CT_IN" 2>/dev/null || true
        pct destroy "$CT_IN" --force 2>/dev/null || true
    fi
    pct create "$CT_IN" "$TEMPLATE" \
        --hostname inside \
        --cores 1 --memory 64 --swap 0 \
        --storage "$STORAGE" --rootfs "${STORAGE}:1" \
        --net0 "name=eth0,bridge=${BR_LAN},ip=${LAN_IN}/${LAN_CIDR},gw=${LAN_GW},type=veth" \
        --unprivileged 0 --start 0

    # ---- Phase 1: Install gatekeeper with internet access ----
    info "Starting gatekeeper CT with internet access for install"
    pct start "$CT_GW"
    wait_boot "$CT_GW"

    info "Pushing source to gatekeeper CT ${CT_GW}"
    tar czf /tmp/gk-src.tar.gz --exclude='.git' --exclude='bin' -C "$SRC_DIR" .
    pct push "$CT_GW" /tmp/gk-src.tar.gz /root/gk-src.tar.gz
    rm -f /tmp/gk-src.tar.gz

    info "Installing gatekeeper (this builds from source — may take a few minutes)"
    pct exec "$CT_GW" -- sh -c '
        mkdir -p /root/gatekeeper && cd /root/gatekeeper
        tar xzf /root/gk-src.tar.gz
        sh scripts/install-alpine.sh
    '

    # ---- Phase 2: Reconfigure to isolated WAN/LAN topology ----
    info "Stopping gatekeeper CT to reconfigure network"
    pct stop "$CT_GW"

    info "Reconfiguring gatekeeper: eth0=WAN (${BR_WAN}), eth1=LAN (${BR_LAN})"
    pct set "$CT_GW" \
        --net0 "name=eth0,bridge=${BR_WAN},ip=${WAN_GW}/${WAN_CIDR},type=veth" \
        --net1 "name=eth1,bridge=${BR_LAN},ip=${LAN_GW}/${LAN_CIDR},type=veth"

    # ---- Phase 3: Start all three on isolated topology ----
    info "Starting all containers on isolated topology"
    pct start "$CT_GW"
    pct start "$CT_OUT"
    pct start "$CT_IN"
    wait_boot "$CT_GW"
    wait_boot "$CT_OUT"
    wait_boot "$CT_IN"

    # Ensure ip_forward is on (install script sets it, but verify after reboot).
    pct exec "$CT_GW" -- sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1 || true

    info "Starting gatekeeperd"
    pct exec "$CT_GW" -- rc-service gatekeeperd start

    # Wait for API to come up.
    info "Waiting for gatekeeper API"
    i=0
    while [ "$i" -lt 30 ]; do
        if pct exec "$CT_GW" -- wget -qO- --no-check-certificate \
            https://127.0.0.1:8080/api/v1/healthz 2>/dev/null | grep -q '"ok"'; then
            break
        fi
        sleep 1; i=$((i + 1))
    done
    if [ "$i" -ge 30 ]; then
        die "Gatekeeper API did not respond within 30s"
    fi
    ok "Gatekeeper API is up"

    # ---- Apply firewall and commit ----
    info "Committing initial config (triggers nftables apply)"
    api_key=$(pct exec "$CT_GW" -- cat /etc/gatekeeper/api.key)
    pct exec "$CT_GW" -- wget -qO- --no-check-certificate \
        --header="X-API-Key: ${api_key}" \
        --post-data='{"message":"initial test commit"}' \
        --header="Content-Type: application/json" \
        "https://127.0.0.1:8080/api/v1/config/commit" || true

    # Confirm the commit so rules persist (60s auto-rollback otherwise).
    sleep 2
    pct exec "$CT_GW" -- wget -qO- --no-check-certificate \
        --header="X-API-Key: ${api_key}" \
        --post-data='{}' \
        --header="Content-Type: application/json" \
        "https://127.0.0.1:8080/api/v1/config/confirm" || true

    info "Gatekeeper deployed — running connectivity tests"
    echo ""
    cmd_test
}

# ---------------------------------------------------------------------------
# cmd: test — run connectivity checks
# ---------------------------------------------------------------------------
cmd_test() {
    local pass=0 total=0

    run_test() {
        total=$((total + 1))
        local desc="$1"; shift
        if "$@"; then
            ok "$desc"; pass=$((pass + 1))
        else
            fail "$desc"
        fi
    }

    info "[1/6] inside → gatekeeper LAN (10.10.0.1)"
    run_test "inside pings gatekeeper LAN interface" \
        pct exec "$CT_IN" -- ping -c 3 -W 2 "$LAN_GW"

    info "[2/6] outside → gatekeeper WAN (172.16.0.1)"
    run_test "outside pings gatekeeper WAN interface" \
        pct exec "$CT_OUT" -- ping -c 3 -W 2 "$WAN_GW"

    info "[3/6] gatekeeper → outside (172.16.0.2)"
    run_test "gatekeeper pings outside" \
        pct exec "$CT_GW" -- ping -c 3 -W 2 "$WAN_OUT"

    info "[4/6] gatekeeper → inside (10.10.0.2)"
    run_test "gatekeeper pings inside" \
        pct exec "$CT_GW" -- ping -c 3 -W 2 "$LAN_IN"

    info "[5/6] inside → outside through gatekeeper (NAT/forward)"
    run_test "inside pings outside (routed through gatekeeper)" \
        pct exec "$CT_IN" -- ping -c 3 -W 2 "$WAN_OUT"

    info "[6/6] nftables rules loaded on gatekeeper"
    run_test "nftables gatekeeper table exists" \
        pct exec "$CT_GW" -- nft list table inet gatekeeper

    echo ""
    echo "======================================"
    if [ "$pass" -eq "$total" ]; then
        ok "All ${total}/${total} tests passed"
    else
        fail "${pass}/${total} tests passed"
    fi
    echo "======================================"
    [ "$pass" -eq "$total" ]
}

# ---------------------------------------------------------------------------
# cmd: status — show state
# ---------------------------------------------------------------------------
cmd_status() {
    info "Bridges"
    for br in "$BR_WAN" "$BR_LAN"; do
        if ip link show "$br" >/dev/null 2>&1; then
            printf "  %-10s UP\n" "$br"
        else
            printf "  %-10s MISSING\n" "$br"
        fi
    done

    echo ""
    info "Containers"
    for ct in "$CT_GW" "$CT_OUT" "$CT_IN"; do
        if ct_exists "$ct"; then
            printf "  CT %-6s %s\n" "$ct" "$(pct status "$ct" | awk '{print $2}')"
        else
            printf "  CT %-6s NOT FOUND\n" "$ct"
        fi
    done

    # If gatekeeper is running, show API health.
    if pct status "$CT_GW" 2>/dev/null | grep -q running; then
        echo ""
        info "Gatekeeper health"
        pct exec "$CT_GW" -- wget -qO- --no-check-certificate \
            https://127.0.0.1:8080/api/v1/healthz 2>/dev/null || echo "  API not responding"
    fi
}

# ---------------------------------------------------------------------------
# cmd: down — destroy everything
# ---------------------------------------------------------------------------
cmd_down() {
    info "Tearing down test topology"

    for ct in "$CT_IN" "$CT_OUT" "$CT_GW"; do
        if ct_exists "$ct"; then
            info "Destroying CT $ct"
            pct stop "$ct" 2>/dev/null || true
            pct destroy "$ct" --force
        fi
    done

    if ip link show "$BR_LAN" >/dev/null 2>&1; then
        info "Removing bridge $BR_LAN"
        ip link set "$BR_LAN" down
        ip link del "$BR_LAN"
    fi

    rm -f /etc/network/interfaces.d/gk-test
    rm -f /tmp/gk-src.tar.gz

    ok "Test topology destroyed"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
case "${1:-}" in
    up)     cmd_up ;;
    down)   cmd_down ;;
    test)   cmd_test ;;
    status) cmd_status ;;
    *)
        echo "Usage: $0 {up|down|test|status}"
        echo ""
        echo "  up      Create bridges, containers, install gatekeeper, run tests"
        echo "  down    Destroy all test containers and bridges"
        echo "  test    Run connectivity tests (containers must already exist)"
        echo "  status  Show container and bridge state"
        echo ""
        echo "Environment:"
        echo "  TEMPLATE   LXC template (default: alpine-3.23)"
        echo "  CT_GW      Gatekeeper CT ID (default: 150)"
        echo "  CT_OUT     Outside CT ID    (default: 151)"
        echo "  CT_IN      Inside CT ID     (default: 152)"
        echo "  BR_WAN     WAN bridge       (default: vmbr1)"
        echo "  BR_LAN     LAN bridge       (default: vmbr2)"
        echo "  STORAGE    Proxmox storage  (default: local-lvm)"
        exit 1
        ;;
esac
