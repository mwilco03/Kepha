#!/usr/bin/env bash
# smoke-test.sh — End-to-end integration smoke test for gatekeeperd.
#
# Runs INSIDE the build container (CT 112). Starts a fresh daemon with
# a temporary database, then validates all core subsystems.
#
# Usage:  ./scripts/smoke-test.sh
# Exit:   0 = all checks passed, 1 = at least one failure.

set -euo pipefail

PORT=18080
WORK=$(mktemp -d /tmp/gk-smoke.XXXXXX)
DAEMON_PID=""
PASS=0
FAIL=0

# --- Cleanup ---

cleanup() {
    if [ -n "$DAEMON_PID" ] && kill -0 "$DAEMON_PID" 2>/dev/null; then
        kill "$DAEMON_PID" 2>/dev/null || true
        wait "$DAEMON_PID" 2>/dev/null || true
    fi
    # Remove nft tables created during test (kernel-persistent).
    nft delete table inet gk_perf 2>/dev/null || true
    nft delete table inet gatekeeper 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT

# --- Helpers ---

pass() { PASS=$((PASS + 1)); printf "  \033[32mPASS\033[0m %s\n" "$1"; }
fail() { FAIL=$((FAIL + 1)); printf "  \033[31mFAIL\033[0m %s\n" "$1"; }

BASE="http://127.0.0.1:$PORT"

echo "=== Gatekeeper Smoke Test ==="
echo ""

# --- Prerequisites ---

for cmd in nft curl dnsmasq; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "FATAL: $cmd not found"; exit 1
    fi
done

# --- Build if needed ---

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
PROJECT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BINARY="$PROJECT_DIR/gatekeeperd"

if [ ! -x "$BINARY" ]; then
    echo "Building gatekeeperd..."
    cd "$PROJECT_DIR" && go build -o gatekeeperd ./cmd/gatekeeperd
fi

# --- Start daemon with temp state ---

mkdir -p "$WORK"/{db,rulesets,dnsmasq}

echo "Starting daemon on :$PORT (workdir $WORK)..."
SMOKE_API_KEY="smoke-test-$(date +%s)"
"$BINARY" \
    -listen ":$PORT" \
    -api-key "$SMOKE_API_KEY" \
    -db "$WORK/db/gatekeeper.db" \
    -ruleset-dir "$WORK/rulesets" \
    -dnsmasq-dir "$WORK/dnsmasq" \
    -dnsmasq-pid "$WORK/dnsmasq.pid" \
    >"$WORK/daemon.log" 2>&1 &
DAEMON_PID=$!

# Wait for readiness (up to 10 s).
READY=false
for _ in $(seq 1 20); do
    if curl -sf "$BASE/api/v1/healthz" >/dev/null 2>&1; then
        READY=true; break
    fi
    sleep 0.5
done
if ! $READY; then
    echo "FATAL: daemon did not become ready within 10 s"
    cat "$WORK/daemon.log"
    exit 1
fi
echo "Daemon ready (PID $DAEMON_PID)"
echo ""

# ================================================================
# 1. Health check
# ================================================================
echo "[1] Health check"

CODE=$(curl -s -o /dev/null -w '%{http_code}' "$BASE/api/v1/healthz")
[ "$CODE" = "200" ] \
    && pass "/api/v1/healthz returns 200" \
    || fail "/api/v1/healthz returned $CODE"

BODY=$(curl -sf "$BASE/api/v1/healthz")
echo "$BODY" | grep -q '"status":"ok"' \
    && pass 'body contains "status":"ok"' \
    || fail "unexpected body: $BODY"

# ================================================================
# 2. Default zones (wan + lan seeded on first boot)
# ================================================================
echo "[2] Default zones"

ZONES=$(curl -sf -H "X-API-Key: $SMOKE_API_KEY" "$BASE/api/v1/zones")
echo "$ZONES" | grep -q '"name":"wan"' \
    && pass "wan zone exists" \
    || fail "wan zone not found"

echo "$ZONES" | grep -q '"name":"lan"' \
    && pass "lan zone exists" \
    || fail "lan zone not found"

# ================================================================
# 3. nftables rules compiled and applied
# ================================================================
echo "[3] nftables rules"

if nft list table inet gatekeeper >/dev/null 2>&1; then
    pass "table inet gatekeeper exists"

    NFT=$(nft list table inet gatekeeper)
    echo "$NFT" | grep -q "chain input" \
        && pass "input chain present" \
        || fail "input chain missing"
    echo "$NFT" | grep -q "chain forward" \
        && pass "forward chain present" \
        || fail "forward chain missing"
    echo "$NFT" | grep -q "chain postrouting" \
        && pass "postrouting chain present" \
        || fail "postrouting chain missing"
else
    fail "table inet gatekeeper not found"
fi

# ================================================================
# 4. dnsmasq config generated and valid
# ================================================================
echo "[4] dnsmasq config"

DNSMASQ_CONF="$WORK/dnsmasq/dnsmasq.conf"
if [ -f "$DNSMASQ_CONF" ]; then
    pass "dnsmasq.conf generated"

    grep -q "^server=" "$DNSMASQ_CONF" \
        && pass "upstream server= directive present" \
        || fail "server= directive missing"

    grep -q "^domain=" "$DNSMASQ_CONF" \
        && pass "domain= directive present" \
        || fail "domain= directive missing"

    # Validate syntax with dnsmasq itself.
    if dnsmasq --test --conf-file="$DNSMASQ_CONF" >/dev/null 2>&1; then
        pass "dnsmasq --test validates config"
    else
        fail "dnsmasq --test failed: $(dnsmasq --test --conf-file="$DNSMASQ_CONF" 2>&1)"
    fi
else
    fail "dnsmasq.conf not generated"
fi

# ================================================================
# 5. PerformanceTuner: enable and verify sysctl settings
# ================================================================
echo "[5] PerformanceTuner sysctl"

CODE=$(curl -s -o /dev/null -w '%{http_code}' -H "X-API-Key: $SMOKE_API_KEY" -X POST "$BASE/api/v1/services/performance-tuner/enable")
if [ "$CODE" = "200" ] || [ "$CODE" = "204" ]; then
    pass "performance-tuner service enabled ($CODE)"
else
    fail "performance-tuner enable returned $CODE"
fi

# Give the service a moment to apply settings.
sleep 1

# Verify the daemon is still alive after enabling the service.
if ! kill -0 "$DAEMON_PID" 2>/dev/null; then
    echo "FATAL: daemon crashed after enabling performance-tuner"
    cat "$WORK/daemon.log"
    exit 1
fi

# ip_forward (should already be 1, but tuner ensures it).
FWD=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null || echo "?")
[ "$FWD" = "1" ] \
    && pass "ip_forward = 1" \
    || fail "ip_forward = $FWD (expected 1)"

# netdev_max_backlog (default config: 4096).
# This sysctl is NOT network-namespaced — it doesn't exist inside LXC.
BL_PATH="/proc/sys/net/core/netdev_max_backlog"
if [ -f "$BL_PATH" ]; then
    BL=$(cat "$BL_PATH")
    [ "$BL" -ge 4096 ] 2>/dev/null \
        && pass "netdev_max_backlog = $BL (>= 4096)" \
        || fail "netdev_max_backlog = $BL (expected >= 4096)"
else
    pass "netdev_max_backlog skipped (not namespaced in LXC)"
fi

# somaxconn (default config: 16384).
SC=$(cat /proc/sys/net/core/somaxconn 2>/dev/null || echo "0")
[ "$SC" -ge 16384 ] 2>/dev/null \
    && pass "somaxconn = $SC (>= 16384)" \
    || fail "somaxconn = $SC (expected >= 16384)"

# ================================================================
# 6. Flowtable in nftables ruleset
# ================================================================
echo "[6] Flowtable"

if nft list table inet gk_perf >/dev/null 2>&1; then
    pass "table inet gk_perf exists"
    nft list table inet gk_perf | grep -q "flowtable" \
        && pass "flowtable ft declared" \
        || fail "flowtable not found in gk_perf"
else
    # Flowtables require >= 2 non-loopback UP interfaces.
    # A single-NIC container (typical LXC) correctly skips this.
    IFACE_COUNT=$(ip -o link show up | grep -cv ": lo:" 2>/dev/null || echo "0")
    if [ "$IFACE_COUNT" -lt 2 ]; then
        pass "gk_perf skipped (${IFACE_COUNT} non-lo interface, need 2+)"
    else
        fail "gk_perf table missing despite ${IFACE_COUNT} interfaces"
    fi
fi

# ================================================================
# Summary
# ================================================================
echo ""
TOTAL=$((PASS + FAIL))
echo "=== $PASS/$TOTAL passed, $FAIL failed ==="

if [ "$FAIL" -gt 0 ]; then
    echo ""
    echo "--- daemon log (last 50 lines) ---"
    tail -50 "$WORK/daemon.log"
    exit 1
fi
exit 0
