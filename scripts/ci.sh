#!/bin/bash
# CI pipeline — mirrors what .github/workflows/ci.yml should do.
# Run locally or in any CI system: bash scripts/ci.sh
set -euo pipefail

echo "=== Gatekeeper CI Pipeline ==="

echo "[1/5] Build..."
make build

echo "[2/5] Test..."
make test

echo "[3/5] Lint..."
make lint

echo "[4/5] Vulnerability scan..."
make vuln

echo "[5/5] Smoke test..."
make smoke-ci

echo ""
echo "=== CI PASSED ==="
