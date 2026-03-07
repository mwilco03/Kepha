#!/bin/bash
# Build Gatekeeper binaries for production.
set -euo pipefail

# CalVer: YYYY.0M.patch. Falls back to git describe, then "dev".
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
# For release builds, set VERSION explicitly: VERSION=2026.03.0 bash scripts/build.sh
LDFLAGS="-X main.version=${VERSION} -s -w"
OUTPUT_DIR="${OUTPUT_DIR:-bin}"

echo "Building Gatekeeper ${VERSION}..."

mkdir -p "${OUTPUT_DIR}"

echo "  gatekeeperd..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "${LDFLAGS}" -o "${OUTPUT_DIR}/gatekeeperd" ./cmd/gatekeeperd

echo "  gk..."
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags "${LDFLAGS}" -o "${OUTPUT_DIR}/gk" ./cmd/gk

echo "Done. Binaries in ${OUTPUT_DIR}/"
ls -lh "${OUTPUT_DIR}/"
