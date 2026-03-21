#!/bin/bash
# Create a versioned release with CalVer.
# Usage: bash scripts/release.sh [version]
# Example: bash scripts/release.sh 2026.03.1
set -euo pipefail

VERSION="${1:-$(date +%Y.%m).0}"
TAG="v${VERSION}"

echo "=== Gatekeeper Release ${TAG} ==="

# Build production binaries.
VERSION="${VERSION}" bash scripts/build.sh

# Create release tarball.
TARBALL="gatekeeper-${VERSION}-linux-amd64.tar.gz"
tar czf "${TARBALL}" \
    -C bin gatekeeperd gk \
    -C .. init/gatekeeperd.openrc init/gatekeeperd.service \
    scripts/install-alpine.sh scripts/first-boot.sh

echo "Release tarball: ${TARBALL}"
ls -lh "${TARBALL}"

# Tag if not already tagged.
if ! git rev-parse "${TAG}" >/dev/null 2>&1; then
    git tag -a "${TAG}" -m "Release ${VERSION}"
    echo "Tagged: ${TAG}"
fi

echo ""
echo "To publish:"
echo "  git push origin ${TAG}"
echo "  gh release create ${TAG} ${TARBALL} --title 'Gatekeeper ${VERSION}' --notes-file CHANGELOG.md"
