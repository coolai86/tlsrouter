#!/bin/bash
# Download Datastar JS library
# Usage: ./download.sh [version]
set -euo pipefail

VERSION="${1:-v1.0.0-RC.7}"
BASE_URL="https://raw.githubusercontent.com/starfederation/datastar/${VERSION#v}/bundles"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Downloading Datastar ${VERSION}..."

curl -sSL "${BASE_URL}/datastar.js" -o "${SCRIPT_DIR}/datastar.js"

# Verify download
if [ ! -s "${SCRIPT_DIR}/datastar.js" ]; then
    echo "ERROR: Failed to download datastar.js"
    exit 1
fi

# Copy to v2/vendor/ for go:embed
cp "${SCRIPT_DIR}/datastar.js" "${PROJECT_ROOT}/v2/vendor/datastar.js"

echo "Downloaded datastar.js ($(wc -c < "${SCRIPT_DIR}/datastar.js") bytes)"
echo "Copied to v2/vendor/datastar.js"
echo "Done."