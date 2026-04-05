#!/bin/bash
# Download Oat.ink CSS/JS framework
# Usage: ./download.sh [version]
set -euo pipefail

VERSION="${1:-latest}"
BASE_URL="https://oat.ink"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "Downloading Oat.ink ${VERSION}..."

curl -sSL "${BASE_URL}/oat.min.css" -o "${SCRIPT_DIR}/oat.min.css"
curl -sSL "${BASE_URL}/oat.min.js" -o "${SCRIPT_DIR}/oat.min.js"

# Verify downloads
if [ ! -s "${SCRIPT_DIR}/oat.min.css" ]; then
    echo "ERROR: Failed to download oat.min.css"
    exit 1
fi

if [ ! -s "${SCRIPT_DIR}/oat.min.js" ]; then
    echo "ERROR: Failed to download oat.min.js"
    exit 1
fi

# Copy to v2/frontend/ for go:embed
cp "${SCRIPT_DIR}/oat.min.css" "${PROJECT_ROOT}/v2/frontend/oat.min.css"
cp "${SCRIPT_DIR}/oat.min.js" "${PROJECT_ROOT}/v2/frontend/oat.min.js"

echo "Downloaded oat.min.css ($(wc -c < "${SCRIPT_DIR}/oat.min.css") bytes)"
echo "Downloaded oat.min.js ($(wc -c < "${SCRIPT_DIR}/oat.min.js") bytes)"
echo "Copied to v2/frontend/"
echo "Done."