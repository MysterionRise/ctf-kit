#!/usr/bin/env bash
# Run volatility3 analysis on a memory dump
# Usage: run-volatility.sh <memory-dump> [plugin]
# Default plugin: windows.info (system info)
set -euo pipefail

DUMP="${1:?Usage: run-volatility.sh <memory-dump> [plugin]}"
PLUGIN="${2:-windows.info}"

if ! command -v vol &>/dev/null; then
    echo "ERROR: volatility3 not installed. Install: pip install volatility3" >&2
    exit 1
fi

echo "=== Volatility3: $PLUGIN on $DUMP ==="
vol -f "$DUMP" "$PLUGIN"
