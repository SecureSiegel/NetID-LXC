#!/usr/bin/env bash
set -euo pipefail

LISTEN_SECONDS="${1:-30}"
OUTPUT_DIR="${2:-/var/lib/netid-lxc/output}"
exec /usr/local/bin/netid-lxc "$LISTEN_SECONDS" "$OUTPUT_DIR"
