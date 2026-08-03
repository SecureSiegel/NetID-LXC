#!/usr/bin/env bash
set -euo pipefail

LISTEN_SECONDS="${1:-30}"
exec /usr/local/bin/netid-lxc "$LISTEN_SECONDS"
