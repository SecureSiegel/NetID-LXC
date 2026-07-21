#!/usr/bin/env bash
set -euo pipefail

NETWORK="${1:-192.168.1.0/24}"
exec /usr/local/bin/netid-lxc "$NETWORK"
