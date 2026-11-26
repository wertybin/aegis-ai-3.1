#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
cd "$ROOT/wordlists" || exit 1
PYTHONPATH="${AEGIS_PYTHONPATH:-$HOME/.local/lib/python3.14/site-packages}"
printf '1234\n' | sudo -S -p '' env PYTHONPATH="$PYTHONPATH" python3 dns_lab_server.py
