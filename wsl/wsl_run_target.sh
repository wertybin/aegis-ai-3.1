#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
cd "$ROOT/sample_vulnerable_app" || exit 1
exec python3 app.py
