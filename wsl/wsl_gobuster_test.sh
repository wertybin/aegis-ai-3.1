#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
WL=/tmp/aegis_hidden.txt
cp "$ROOT/wordlists/hidden_files.txt" "$WL"
echo "=== GOBUSTER DIR (site 2) ==="
gobuster dir -u http://127.0.0.1:5001 -w "$WL" -s 200,204,301,302,307,401,403 -b '' \
  -x php,txt,json,bak,sql -t 12 -q -np -nc -ne -e -o /tmp/aegis_gofile_test.txt 2>&1 | head -n 15
echo "=== RESULTS ==="
head -n 20 /tmp/aegis_gofile_test.txt 2>/dev/null || echo "no output file"
