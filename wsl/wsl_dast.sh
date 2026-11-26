#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"

echo "=== SQLMAP ==="
"$HOME/.local/bin/sqlmap" \
  -u "http://127.0.0.1:5000/api/user?username=admin" \
  --batch --level=1 --risk=1 --technique=B --flush-session \
  --output-dir=/tmp/sqlmap-aegis --timeout=10 --retries=1 \
  > /tmp/sqlmap.log 2>&1
tail -n 35 /tmp/sqlmap.log

echo
echo "=== SQLMAP SUMMARY ==="
grep -aE "Parameter:|Type:|Title:|Payload:|back-end DBMS|is vulnerable|might be injectable" /tmp/sqlmap.log | head -n 25

echo
echo "=== FFUF ==="
"$HOME/tools/ffuf" -u "http://127.0.0.1:5000/FUZZ" \
  -w "$ROOT/wordlists/common.txt" \
  -mc 200,204,301,302,307,401,403 -t 20 -s 2>&1
