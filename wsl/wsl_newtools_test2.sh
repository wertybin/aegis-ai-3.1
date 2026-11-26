#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
echo "=== DNS QUICK ==="
dig +short @127.0.0.1 aegis-lab.local A
echo "=== DNSRECON STD ==="
"$HOME/.local/bin/dnsrecon" -d aegis-lab.local -n 127.0.0.1 -t std 2>/dev/null | head -n 20
echo "=== DNSRECON BRT ==="
"$HOME/.local/bin/dnsrecon" -d aegis-lab.local -n 127.0.0.1 -t brt -D "$ROOT/wordlists/dns_subdomains.txt" 2>/dev/null | head -n 20
echo "=== NUCLEI VERBOSE ==="
"$HOME/tools/nuclei" -u http://127.0.0.1:5001 -t "$ROOT/wordlists/nuclei-aegis.yaml" \
  -no-color -v -timeout 5 -retries 0 -duc 2>&1 | head -n 60
echo "=== AEGIS PORT ==="
curl -s -o /dev/null -w "8765 -> %{http_code}\n" http://127.0.0.1:8765/
