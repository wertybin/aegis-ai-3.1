#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"

echo "=== SITE 2 ==="
curl -s -o /dev/null -w "HTTP %{http_code}\n" http://127.0.0.1:5001/
curl -s "http://127.0.0.1:5001/api/user?name=alice' OR '1'='1" | head -c 200; echo

echo
echo "=== DIG (local lab DNS) ==="
dig +short @127.0.0.1 aegis-lab.local A
dig +short @127.0.0.1 www.aegis-lab.local A
dig +short @127.0.0.1 -x 127.0.0.1

echo
echo "=== DNSRECON STD ==="
"$HOME/.local/bin/dnsrecon" -d aegis-lab.local -n 127.0.0.1 -t std 2>/dev/null | head -n 25

echo
echo "=== DNSRECON BRUTE ==="
"$HOME/.local/bin/dnsrecon" -d aegis-lab.local -n 127.0.0.1 -t brt \
  -D "$ROOT/wordlists/dns_subdomains.txt" 2>/dev/null | grep -E '\[\*\]|Host' | head -n 25

echo
echo "=== NMAP ==="
nmap -sT -sV -Pn --open -p 5000,5001,8765 127.0.0.1 2>/dev/null | tail -n 20

echo
echo "=== NUCLEI (custom templates) ==="
"$HOME/tools/nuclei" -u http://127.0.0.1:5001 \
  -t "$ROOT/wordlists/nuclei-aegis.yaml" -silent -no-color -timeout 5 -retries 0 2>&1 | head -n 30
