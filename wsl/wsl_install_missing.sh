#!/usr/bin/env bash
set -u
echo "=== SUDO TEST ==="
printf '1234\n' | sudo -S -p '' true 2>/dev/null && echo "SUDO OK" || echo "SUDO FAILED"
echo "=== APT UPDATE ==="
printf '1234\n' | sudo -S -p '' apt-get update -qq 2>/dev/null && echo "APT UPDATE OK" || echo "APT UPDATE FAILED"
echo "=== INSTALL NMAP / DNSUTILS / UNZIP ==="
printf '1234\n' | sudo -S -p '' DEBIAN_FRONTEND=noninteractive apt-get install -y -qq nmap dnsutils unzip 2>/dev/null
echo "=== VERSIONS ==="
for t in nmap dig host nslookup unzip; do printf '%-10s ' "$t"; command -v "$t" || echo MISSING; done
nmap --version 2>&1 | head -n 2
