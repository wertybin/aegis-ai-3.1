#!/usr/bin/env bash
set -u
echo "=== apt tooling ==="
for t in apt-get dpkg-deb ar; do printf '%s: ' "$t"; command -v "$t" || echo MISSING; done
echo "=== nmap from apt (no sudo) ==="
mkdir -p /tmp/aegis-debs && cd /tmp/aegis-debs || exit 1
apt-get download nmap nmap-common liblua5.4-0 liblinear4 libpcap0.8 2>&1 | tail -n 15
ls -lh /tmp/aegis-debs | head -n 15
echo "=== nuclei release ==="
curl -sS https://api.github.com/repos/projectdiscovery/nuclei/releases/latest -o /tmp/nuclei_release.json
grep -o '"tag_name": *"[^"]*"' /tmp/nuclei_release.json | head -n 1
grep -o '"browser_download_url": *"[^"]*"' /tmp/nuclei_release.json | grep -iE 'linux_amd64|linux_amd' | head -n 5
echo "=== dnsrecon ==="
python3 -m pip index versions dnsrecon 2>&1 | head -n 5
echo "=== dnslib ==="
python3 -m pip index versions dnslib 2>&1 | head -n 3
