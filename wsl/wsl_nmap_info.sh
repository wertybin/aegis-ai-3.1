#!/usr/bin/env bash
set -u
echo "=== nmap depends ==="
apt-cache depends nmap 2>&1 | head -n 30
echo "=== download nmap + common ==="
cd /tmp/aegis-debs || exit 1
apt-get download nmap nmap-common 2>&1 | tail -n 10
ls -lh /tmp/aegis-debs
echo "=== nmap.org AppImage check ==="
curl -sSL --max-time 30 https://nmap.org/dist/ -o /tmp/nmapdist.html
grep -oE 'nmap-[0-9.]+-[a-z0-9_]+\.AppImage|nmap-[0-9.]+-x86_64\.AppImage|nmap-[0-9.]+\.tar\.bz2' /tmp/nmapdist.html | sort -u | tail -n 10
