#!/usr/bin/env bash
set -u
echo "=== DISK ==="
df -h "$HOME" | tail -n 2
echo "=== ZAP RELEASE ==="
curl -sS https://api.github.com/repos/zaproxy/zaproxy/releases/latest -o /tmp/zap_release.json
grep -o '"tag_name": *"[^"]*"' /tmp/zap_release.json | head -n 1
grep -o '"browser_download_url": *"[^"]*"' /tmp/zap_release.json | grep -i 'linux' | head -n 5
echo "=== JAVA ==="
java -version 2>&1 | head -n 1
