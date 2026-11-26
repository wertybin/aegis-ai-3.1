#!/usr/bin/env bash
set -u
LINE='127.0.0.1 aegis-lab.local www.aegis-lab.local api.aegis-lab.local dev.aegis-lab.local staging.aegis-lab.local mail.aegis-lab.local admin.aegis-lab.local'
if ! grep -q 'aegis-lab.local' /etc/hosts 2>/dev/null; then
  printf '1234\n' | sudo -S -p '' sh -c "printf '%s\n' '$LINE' >> /etc/hosts"
fi
tail -n 3 /etc/hosts
echo "=== std retry ==="
"$HOME/.local/bin/dnsrecon" -d aegis-lab.local -n 127.0.0.1 -t std 2>/dev/null | head -n 20
echo "=== reverse ==="
"$HOME/.local/bin/dnsrecon" -n 127.0.0.1 -r 127.0.0.1-127.0.0.2 -t rvl 2>/dev/null | head -n 15
