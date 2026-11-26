#!/usr/bin/env bash
set -u
F="$HOME/.local/lib/python3.14/site-packages/dnsrecon/lib/bingenum.py"
echo "=== original lines 1-45 ==="
sed -n '1,45p' "$F"
echo "=== urllib attrs ==="
python3 -c 'import urllib.request as u; print([x for x in ("FancyURLopener","URLopener","urlopen") if hasattr(u,x)])'
