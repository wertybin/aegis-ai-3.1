#!/usr/bin/env bash
set -u
F="$HOME/.local/lib/python3.14/site-packages/dnsrecon/lib/bingenum.py"
cp "$F" "$F.bak"
python3 - "$F" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = "url_opener = urllib.request.FancyURLopener"
new = '''class _FancyURLopenerCompat:
    """Python 3.14 compatibility shim (urllib.request.FancyURLopener removed)."""
    version = "Mozilla/5.0 (compatible; dnsrecon/0.10.1)"
    def __init__(self, *args, **kwargs):
        pass
    def open(self, *args, **kwargs):
        return urllib.request.urlopen(*args, **kwargs)


url_opener = getattr(urllib.request, "FancyURLopener", _FancyURLopenerCompat)'''
assert old in s, "pattern not found"
open(p, "w", encoding="utf-8").write(s.replace(old, new, 1))
print("patched", p)
PY
echo "=== version ==="
"$HOME/.local/bin/dnsrecon" --version 2>&1 | tail -n 5
echo "=== relevant options ==="
"$HOME/.local/bin/dnsrecon" -h 2>&1 | grep -E '^\s+(-d |--domain|-t |--type|-n |--name_server|-p |--port|-D |--dictionary|-a |--range)' | head -n 25
echo "=== resolv.conf ==="
cat /etc/resolv.conf
