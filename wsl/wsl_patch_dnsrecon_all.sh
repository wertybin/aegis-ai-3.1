#!/usr/bin/env bash
set -u
DIR="$HOME/.local/lib/python3.14/site-packages/dnsrecon"
grep -rl 'urllib.request.FancyURLopener' "$DIR" | while read -r F; do
  cp "$F" "$F.bak"
  python3 - "$F" <<'PY'
import sys
p = sys.argv[1]
s = open(p, encoding="utf-8").read()
old = "url_opener = urllib.request.FancyURLopener"
new = '''class _FancyURLopenerCompat:
    """Python 3.14 compatibility shim."""
    version = "Mozilla/5.0 (compatible; dnsrecon/0.10.1)"
    def __init__(self, *args, **kwargs):
        pass
    def open(self, *args, **kwargs):
        return urllib.request.urlopen(*args, **kwargs)


url_opener = getattr(urllib.request, "FancyURLopener", _FancyURLopenerCompat)'''
if old in s:
    open(p, "w", encoding="utf-8").write(s.replace(old, new))
    print("patched:", p)
PY
done
echo "=== version ==="
"$HOME/.local/bin/dnsrecon" --version 2>&1 | tail -n 5
echo "=== options ==="
"$HOME/.local/bin/dnsrecon" -h 2>&1 | grep -E '(-d |--domain|-t |--type|-n |--name_server|-p |--port|-D |--dictionary|-a |--range)' | head -n 30
