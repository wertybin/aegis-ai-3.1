#!/usr/bin/env bash
set -u

echo "=== base tools ==="
for t in git curl tar unzip python3 java; do
  printf "%s: " "$t"
  command -v "$t" || echo MISSING
done

echo "=== pip ==="
if ! python3 -m pip --version >/dev/null 2>&1; then
  echo "bootstrapping pip..."
  curl -sS https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
  python3 /tmp/get-pip.py --user --break-system-packages -q
fi
python3 -m pip --version

echo "=== flask + sqlmap ==="
python3 -m pip install --user --break-system-packages -q flask sqlmap
python3 -c 'import flask; print("flask", flask.__version__)'
if [ -x "$HOME/.local/bin/sqlmap" ]; then
  "$HOME/.local/bin/sqlmap" --version | head -n 2
else
  python3 -m sqlmap --version 2>&1 | head -n 2 || echo "sqlmap module missing"
fi

echo "=== ffuf ==="
mkdir -p "$HOME/tools"
FFUF_VER=2.1.0
if [ ! -x "$HOME/tools/ffuf" ]; then
  curl -sSL "https://github.com/ffuf/ffuf/releases/download/v${FFUF_VER}/ffuf_${FFUF_VER}_linux_amd64.tar.gz" -o /tmp/ffuf.tar.gz
  tar -xzf /tmp/ffuf.tar.gz -C "$HOME/tools" ffuf
  chmod +x "$HOME/tools/ffuf"
fi
"$HOME/tools/ffuf" -V || echo "ffuf failed"

echo "=== ZAP ==="
ls -d "$HOME"/tools/ZAP* 2>/dev/null || echo "ZAP not installed (optional)"
