#!/usr/bin/env bash
set -u
mkdir -p "$HOME/tools" && cd "$HOME/tools" || exit 1

echo "=== NUCLEI ==="
NUCLEI_VER=3.11.1
if [ ! -x "$HOME/tools/nuclei" ]; then
  curl -sSL --retry 2 -o /tmp/nuclei.zip \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VER}/nuclei_${NUCLEI_VER}_linux_amd64.zip"
  unzip -o -q /tmp/nuclei.zip -d "$HOME/tools" nuclei
  chmod +x "$HOME/tools/nuclei"
fi
"$HOME/tools/nuclei" -version 2>&1 | head -n 3

echo "=== DNSRECON ==="
python3 -m pip install --user --break-system-packages -q dnsrecon dnslib
"$HOME/.local/bin/dnsrecon" --version 2>&1 | head -n 3 || python3 -m dnsrecon --version 2>&1 | head -n 3
python3 -c 'import dns, dnsrecon, dnslib; print("dnspython/dnsrecon/dnslib import OK")'

echo "=== DNS CLI ==="
dig +short localhost A
dig +short -x 127.0.0.1
