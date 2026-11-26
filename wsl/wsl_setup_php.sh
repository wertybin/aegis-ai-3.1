#!/usr/bin/env bash
set -e
cd "$HOME/php85"
apt-get download php8.5-cli php8.5-common php8.5-readline libargon2-1 libsodium23 libxml2-16 libssl3t64 libedit2 >/dev/null 2>&1
for f in *.deb; do dpkg-deb -x "$f" root; done
export LD_LIBRARY_PATH="$HOME/php85/root/usr/lib/x86_64-linux-gnu:$HOME/php85/root/lib/x86_64-linux-gnu"
./root/usr/bin/php8.5 -v
echo '---'
ldd ./root/usr/bin/php8.5 | grep 'not found' || echo LIBS_OK
