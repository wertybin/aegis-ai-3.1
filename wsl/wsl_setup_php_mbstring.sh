#!/usr/bin/env bash
set -e
cd "$HOME/php85"
apt-get download php8.5-mbstring >/dev/null 2>&1
for f in php8.5-mbstring*.deb; do dpkg-deb -x "$f" root; done
export LD_LIBRARY_PATH="$HOME/php85/root/usr/lib/x86_64-linux-gnu:$HOME/php85/root/lib/x86_64-linux-gnu"
./root/usr/bin/php8.5 -m | grep -i mbstring
