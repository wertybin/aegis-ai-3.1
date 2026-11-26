#!/usr/bin/env bash
cd "$HOME/php85"
export LD_LIBRARY_PATH="$HOME/php85/root/usr/lib/x86_64-linux-gnu:$HOME/php85/root/lib/x86_64-linux-gnu"
./root/usr/bin/php8.5 -m | tr '\n' ' '
