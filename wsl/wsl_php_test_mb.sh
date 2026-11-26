#!/usr/bin/env bash
cd "$HOME/php85"
echo '--- LDD mbstring.so ---'
ldd root/usr/lib/php/20250925/mbstring.so 2>&1 | grep -i 'not found' || echo LIBS_OK
echo '--- LOAD TEST ---'
export LD_LIBRARY_PATH="$HOME/php85/root/usr/lib/x86_64-linux-gnu:$HOME/php85/root/lib/x86_64-linux-gnu"
./root/usr/bin/php8.5 -d extension="$HOME/php85/root/usr/lib/php/20250925/mbstring.so" -r 'echo function_exists("mb_strtolower") ? "MB_OK\n" : "MB_FAIL\n";' 2>&1
