#!/usr/bin/env bash
# Stop all lab processes running inside WSL (sample sites, DNS lab).
echo "--- stopping WSL lab processes ---"
for pattern in 'python3 app.py' 'python3 app2.py' 'php8.5 -d extension' 'named' 'dnsmasq'; do
  for p in $(ps -eo pid,args | grep -F "$pattern" | grep -v grep | awk '{print $1}'); do
    kill "$p" 2>/dev/null && echo "  killed [$pattern] pid=$p"
  done
done
sleep 2
echo "--- remaining ---"
ps -eo pid,args | grep -E 'python3 app|php8.5|named|dnsmasq' | grep -v grep || echo "  NONE"
