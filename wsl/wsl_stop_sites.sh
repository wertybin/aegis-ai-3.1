#!/usr/bin/env bash
for p in $(ps -eo pid,args | grep -E 'python3 app' | grep -v grep | awk '{print $1}'); do
  kill "$p" 2>/dev/null && echo "killed $p"
done
sleep 1
echo "--- remaining ---"
ps -eo pid,args | grep -E 'python3 app' | grep -v grep || echo NONE
