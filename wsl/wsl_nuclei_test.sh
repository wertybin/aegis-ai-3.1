#!/usr/bin/env bash
set -u
ROOT="${AEGIS_ROOT:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)}"
echo "=== NUCLEI CUSTOM TEMPLATES ==="
"$HOME/tools/nuclei" -u http://127.0.0.1:5001 \
  -t "$ROOT/wordlists/nuclei-templates" -silent -no-color -timeout 5 -retries 0 -duc \
  -j -o /tmp/aegis_nuclei.jsonl 2>&1 | head -n 20
echo "=== JSONL ==="
cat /tmp/aegis_nuclei.jsonl | python3 -c '
import json,sys
for line in sys.stdin:
    try: d=json.loads(line)
    except: continue
    print(d.get("info",{}).get("severity"), "|", d.get("template-id"), "|", d.get("matched-at"))
'
echo "=== SITE2 SQLI ==="
curl -s --get --data-urlencode "name=alice' OR '1'='1" http://127.0.0.1:5001/api/user | head -c 300; echo
