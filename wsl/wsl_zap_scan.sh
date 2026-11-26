#!/usr/bin/env bash
set -u
ZAP="$HOME/tools/ZAP_2.17.0/zap.sh"
OUT=/tmp/zap-report.xml
rm -f "$OUT"

echo "=== ZAP QUICK SCAN START ==="
"$ZAP" -cmd -quickurl "http://127.0.0.1:5000" -quickout "$OUT" -quickprogress 2>&1 | tail -n 40

echo
echo "=== REPORT ==="
ls -lh "$OUT" 2>/dev/null || echo "no report"

python3 - <<'PY'
import xml.etree.ElementTree as ET
from pathlib import Path

p = Path("/tmp/zap-report.xml")
if not p.exists():
    print("REPORT MISSING")
    raise SystemExit

root = ET.parse(p).getroot()
alerts = root.findall(".//alertitem")
print("ALERT COUNT:", len(alerts))
rows = []
for a in alerts:
    name = (a.findtext("alert") or "").strip()
    risk = (a.findtext("riskdesc") or "").strip()
    conf = (a.findtext("confidence") or "").strip()
    count = len(a.findall(".//instance"))
    rows.append((risk, name, conf, count))

order = {"High": 0, "Medium": 1, "Low": 2, "Informational": 3}
rows.sort(key=lambda r: order.get(r[0].split(" ")[0], 9))
for risk, name, conf, count in rows:
    print(f"[{risk}] {name} (instances: {count}, confidence: {conf})")
PY
