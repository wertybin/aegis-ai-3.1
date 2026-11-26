#!/usr/bin/env bash
set -u
"$HOME/.local/bin/sqlmap" \
  -u "http://127.0.0.1:5000/" \
  --crawl=2 --batch --level=1 --risk=1 --technique=BEU --flush-session \
  --threads=1 --timeout=10 --retries=1 --output-dir=/tmp/sqlmap-crawl \
  > /tmp/sqlmap-crawl.log 2>&1
grep -aE " crawling |Parameter:|Type:|Title:|Payload:|back-end DBMS|is vulnerable|not injectable|CRITICAL" /tmp/sqlmap-crawl.log | head -n 40
