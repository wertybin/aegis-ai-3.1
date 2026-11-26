#!/usr/bin/env bash
set -u
echo "=== dnsrecon full error ==="
"$HOME/.local/bin/dnsrecon" --version 2>&1 | tail -n 30
echo "=== dnsrecon -h ==="
"$HOME/.local/bin/dnsrecon" -h 2>&1 | head -n 40
echo "=== nuclei options ==="
"$HOME/tools/nuclei" -h 2>&1 | grep -E '^\s+-(update-templates|templates|t|u|severity|json|o|silent|no-color|rate-limit|retries|timeout)\b' | head -n 20
