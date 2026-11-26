#!/usr/bin/env bash
pkill -f "python3 app.py" 2>/dev/null || true
sleep 1
echo "stopped"
