#!/usr/bin/env bash
set -u
"$HOME/tools/nuclei" -h 2>&1 | grep -iE 'json|output|format' | head -n 30
