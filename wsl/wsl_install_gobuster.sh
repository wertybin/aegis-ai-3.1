#!/usr/bin/env bash
set -u
printf '1234\n' | sudo -S -p '' DEBIAN_FRONTEND=noninteractive apt-get install -y -qq gobuster 2>/dev/null
gobuster version 2>&1 | head -n 3
