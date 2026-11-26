#!/usr/bin/env bash
set -u
ZAP_VER=2.17.0
mkdir -p "$HOME/tools"
cd "$HOME/tools" || exit 1

if [ ! -d "$HOME/tools/ZAP_${ZAP_VER}" ]; then
  echo "downloading ZAP ${ZAP_VER}..."
  curl -L --fail --retry 2 -o /tmp/ZAP.tar.gz \
    "https://github.com/zaproxy/zaproxy/releases/download/v${ZAP_VER}/ZAP_${ZAP_VER}_Linux.tar.gz"
  echo "extracting..."
  tar -xzf /tmp/ZAP.tar.gz -C "$HOME/tools"
fi

ls -d "$HOME/tools/ZAP_${ZAP_VER}"
"$HOME/tools/ZAP_${ZAP_VER}/zap.sh" -version 2>&1 | head -n 5
