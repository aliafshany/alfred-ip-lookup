#!/bin/bash
set -euo pipefail
root="$(cd "$(dirname "$0")/.." && pwd)"
mkdir -p "$root/dist"
out="$root/dist/IP-Lookup.alfredworkflow"
rm -f "$out"
(
  cd "$root/workflow"
  zip -X -r "$out" info.plist iplookup.py icon.png ip.alfredui -x "*/__pycache__/*" "*/.DS_Store"
)
echo "$out"
