#!/usr/bin/env bash
# Records the Suricata test files: Suricata on the three lab captures, with
# the two local rules of local.rules. Run it with Suricata installed
# (sudo apt install suricata); see README.md.
set -euo pipefail
cd "$(dirname "$0")/../.."   # product/ml
for capture in lab-attack-chain lab-normal-traffic lab-ssh-logins; do
  out="fixtures/suricata/$capture"
  "${PYTHON:-python}" -m flagman_ml.suricata run --overwrite \
    --capture "../core/testdata/pcap/$capture.pcap" \
    --rules fixtures/suricata/local.rules --out "$out" --home-net "[192.168.77.0/24]"
  gzip -9 -n -f "$out/eve.json"   # Suricata's eve.json, unchanged, compressed
  rm -f "$out/console.txt" "$out/fast.log" "$out/stats.log" "$out/suricata.log"
done
