#!/usr/bin/env bash
# Rebuilds the lab feature files in this folder from the lab captures
# (product/core/testdata/pcap). Run it after any change to the flow table,
# the features or the Parquet writer; CI fails while the files are stale.
# Needs: Rust (see product/core/rust-toolchain.toml) and libpcap-dev.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
core="$here/../../core"
cd "$core"
cargo build --locked -p flagmand --features parquet
for name in lab-attack-chain lab-normal-traffic lab-ssh-logins; do
    target/debug/flagmand extract "testdata/pcap/$name.pcap" --out "$here/$name.parquet" --overwrite
done
echo "Rebuilt the lab feature files in $here"
