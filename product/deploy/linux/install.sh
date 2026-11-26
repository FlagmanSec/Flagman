#!/usr/bin/env bash
# Builds Flagman and installs it as a systemd service on this Linux machine.
#
#   sudo ./install.sh            build, install, start
#   sudo ./install.sh --uninstall  stop and remove the program (keeps your data)
#
# It never overwrites an existing /etc/flagman/flagman.toml, and never
# deletes /var/lib/flagman (your database and token).
#
# Build needs: Rust (rustup), libpcap-dev, and Node.js 20+ for the dashboard.
# Run it from a clone of the repository.

set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
PRODUCT="$(cd "$HERE/../.." && pwd)"
BIN=/usr/local/bin/flagmand
UI=/usr/share/flagman/ui
CONFIG=/etc/flagman/flagman.toml
UNIT=/etc/systemd/system/flagman.service

if [[ $EUID -ne 0 ]]; then
    echo "Please run with sudo: sudo $0 $*" >&2
    exit 1
fi

if [[ "${1:-}" == "--uninstall" ]]; then
    systemctl disable --now flagman.service 2>/dev/null || true
    rm -f "$UNIT" "$BIN"
    rm -rf "$UI"
    systemctl daemon-reload
    echo "Removed. Your data is still in /var/lib/flagman and your settings in /etc/flagman."
    exit 0
fi

# Build as the user who called sudo, so build files are not owned by root.
BUILDER="${SUDO_USER:-root}"
as_builder() { sudo -u "$BUILDER" -H bash -lc "$*"; }

echo "== Building the sensor (Rust)"
as_builder "cd '$PRODUCT/core' && cargo build --release --locked -p flagmand"

echo "== Building the dashboard"
if as_builder "command -v npm" >/dev/null; then
    as_builder "cd '$PRODUCT/ui' && npm ci && npm run build"
else
    echo "   npm not found: skipping the dashboard (the API still works)."
fi

echo "== Installing"
id flagman >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin flagman
install -m 0755 "$PRODUCT/core/target/release/flagmand" "$BIN"
if [[ -f "$PRODUCT/ui/dist/index.html" ]]; then
    rm -rf "$UI"
    mkdir -p "$UI"
    cp -r "$PRODUCT/ui/dist/." "$UI/"
    chmod -R a+rX "$UI"
fi
mkdir -p /etc/flagman
if [[ -f "$CONFIG" ]]; then
    echo "   keeping your existing $CONFIG"
else
    install -m 0644 "$HERE/flagman.toml" "$CONFIG"
fi
install -m 0644 "$HERE/flagman.service" "$UNIT"

echo "== Starting"
systemctl daemon-reload
systemctl enable --now flagman.service
sleep 2
systemctl --no-pager --lines=5 status flagman.service || true

echo
echo "Open the dashboard with this link (keep it private, it contains the access token):"
sudo -u flagman "$BIN" token --config "$CONFIG" || echo "   (run: sudo flagmand token)"
