# Installing Flagman on Linux

Files in this folder:

| File | What it is |
|---|---|
| `install.sh` | Builds Flagman and installs it as a service. Run with `sudo`. |
| `flagman.service` | The systemd unit. The sensor runs as the `flagman` user with only `CAP_NET_RAW` and `CAP_NET_ADMIN`. |
| `flagman.toml` | The configuration, with every setting and its default. |

## Quick install (Ubuntu or Debian)

```bash
# 1. Build tools (once)
sudo apt install build-essential libpcap-dev nodejs npm
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh   # Rust, from rustup.rs

# 2. Build, install and start
cd product/deploy/linux
sudo ./install.sh
```

The last lines printed are the dashboard link, for example
`http://127.0.0.1:8750/#token=…`. Open it in a browser on the same machine.
The link contains the access token, so do not share it.

Node.js 20 or newer is needed for the dashboard. If your distribution's
`nodejs` is older, install a current one from [nodejs.org](https://nodejs.org).

## Everyday commands

```bash
systemctl status flagman          # is it running?
journalctl -u flagman -f          # its log
sudo flagmand token               # print the dashboard link again
flagmand interfaces               # list network interfaces
sudo systemctl restart flagman    # after editing /etc/flagman/flagman.toml
```

## Running without installing

```bash
cd product/core
cargo build --release -p flagmand
sudo ./target/release/flagmand run --interface enp3s0   # your interface name
```

Without a configuration file, the database and token go to
`/var/lib/flagman/`. Pass `--config my.toml` to change that.

## Opening the dashboard from another device

The dashboard listens on `127.0.0.1` only. From a laptop, use an SSH tunnel:

```bash
ssh -L 8750:127.0.0.1:8750 you@the-sensor
```

then open the same link on the laptop. Changing `listen` to `0.0.0.0:8750`
also works, but the token then travels over the network without encryption
(there is no HTTPS yet). See `docs/threat-model.md`.

## Suricata (optional)

Flagman reads Suricata's alerts from `/var/log/suricata/eve.json` when
Suricata is installed. See `docs/home-test.md` for the setup. If the health
strip says "permission denied", add the `flagman` user to the group that owns
that file: `sudo usermod -aG suricata flagman`, then restart Flagman.

## Uninstalling

```bash
sudo ./install.sh --uninstall
```

This removes the program and the service. Your data (`/var/lib/flagman`) and
settings (`/etc/flagman`) are kept; delete them by hand if you want.
