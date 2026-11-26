#!/usr/bin/env bash
# Records the capture files used by the replay tests.
#
# Everything happens in an isolated lab built for the occasion: two Linux
# network namespaces ("attacker" and "victim") joined by a virtual cable.
# No real interface is touched and no packet leaves this machine. The
# namespaces are deleted at the end, even after an error.
#
# The sensor's point of view is the victim's network card, like a home PC
# running Flagman while someone scans it.
#
# Needs: root, iproute2, tcpdump, nmap, python3, ping.
# Usage: sudo ./record-lab-captures.sh [output-folder]

set -euo pipefail

OUT="$(realpath "${1:-$(dirname "$0")}")"
ATTACKER=fm-lab-attacker
VICTIM=fm-lab-victim
ATTACKER_IP=192.168.77.66
VICTIM_IP=192.168.77.10
SERVER_PIDS=()

# For commands that run in the foreground. Background jobs call `ip netns exec`
# directly, so that `$!` is the program itself and not a subshell.
in_attacker() { ip netns exec "$ATTACKER" "$@"; }
in_victim() { ip netns exec "$VICTIM" "$@"; }

cleanup() {
    for pid in "${SERVER_PIDS[@]}"; do kill "$pid" 2>/dev/null || true; done
    ip netns del "$ATTACKER" 2>/dev/null || true
    ip netns del "$VICTIM" 2>/dev/null || true
}
trap cleanup EXIT
cleanup

echo "== Building the lab network 192.168.77.0/24"
ip netns add "$ATTACKER"
ip netns add "$VICTIM"
ip link add fm-attacker type veth peer name fm-victim
ip link set fm-attacker netns "$ATTACKER"
ip link set fm-victim netns "$VICTIM"
# Fixed, locally administered MAC addresses, so recordings are comparable.
in_attacker ip link set fm-attacker address 02:00:00:77:00:66
in_victim ip link set fm-victim address 02:00:00:77:00:10
in_attacker ip addr add "$ATTACKER_IP/24" dev fm-attacker
in_victim ip addr add "$VICTIM_IP/24" dev fm-victim
for ns in "$ATTACKER" "$VICTIM"; do ip -n "$ns" link set lo up; done
in_attacker ip link set fm-attacker up
in_victim ip link set fm-victim up
sleep 1

echo "== Starting the victim's services: a web server (8080) and an SSH-like banner (22)"
ip netns exec "$VICTIM" python3 -m http.server 8080 --bind "$VICTIM_IP" >/dev/null 2>&1 &
SERVER_PIDS+=($!)
ip netns exec "$VICTIM" python3 -c '
import socket
server = socket.create_server(("'"$VICTIM_IP"'", 22), reuse_port=True)
while True:
    connection, _ = server.accept()
    connection.sendall(b"SSH-2.0-OpenSSH_9.6 lab\r\n")
    connection.settimeout(2)
    try:
        connection.recv(256)
    except OSError:
        pass
    connection.close()
' &
SERVER_PIDS+=($!)
sleep 1

# Starts tcpdump on the victim's card; stops it with `stop_capture`.
start_capture() {
    ip netns exec "$VICTIM" tcpdump -i fm-victim -s 160 -U -Z root -w "$OUT/$1" 2>/dev/null &
    CAPTURE_PID=$!
    sleep 1
}
stop_capture() {
    sleep 2
    # SIGTERM, not SIGINT: a script's background jobs ignore SIGINT.
    kill -TERM "$CAPTURE_PID"
    wait "$CAPTURE_PID" || true
}

echo "== Recording lab-attack-chain.pcap"
start_capture lab-attack-chain.pcap
echo "   1. host discovery of the whole network (ARP)"
in_attacker nmap -sn -n 192.168.77.0/24 >/dev/null
sleep 2
echo "   2. default nmap scan of the victim (SYN scan, top 1000 ports)"
in_attacker nmap -n "$VICTIM_IP" >/dev/null
sleep 2
echo "   3. 15 quick connections to SSH, like a password-guessing tool"
in_attacker python3 -c '
import socket, time
for attempt in range(15):
    with socket.create_connection(("'"$VICTIM_IP"'", 22), timeout=2) as connection:
        connection.recv(256)
        connection.sendall(b"SSH-2.0-lab-client\r\n")
    time.sleep(0.3)
'
stop_capture

echo "== Recording lab-normal-traffic.pcap"
start_capture lab-normal-traffic.pcap
echo "   40 web page loads, 5 pings, a few mDNS-like packets"
in_attacker python3 -c '
import socket, time, urllib.request
for page in range(40):
    urllib.request.urlopen("http://'"$VICTIM_IP"':8080/", timeout=2).read()
    time.sleep(0.2)
sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for _ in range(5):
    sender.sendto(b"lab", ("'"$VICTIM_IP"'", 5353))
    time.sleep(0.2)
'
in_attacker ping -c 5 -i 0.2 "$VICTIM_IP" >/dev/null
stop_capture

echo "== Done. Files in $OUT:"
ls -l "$OUT"/*.pcap
