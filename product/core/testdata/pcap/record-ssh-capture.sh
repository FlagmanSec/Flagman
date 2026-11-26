#!/usr/bin/env bash
# Records lab-ssh-logins.pcap: real OpenSSH logins, failed and successful,
# used to check the login-attempt (brute force) detector.
#
# Like record-lab-captures.sh, everything happens in an isolated lab: two
# Linux network namespaces ("attacker" and "victim") joined by a virtual
# cable. No real interface is touched and no packet leaves this machine.
#
# The victim runs a real OpenSSH server with its own throwaway configuration,
# host keys and authorised key, all in a temporary folder: no account is
# created and nothing in /etc/ssh is used or changed. The wrong passwords are
# tried for "admin", a user that does not exist.
#
# Needs: root, iproute2, tcpdump, openssh-server, openssh-client, sshpass.
# Usage: sudo ./record-ssh-capture.sh [output-folder]

set -euo pipefail

OUT="$(realpath "${1:-$(dirname "$0")}")"
ATTACKER=fm-lab-ssh-attacker
VICTIM=fm-lab-ssh-victim
ATTACKER_IP=192.168.77.66
VICTIM_IP=192.168.77.10
WORK="$(mktemp -d)"

in_attacker() { ip netns exec "$ATTACKER" "$@"; }

cleanup() {
    if [ -f "$WORK/sshd.pid" ]; then kill "$(cat "$WORK/sshd.pid")" 2>/dev/null || true; fi
    ip netns del "$ATTACKER" 2>/dev/null || true
    ip netns del "$VICTIM" 2>/dev/null || true
    rm -rf "$WORK"
}
trap cleanup EXIT
ip netns del "$ATTACKER" 2>/dev/null || true
ip netns del "$VICTIM" 2>/dev/null || true

echo "== Building the lab network 192.168.77.0/24"
ip netns add "$ATTACKER"
ip netns add "$VICTIM"
ip link add fm-ssh-att type veth peer name fm-ssh-vic
ip link set fm-ssh-att netns "$ATTACKER"
ip link set fm-ssh-vic netns "$VICTIM"
ip -n "$ATTACKER" link set fm-ssh-att address 02:00:00:77:00:66
ip -n "$VICTIM" link set fm-ssh-vic address 02:00:00:77:00:10
ip -n "$ATTACKER" addr add "$ATTACKER_IP/24" dev fm-ssh-att
ip -n "$VICTIM" addr add "$VICTIM_IP/24" dev fm-ssh-vic
for ns in "$ATTACKER" "$VICTIM"; do ip -n "$ns" link set lo up; done
ip -n "$ATTACKER" link set fm-ssh-att up
ip -n "$VICTIM" link set fm-ssh-vic up
sleep 1

echo "== Starting the victim's OpenSSH server (throwaway keys and settings)"
for type in ed25519 ecdsa rsa; do
    ssh-keygen -q -t "$type" -N '' -f "$WORK/host_$type"
done
ssh-keygen -q -t ed25519 -N '' -f "$WORK/client_key"
cp "$WORK/client_key.pub" "$WORK/authorized_keys"
cat > "$WORK/sshd_config" <<CONFIG
ListenAddress $VICTIM_IP
HostKey $WORK/host_ed25519
HostKey $WORK/host_ecdsa
HostKey $WORK/host_rsa
PidFile $WORK/sshd.pid
UsePAM yes
PasswordAuthentication yes
KbdInteractiveAuthentication no
PubkeyAuthentication yes
PermitRootLogin prohibit-password
AuthorizedKeysFile $WORK/authorized_keys
StrictModes no
MaxStartups 100
CONFIG
cat > "$WORK/wrong-password" <<'ASKPASS'
#!/bin/sh
echo "wrong-guess-$$"
ASKPASS
chmod +x "$WORK/wrong-password"
mkdir -p /run/sshd
ip netns exec "$VICTIM" /usr/sbin/sshd -f "$WORK/sshd_config"
sleep 1

CLIENT=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=QUIET)
PASSWORD_ONLY=(-o PreferredAuthentications=password -o PubkeyAuthentication=no)
WITH_KEY=(-i "$WORK/client_key" -o IdentitiesOnly=yes -o PreferredAuthentications=publickey)

echo "== Recording lab-ssh-logins.pcap"
ip netns exec "$VICTIM" tcpdump -i fm-ssh-vic -s 160 -U -Z root -w "$OUT/lab-ssh-logins.pcap" 2>/dev/null &
CAPTURE_PID=$!
sleep 1

echo "   1. 10 connections with one wrong password each"
for attempt in $(seq 1 10); do
    in_attacker sshpass -p "wrong-$attempt" ssh "${CLIENT[@]}" "${PASSWORD_ONLY[@]}" \
        -o NumberOfPasswordPrompts=1 "admin@$VICTIM_IP" true || true
done
echo "   2. 3 connections with wrong passwords until the server hangs up"
for attempt in 1 2 3; do
    SSH_ASKPASS="$WORK/wrong-password" SSH_ASKPASS_REQUIRE=force DISPLAY=lab \
        in_attacker setsid ssh "${CLIENT[@]}" "${PASSWORD_ONLY[@]}" \
        -o NumberOfPasswordPrompts=10 "admin@$VICTIM_IP" true </dev/null || true
done
echo "   3. 1 working session: a key login that stays open 40 s"
in_attacker ssh "${CLIENT[@]}" "${WITH_KEY[@]}" "root@$VICTIM_IP" sleep 40
echo "   4. 5 quick successful logins that each run one command (like git or Ansible)"
for attempt in $(seq 1 5); do
    in_attacker ssh "${CLIENT[@]}" "${WITH_KEY[@]}" "root@$VICTIM_IP" true
done
echo "   5. the server stops; 5 connections are refused"
kill "$(cat "$WORK/sshd.pid")"
rm -f "$WORK/sshd.pid"
sleep 1
for attempt in $(seq 1 5); do
    in_attacker ssh "${CLIENT[@]}" -o ConnectTimeout=2 "root@$VICTIM_IP" true || true
done

sleep 2
kill -TERM "$CAPTURE_PID"
wait "$CAPTURE_PID" || true
echo "== Done: $OUT/lab-ssh-logins.pcap"
