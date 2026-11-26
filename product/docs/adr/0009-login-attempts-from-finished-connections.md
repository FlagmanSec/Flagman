# 0009. Judge login attempts by how each connection ended

Status: accepted; the part about internet servers and `ignore_sources` is
changed by [ADR 0011](0011-watch-logins-to-internet-servers.md)
Date: 2026-11-26

## Context

The first login-attempt (brute force) detector counted every new connection
to a login port, like many simple IDS rules. The review of phase 1 pointed
out that successful logins counted too: git over SSH, VS Code Remote or
Ansible can open 10 connections a minute, the threshold. Flagman only reads
packet headers, never the password, so it cannot see "wrong password".

A lab recording with a real OpenSSH server (`lab-ssh-logins.pcap`, see the
README next to it) showed what headers can tell. A connection with one
wrong password lasted 3.1 s and one with six wrong passwords 17.8 s, because
servers slow down wrong passwords on purpose. A successful login running one
command lasted 0.24 s, and a working session as long as it stays open. So a
failed login is not shorter than a successful one, and "very short" cannot
mean one or two seconds.

## Decision

- The detector looks at connections when they **end**, not when they start.
- A connection counts as a failed attempt when it was **refused** (a reset
  instead of an answer) or **closed within 30 seconds**
  (`max_attempt_secs`). 30 s covers six wrong passwords with room for slower
  servers; OpenSSH allows six per connection by default (`MaxAuthTries`).
- Connections that stay open longer, connections that never got an answer
  (a firewall dropping them: no password can be tried) and half-open ones
  (a scanner) never count.
- By default only services inside the home network are watched
  (`local_targets_only`), so connections from your devices to servers on
  the internet (GitHub, cloud machines) never count. (Changed by ADR 0011:
  internet servers are watched again, with a threshold of 30.)
- To be sure a connection was closed, every finished flow now says why it
  ended (closed, idle, active timeout, evicted, stopped), like the
  `flowEndReason` field of IPFIX, the standard flow export format.

## Consequences

- Working sessions (interactive SSH, VS Code Remote, Ansible's shared
  connection) no longer count, nor do your git commands to GitHub.
- **Known limit**: a quick successful login looks like a failed one, so ten
  quick logins in a minute to a server inside the home network (scripts,
  git to a home server) still raise an alert. The advice on the alert page
  says how to silence a known script (`ignore_sources`; since ADR 0011,
  `ignore_logins`, which silences that one login only), and the home test
  will tell us whether more is needed.
- An attempt is counted about 5 seconds after its connection closes (the
  time a closed flow is kept to catch its last packets).
- In the nmap lab capture the count drops from 16 to 15: nmap's single
  probe of port 22 was half-open, not a login.
- A tool that guesses slowly (fewer than 10 connections a minute) is not
  caught, as before. The thresholds will be tuned with the home test.

## Alternatives considered

- **Count every new connection** (the first version, like many simple IDS
  rules): counts successful logins.
- **"Closed within a second or two"**: would miss password guessing that
  tries several passwords per connection, and would still count quick
  successful logins (0.24 s).
- **Look at which side sent more bytes** (in the lab, the server sent less
  than the client when the login failed, and more when it worked): this
  depends on the server's key type and SSH software, so it would miss
  attacks on routers and older devices, which are the usual targets.
- **Read the server's login log** (what fail2ban does): exact, but only for
  the PC Flagman runs on, and it needs access to system logs. A good later
  addition for that PC.
