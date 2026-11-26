# 0011. Watch login attempts on internet servers with a higher threshold

Status: accepted
Date: 2026-11-26

## Context

[ADR 0009](0009-login-attempts-from-finished-connections.md) made the login
detector count only connections that were refused or closed within 30 s.
To keep git over SSH to GitHub quiet, it also watched only servers inside
the home network (`local_targets_only = true`).

The follow-up review of phase 1 pointed out the cost: a device in the home
that guesses passwords on servers on the internet was never reported. The
review calls this typical botnet behaviour: a device that has been taken
over and is used against other people's servers. Telling the owner about
it is one of the reasons to run an IDS at home.

Two facts shape the decision:

- **Normal use makes quick logins to internet servers.** Each `git fetch`
  or `git push` over SSH is one short connection, and from packet headers a
  quick successful login looks like a failed one (ADR 0009). A person
  working by hand makes a few a minute; a script can make more.
- **Guessing tools make many.** In the lab recording
  `lab-ssh-logins.pcap` (real OpenSSH), one wrong password took 3.1 s and
  six wrong passwords 17.8 s. A tool that reconnects for each password
  therefore makes about 19 connections a minute for each connection it runs
  in parallel (60 / 3.1), and one that tries six passwords per connection
  about 3.4 (60 / 17.8).

## Decision

- Servers on the internet are watched again, with their own threshold:
  `outbound_min_attempts`, **30** failed attempts on one server's login
  port within 60 s by default, three times the threshold inside the home
  (`min_attempts`, 10). Everything else is the same rule as ADR 0009.
- The alert says which case it is (`outbound` in the alert details), and
  the dashboard gives its own advice: check the device for unwanted
  software, or, if it is your script, add an exception.
- The alert and its incident are filed under the home device (the
  guesser), as for every login alert.
- `local_targets_only` stays as a setting, so existing configuration files
  remain valid. Its default changes from `true` to `false`; `true` turns
  the internet watch off.
- Known scripts are silenced **one login at a time**, with
  `brute_force.ignore_logins` (source, target, port). The advice on the
  alert page now points there instead of `ignore_sources`, which silences a
  device for every detector and so would also hide its scans.
- 30 is a starting value, like the other thresholds. The home test week
  ([phase 2 plan](../phase-2-plan.md), 2.1) will tell whether it is right.

## Consequences

- A home device that guesses passwords on an internet server with two or
  more parallel connections, one password each, crosses 30 a minute and is
  reported. The test `guessing_passwords_on_an_internet_server_is_reported`
  checks it, and fails with the old default.
- Normal git use stays quiet: the test
  `quick_logins_to_an_internet_server_stay_silent` sends 20 quick logins in
  a minute to an internet server (silent) and the same 20 to a home server
  (reported).
- **Existing installations keep the old behaviour.** The installer never
  overwrites `/etc/flagman/flagman.toml`, and phase 1 wrote
  `local_targets_only = true` there. Owners who want the internet watch set
  it to `false` (the changelog says so).
- **Known limits**:
  - a slow guesser stays under 30: one connection at a time with one
    password each (about 19 a minute), or several passwords per connection;
  - spraying, one or two tries on each of many servers, is a different
    pattern and is not caught: each server's count stays low. A later
    detector could count servers per device;
  - a script that runs more than 30 git commands a minute against the same
    server, or an app that opens a new database connection for every
    request to a database on the internet (ports 1433, 3306, 5432), raises
    an alert. One `ignore_logins` entry silences that login only.

## Alternatives considered

- **Keep `local_targets_only = true` and write down why** (the other option
  the review offered): leaves the infected-device case unreported.
- **The same threshold (10) for both**: a burst of git commands or a
  deployment script against one server can make 10 quick connections in a
  minute.
- **Skip well-known services** (a list of GitHub addresses, for example):
  the list changes over time, and a guessing device could target those
  services too.
- **Silence scripts with `ignore_sources`**, as before: hides every other
  alert about that device, including scans.
