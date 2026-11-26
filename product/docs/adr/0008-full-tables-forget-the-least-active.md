# 0008. A full table forgets its least active entries, never the newcomer

Status: accepted
Date: 2026-11-26

## Context

Memory must stay bounded, so each detector follows at most 50,000 keys (for
the port scan detector, a key is a pair "scanner, target") and the flow
table at most 100,000 connections. In the first version, a full detector
simply ignored any new key. The review of phase 1 showed the problem: with
50,000 fake source addresses in the tables, a real 1,000-port scan went
unseen. A key stays for the 60-second window, so about 50,000 / 60 ≈ 830
packets per second keep the tables full, which any device on the network
can send. (The flow table already passed new connections on to the
detectors, but no longer recorded them.)

## Decision

- A full detector forgets the least active tenth of its keys before adding
  the newcomer. "Least active", in this order: keys without an open
  finding first, then keys with the fewest distinct values in their window,
  then keys quiet for longest. A finding forgotten this way still reports
  its last count.
- A full flow table ends the least recently active tenth of its flows (they
  are written out like any finished flow, marked "evicted") before adding
  the new one.
- Removing a tenth at once keeps the cost low: the entries are ranked once per
  5,000 (detectors) or 10,000 (flows) newcomers, not once per packet.
- Both are counted. The dashboard's health strip shows **Detector
  saturated** with the time it last happened (a warning for 10 minutes,
  then a quiet note), and the replay summary prints a line.

## Consequences

- A real scanner collects many distinct ports within seconds, so it stays
  while one-packet fake sources go. The review's attack is a test in
  `engine.rs`: 60,000 fake addresses, then a 1,000-port scan, which is found.
  With the old rule the same test fails.
- An attacker who wants to push out a key must now send entries that are
  more active than the real scanner's, which means a much bigger flood, and
  the flood itself shows up as **Detector saturated**.
- Under such a flood, some connections are written out before they end, so
  their records are incomplete. That is the price of bounded memory.

## Alternatives considered

- **Ignore newcomers when full** (the first version): an attacker can fill
  the table on purpose and attack unseen.
- **Remove the single oldest entry each time**: needs a sorted structure
  updated on every packet, more code for the same effect.
- **No limit**: a flood would use all the memory of the PC, or of the router
  later (the OpenWrt One has 1 GB).
