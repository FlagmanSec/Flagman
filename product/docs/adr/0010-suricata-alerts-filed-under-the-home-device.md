# 0010. File Suricata alerts from the internet under the home device

Status: accepted
Date: 2026-11-26

## Context

Incidents group alerts by host. For Flagman's own detectors the host is the
alert's source: the scanner or the password guesser. Suricata rules are
different: many match the *answer* of a server. Suricata's own test
(`curl http://testmynids.org/uid/index.html`, rule 2100498) raises an alert
whose source is the testmynids.org server. The review of phase 1 pointed
out that this opened an incident "from" an outside server, and alerts about
one PC were split across one incident per server.

## Decision

- A Suricata alert whose source is outside the home network and whose
  destination is inside is filed under the destination: your device.
- Every other alert stays filed under its source, including scans from the
  internet (the scanner is the one to look at).
- The alert itself keeps its real source and destination, so the incident
  page still says which server sent the matching traffic.
- The dashboard calls the incident's device **Host** instead of **Source**.
  The database column keeps its name (`src_ip`), so existing files stay
  valid.

## Consequences

- One PC's Suricata alerts make one incident, whichever servers were
  involved, which is what the owner can act on.
- An attacker on the internet who scans a forwarded port *and* triggers a
  Suricata rule appears in two incidents: one under the attacker (the scan)
  and one under your device (the rule).
- "Inside" means a private address (10/8, 172.16/12, 192.168/16, fc00::/7,
  link-local). A device reached through a public IPv6 address is not
  recognised yet; a configurable home network, like Suricata's `HOME_NET`,
  is planned for phase 2.

## Alternatives considered

- **Keep grouping by source**: the problem from the review.
- **Use Suricata's own `source`/`target` fields**: Suricata fills
  `alert.source` and `alert.target` only "if target keyword is used in the
  signature" ([EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html),
  [`target` keyword](https://docs.suricata.io/en/latest/rules/meta.html)).
  We have not counted how many ET Open rules use it, so Flagman cannot rely
  on it. When an alert does carry these fields, using them is a possible
  improvement for phase 2.
