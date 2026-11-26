# 0007. Require a token for the API, even on localhost

Status: accepted
Date: 2026-11-26

## Context

The API listens on `127.0.0.1`, so other machines cannot reach it. But any
web page open in the owner's browser can send requests to
`http://127.0.0.1:8750`, and a DNS-rebinding page can even read the answers
if nothing else stops it. Other user accounts on the same PC can reach
localhost too. The data (who talks to whom, alerts) is private.

## Decision

- On first start, `flagmand` creates a random token: 32 bytes from the
  operating system's random generator, written as 64 hexadecimal
  characters, in `/var/lib/flagman/api-token` with mode `0600`.
- Every `/api/` route requires `Authorization: Bearer <token>`. The
  comparison does not stop at the first different character, so timing does
  not reveal the token.
- `flagmand` prints the link as `http://127.0.0.1:8750/#token=…`. The part
  after `#` is never sent to the server. The dashboard reads it, keeps it for
  the tab (or on the computer if the person asks), and removes it from the
  address bar.
- Security headers on every response: a strict Content Security Policy, no
  framing by other sites, no referrer.

## Consequences

- A malicious page cannot read the API: browsers never add our
  `Authorization` header to a cross-site request, and the API allows no
  cross-origin reads.
- Anyone who has the link has full access, so it must not be shared.
  Deleting the token file and restarting Flagman creates a new one.
- No accounts yet: everyone with the token is the same user.

## Alternatives considered

- **No authentication on localhost**: open to the browser attacks above.
- **Cookies and a login form**: needs CSRF protection and password storage.
  Worth doing when Flagman has several users.
- **Client certificates**: strong, but too hard to set up for a home user.
