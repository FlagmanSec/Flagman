# 0002. Keep the product in `product/` inside the CS395 repository

Status: accepted
Date: 2026-11-26

## Context

The product work happens in the `FlagmanSec/Flagman` repository, which also
holds the CS395 research project (notebooks, results, the paper's numbers).
The research has strict rules: its files and results must not change by
accident.

## Decision

Everything for the product lives under `product/`, with its own
`.gitignore`, documentation and changelog. The only file outside it is the
CI workflow (`.github/workflows/product-ci.yml`), because GitHub only reads
workflows from that folder; it runs only when `product/` changes.

## Consequences

- One repository for the team, with a clear boundary: a review can check
  that a product change touches nothing outside `product/`.
- The research README and files stay as they are.
- If the product needs its own repository later, `git filter-repo` (or
  `git subtree split`) can move `product/` out with its history.

## Alternatives considered

- **A new repository now**: cleaner, but the team asked to work in this one.
- **Mixing product code into `src/`**: would blur what the research results
  depend on.
