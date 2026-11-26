# 0006. Svelte dashboard with hand-made SVG charts and a checked palette

Status: accepted
Date: 2026-11-26

## Context

The dashboard must feel like a security console (in the spirit of
Suricata's dashboards) and still be clear to someone who is not an expert.
It must work without internet access, be light enough to be served by a
router later, and work in English, French and Arabic (right to left), in
light and dark themes, on a phone too. Charts must not rely on colour alone,
because many people have some colour-vision deficiency.

## Decision

- **Svelte 5 with Vite**, compiled to static files that `flagmand` serves.
  No SvelteKit, no server-side code, no files loaded from the internet.
- **Charts drawn by hand in SVG**: time series with a crosshair and keyboard
  support, stacked columns, ranked bars, a split bar.
  Every chart has a **table view**.
- **Colours** are variables in `ui/src/app.css`, defined for light and dark.
  The five categorical colours (one per protocol) were checked with a
  colour-vision simulation script for separation in both themes. In light
  mode some are low-contrast against white, so every chart also prints its
  values or names, and has the table view.
- **Severity** uses the reserved status colours, always with a shape and a
  word: grey circle (low), yellow diamond (medium), orange triangle (high),
  red octagon (critical).
- **Language**: all text is in `ui/src/lib/i18n/` (one file per language).
  Numbers, dates and sizes are formatted by the browser's `Intl` library.
  Arabic uses Western digits, like IP addresses, and values inside Arabic
  sentences are wrapped in Unicode isolates so they keep their order.

## Consequences

- The built dashboard is small: `npm run build` prints its size (about
  45 kB of JavaScript once compressed, at the time of writing).
- No chart library to update or audit, but more code of our own to test.
- Adding a language means adding one file; a test checks that every
  language has every message with the same placeholders.

## Alternatives considered

- **Grafana or Kibana**: complete, but separate servers, far too heavy for a
  router, and not written for non-experts.
- **React with a chart library**: fine, but a larger bundle and more
  dependencies for the same result.
