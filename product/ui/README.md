# Flagman dashboard (Svelte)

The web dashboard. It is compiled to static files in `dist/`, which
`flagmand` serves next to the API. Nothing is loaded from the internet.
Why it is built this way: [ADR 0006](../docs/adr/0006-svelte-dashboard-and-charts.md).

## Commands

Needs Node.js 20.19 or newer.

```bash
npm ci            # install the exact versions from package-lock.json
npm run dev       # development server with live reload (see below)
npm run check     # type checks; fails on any warning
npm test          # unit tests (vitest)
npm run build     # the production files, in dist/
```

`npm run dev` sends `/api` calls to a running sensor, by default
`http://127.0.0.1:8750`. To use replay data instead:

```bash
cd ../core && cargo run -p flagmand -- replay testdata/pcap/lab-attack-chain.pcap --overwrite --serve
# in another terminal, from product/ui:
FLAGMAN_API=http://127.0.0.1:8751 npm run dev
```

Open the address Vite prints and paste the token that `flagmand` printed.

## Folders

| Folder | What is inside |
|---|---|
| `src/pages/` | One file per page: overview, incidents, one incident, traffic (flows) |
| `src/components/` | The page frame, sign-in, settings, badges, tiles |
| `src/components/charts/` | The hand-made SVG charts and their tooltip |
| `src/lib/` | API calls, types, routing, formatting, token handling, chart maths |
| `src/lib/i18n/` | Every sentence, in English (`en.ts`, the reference), French and Arabic |
| `src/app.css` | Colours (light and dark) and base styles |

## Rules for changes

- **Text** goes in `src/lib/i18n/en.ts` first, then `fr.ts` and `ar.ts`. The
  type checker refuses a missing key, and a test refuses a translation whose
  `{placeholders}` differ from English.
- **Numbers, sizes, dates** go through `src/lib/format.ts`, never by hand.
- **Colours** come from the variables in `app.css`. Severity always shows a
  shape and a word, never colour alone. Protocols keep the same colour on
  every chart.
- **Every chart** has a table view (the "Table" button of `ChartCard`).
- **Right to left**: use `margin-inline-start` rather than `margin-left`,
  the `.ltr` class for IP addresses and ports, and `.flip-rtl` for arrows.
- **No `{@html}`**: all text is escaped by Svelte. The server's Content
  Security Policy blocks inline scripts anyway.
