<!--
  New alerts per time bucket, stacked by severity (low at the bottom,
  critical on top). Thin columns with a 2px gap between severities.
  Each column is its own hover target; arrow keys move between columns.
-->
<script lang="ts">
  import { formatDateTime, formatNumber, formatTick } from '../../lib/format';
  import { fmt, t } from '../../lib/i18n/index.svelte';
  import { columnPath, labelIndexes, niceTicks } from '../../lib/scale';
  import { SEVERITIES } from '../../lib/severity';
  import type { AlertPoint, Severity } from '../../lib/types';
  import Tooltip from './Tooltip.svelte';

  let { points, spanMs, label }: { points: AlertPoint[]; spanMs: number; label: string } = $props();

  const PLOT = 180;
  const TOP = 10;
  const AXIS = 26;
  const LEFT = 40;
  const RIGHT = 14;
  const GAP = 2;

  const COLORS: Record<Severity, string> = {
    low: 'var(--sev-low)',
    medium: 'var(--sev-medium)',
    high: 'var(--sev-high)',
    critical: 'var(--sev-critical)',
  };

  let width = $state(0);
  let active: number | null = $state(null);

  const totals = $derived(points.map((p) => SEVERITIES.reduce((sum, s) => sum + p[s], 0)));
  const ticks = $derived(niceTicks(Math.max(0, ...totals), 4, true));
  const top = $derived(ticks[ticks.length - 1] || 1);
  const plotWidth = $derived(Math.max(0, width - LEFT - RIGHT));
  const slot = $derived(points.length ? plotWidth / points.length : 0);
  const barWidth = $derived(Math.max(2, Math.min(24, slot * 0.7)));
  const xLabels = $derived(labelIndexes(points.length, Math.max(2, Math.floor(plotWidth / 110))));
  const y = (value: number) => TOP + PLOT - (value / top) * PLOT;
  const center = (i: number) => LEFT + slot * (i + 0.5);

  interface Segment {
    severity: Severity;
    path: string;
  }

  /** The visible pieces of one column, bottom to top. */
  function segments(point: AlertPoint, i: number): Segment[] {
    const present = SEVERITIES.filter((s) => point[s] > 0);
    const result: Segment[] = [];
    let base = y(0);
    present.forEach((severity, index) => {
      const height = (point[severity] / top) * PLOT;
      const isTop = index === present.length - 1;
      const drawn = isTop ? height : Math.max(1, height - GAP);
      const x = center(i) - barWidth / 2;
      const yTop = base - height + (isTop ? 0 : GAP);
      result.push({
        severity,
        path: isTop ? columnPath(x, base - height, barWidth, drawn) : `M${x},${yTop}h${barWidth}v${drawn}h${-barWidth}Z`,
      });
      base -= height;
    });
    return result;
  }

  function onKey(event: KeyboardEvent) {
    const last = points.length - 1;
    const now = active ?? last;
    const moves: Record<string, number> = { ArrowRight: now + 1, ArrowLeft: now - 1, Home: 0, End: last };
    if (event.key in moves) {
      event.preventDefault();
      active = Math.min(last, Math.max(0, moves[event.key] ?? now));
    } else if (event.key === 'Escape') {
      active = null;
    }
  }

  const current = $derived(active === null ? undefined : points[active]);
</script>

<ul class="legend">
  {#each [...SEVERITIES].reverse() as severity (severity)}
    <li><span class="swatch" style:background={COLORS[severity]}></span>{t(`severity.${severity}`)}</li>
  {/each}
</ul>
<div class="chart" dir="ltr" bind:clientWidth={width}>
  {#if width > 0 && points.length > 0}
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <svg
      {width}
      height={TOP + PLOT + AXIS}
      role="img"
      aria-label={label}
      tabindex="0"
      onkeydown={onKey}
      onfocus={() => (active ??= points.length - 1)}
      onblur={() => (active = null)}
      onpointerleave={() => (active = null)}
    >
      {#each ticks as tick (tick)}
        <line class="grid" x1={LEFT} x2={width - RIGHT} y1={y(tick)} y2={y(tick)} />
        <text class="tick num" x={LEFT - 8} y={y(tick)} dy="0.32em" text-anchor="end">{formatNumber(tick, fmt())}</text>
      {/each}
      {#each points as point, i (point.t)}
        <g class:dim={active !== null && active !== i}>
          {#each segments(point, i) as segment (segment.severity)}
            <path d={segment.path} fill={COLORS[segment.severity]} />
          {/each}
        </g>
        <rect
          class="hit"
          x={LEFT + slot * i}
          y={TOP}
          width={slot}
          height={PLOT}
          role="presentation"
          onpointerenter={() => (active = i)}
        />
      {/each}
      <line class="baseline" x1={LEFT} x2={width - RIGHT} y1={y(0)} y2={y(0)} />
      {#each xLabels as i (i)}
        <text class="tick" x={center(i)} y={TOP + PLOT + 18} text-anchor="middle">
          {formatTick(points[i]?.t ?? 0, spanMs, fmt())}
        </text>
      {/each}
    </svg>
    {#if active !== null && current}
      <Tooltip
        x={center(active)}
        y={TOP + PLOT / 2}
        {width}
        title={formatDateTime(current.t, fmt())}
        rows={[
          ...[...SEVERITIES].reverse().map((s) => ({
            label: t(`severity.${s}`),
            value: formatNumber(current[s], fmt()),
            key: COLORS[s],
          })),
          { label: t('chart.total'), value: formatNumber(totals[active] ?? 0, fmt()) },
        ]}
      />
    {/if}
  {/if}
</div>

<style>
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    margin: 0;
    padding: 0;
    list-style: none;
    font-size: 0.85rem;
    color: var(--ink-2);
  }
  .legend li {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .swatch {
    width: 10px;
    height: 10px;
    border-radius: 2px;
  }
  .chart {
    position: relative;
    min-height: 216px;
  }
  svg {
    display: block;
    overflow: visible;
  }
  .grid {
    stroke: var(--grid);
    shape-rendering: crispEdges;
  }
  .baseline {
    stroke: var(--axis);
    shape-rendering: crispEdges;
  }
  .tick {
    fill: var(--ink-2);
    font-size: 11px;
  }
  .hit {
    fill: transparent;
  }
  .dim {
    opacity: 0.55;
  }
</style>
