<!--
  One series over time, as a line with a light wash under it.
  Hover (or focus and use the arrow keys) to read any point: a vertical line
  snaps to the nearest time and the tooltip lists the value and its parts.
-->
<script lang="ts">
  import { formatDateTime, formatNumber, formatTick } from '../../lib/format';
  import { fmt } from '../../lib/i18n/index.svelte';
  import { textWidth } from '../../lib/measure';
  import { labelIndexes, nearestIndex, niceTicks } from '../../lib/scale';
  import Tooltip, { type TooltipRow } from './Tooltip.svelte';

  export interface TimePoint {
    t: number;
    value: number;
    /** Extra lines for the tooltip (for example the share of each protocol). */
    parts: TooltipRow[];
  }

  let {
    points,
    spanMs,
    label,
    valueLabel,
    formatValue,
    formatAxis,
  }: {
    points: TimePoint[];
    spanMs: number;
    label: string;
    valueLabel: string;
    formatValue: (value: number) => string;
    formatAxis: (value: number) => string;
  } = $props();

  const PLOT = 200;
  const TOP = 10;
  const AXIS = 26;
  const RIGHT = 14;

  let width = $state(0);
  let svg: SVGSVGElement | undefined = $state();
  let active: number | null = $state(null);

  const ticks = $derived(niceTicks(Math.max(0, ...points.map((p) => p.value))));
  const tickLabels = $derived(ticks.map((tick) => (tick === 0 ? formatNumber(0, fmt()) : formatAxis(tick))));
  // Room on the left for the longest axis label, plus a small gap.
  const left = $derived(Math.max(40, Math.ceil(Math.max(0, ...tickLabels.map((l) => textWidth(l)))) + 14));
  const plotWidth = $derived(Math.max(0, width - left - RIGHT));
  const top = $derived(ticks[ticks.length - 1] || 1);
  const x = (i: number) => left + (points.length <= 1 ? plotWidth / 2 : (i * plotWidth) / (points.length - 1));
  const y = (value: number) => TOP + PLOT - (value / top) * PLOT;
  const line = $derived(points.map((p, i) => `${i ? 'L' : 'M'}${x(i)},${y(p.value)}`).join(' '));
  const area = $derived(
    points.length > 1 ? `${line} L${x(points.length - 1)},${y(0)} L${x(0)},${y(0)} Z` : '',
  );
  const xLabels = $derived(labelIndexes(points.length, Math.max(2, Math.floor(plotWidth / 110))));
  const current = $derived(active === null ? undefined : points[active]);

  function anchor(i: number): 'start' | 'middle' | 'end' {
    if (x(i) < left + 30) return 'start';
    if (x(i) > width - RIGHT - 30) return 'end';
    return 'middle';
  }

  function onMove(event: PointerEvent) {
    if (!svg) return;
    const box = svg.getBoundingClientRect();
    active = nearestIndex(event.clientX - box.left, left, plotWidth, points.length);
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
</script>

<div class="chart" dir="ltr" bind:clientWidth={width}>
  {#if width > 0 && points.length > 0}
    <!-- The chart takes keyboard focus so arrow keys can move the cursor; the
         table view (card button) is the full accessible alternative. -->
    <!-- svelte-ignore a11y_no_noninteractive_tabindex, a11y_no_noninteractive_element_interactions -->
    <svg
      bind:this={svg}
      {width}
      height={TOP + PLOT + AXIS}
      role="img"
      aria-label={label}
      tabindex="0"
      onpointermove={onMove}
      onpointerleave={() => (active = null)}
      onkeydown={onKey}
      onfocus={() => (active ??= points.length - 1)}
      onblur={() => (active = null)}
    >
      {#each ticks as tick, i (tick)}
        <line class="grid" x1={left} x2={width - RIGHT} y1={y(tick)} y2={y(tick)} />
        <text class="tick num" x={left - 8} y={y(tick)} dy="0.32em" text-anchor="end">{tickLabels[i]}</text>
      {/each}
      <path class="area" d={area} />
      <path class="line" d={line} />
      <line class="baseline" x1={left} x2={width - RIGHT} y1={y(0)} y2={y(0)} />
      {#each xLabels as i (i)}
        <text class="tick" x={x(i)} y={TOP + PLOT + 18} text-anchor={anchor(i)}>
          {formatTick(points[i]?.t ?? 0, spanMs, fmt())}
        </text>
      {/each}
      {#if active !== null && current}
        <line class="crosshair" x1={x(active)} x2={x(active)} y1={TOP} y2={TOP + PLOT} />
        <circle class="marker" cx={x(active)} cy={y(current.value)} r="4" />
      {/if}
    </svg>
    {#if active !== null && current}
      <Tooltip
        x={x(active)}
        y={Math.max(40, y(current.value))}
        {width}
        title={formatDateTime(current.t, fmt())}
        rows={[{ label: valueLabel, value: formatValue(current.value) }, ...current.parts]}
      />
    {/if}
  {/if}
</div>

<style>
  .chart {
    position: relative;
    min-height: 236px;
  }
  svg {
    display: block;
    overflow: visible;
  }
  .grid {
    stroke: var(--grid);
    stroke-width: 1;
    shape-rendering: crispEdges;
  }
  .baseline {
    stroke: var(--axis);
    stroke-width: 1;
    shape-rendering: crispEdges;
  }
  .tick {
    fill: var(--ink-2);
    font-size: 11px;
  }
  .area {
    fill: var(--series-1-wash);
  }
  .line {
    fill: none;
    stroke: var(--series-1);
    stroke-width: 2;
    stroke-linejoin: round;
    stroke-linecap: round;
  }
  .crosshair {
    stroke: var(--axis);
    stroke-width: 1;
  }
  .marker {
    fill: var(--series-1);
    stroke: var(--surface);
    stroke-width: 2;
  }
</style>
