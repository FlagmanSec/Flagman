<!-- The floating box shown on hover or keyboard focus. Values come first and
     stand out; labels follow, quieter. -->
<script lang="ts">
  export interface TooltipRow {
    label: string;
    value: string;
    /** CSS colour of the short line key beside the row, if any. */
    key?: string;
  }

  let {
    x,
    y,
    width,
    title,
    rows,
  }: { x: number; y: number; width: number; title: string; rows: TooltipRow[] } = $props();

  // Stay inside the chart: flip to the left of the pointer near the right edge.
  const flip = $derived(x > width - 190);
</script>

<div class="tooltip" style:top="{y}px" style:left={flip ? 'auto' : `${x + 14}px`} style:right={flip ? `${width - x + 14}px` : 'auto'} role="status">
  <div class="title">{title}</div>
  {#each rows as row (row.label)}
    <div class="row">
      {#if row.key}<span class="key" style:background={row.key}></span>{/if}
      <strong class="num">{row.value}</strong>
      <span class="muted">{row.label}</span>
    </div>
  {/each}
</div>

<style>
  .tooltip {
    position: absolute;
    z-index: 5;
    pointer-events: none;
    min-width: 140px;
    max-width: 240px;
    padding: 8px 10px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 8px;
    box-shadow: 0 4px 16px rgba(0, 0, 0, 0.12);
    font-size: 0.85rem;
    transform: translateY(-50%);
  }
  .title {
    color: var(--ink-2);
    margin-bottom: 4px;
    white-space: nowrap;
  }
  .row {
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .key {
    width: 12px;
    height: 2px;
    border-radius: 1px;
    flex: none;
  }
</style>
