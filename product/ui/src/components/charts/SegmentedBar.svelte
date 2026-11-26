<!--
  One whole split into parts (for example the protocol mix), as a tall bar.
  Each block prints its share when it fits; the legend names the blocks.
  Hover a block for its exact amount; the table view lists everything.
-->
<script lang="ts">
  import Tooltip from './Tooltip.svelte';

  export interface Part {
    key: string;
    label: string;
    value: number;
    display: string;
    /** A CSS colour variable name such as "--series-1". */
    color: string;
    /** Text colour inside the block. */
    ink: string;
  }

  let {
    parts,
    label,
    formatShare,
    caption = '',
    legend = true,
  }: {
    parts: Part[];
    label: string;
    formatShare: (share: number) => string;
    /** A short name printed above the bar, when two bars are stacked. */
    caption?: string;
    /** Two stacked bars with the same parts share one legend. */
    legend?: boolean;
  } = $props();

  const GAP = 2;
  let width = $state(0);
  let active: string | null = $state(null);
  let pointer = $state({ x: 0, y: 0 });

  const visible = $derived(parts.filter((part) => part.value > 0));
  const total = $derived(visible.reduce((sum, part) => sum + part.value, 0));

  function blockWidth(part: Part): number {
    const room = width - GAP * Math.max(0, visible.length - 1);
    return total ? (room * part.value) / total : 0;
  }

  function fits(part: Part): boolean {
    return blockWidth(part) >= formatShare(part.value / total).length * 8 + 14;
  }

  const current = $derived(visible.find((part) => part.key === active));
</script>

{#if caption}<p class="caption">{caption}</p>{/if}
<div class="wrap" dir="ltr" bind:clientWidth={width}>
  <div class="bar" role="img" aria-label={label}>
    {#each visible as part (part.key)}
      <span
        class="block"
        role="img"
        aria-label={`${part.label}: ${part.display} (${formatShare(part.value / total)})`}
        style:flex-grow={part.value}
        style:background={`var(${part.color})`}
        style:color={part.ink}
        onpointerenter={(event) => {
          active = part.key;
          pointer = { x: event.offsetX + (event.currentTarget as HTMLElement).offsetLeft, y: 14 };
        }}
        onpointerleave={() => (active = null)}
      >
        {#if fits(part)}{formatShare(part.value / total)}{/if}
      </span>
    {/each}
  </div>
  {#if current}
    <Tooltip
      x={pointer.x}
      y={pointer.y + 46}
      {width}
      title={current.label}
      rows={[{ label: formatShare(current.value / total), value: current.display }]}
    />
  {/if}
</div>
{#if legend}
  <ul class="legend">
    {#each visible as part (part.key)}
      <li><span class="swatch" style:background={`var(${part.color})`}></span>{part.label}</li>
    {/each}
  </ul>
{/if}

<style>
  .caption {
    margin: 0 0 4px;
    font-size: 0.8rem;
    color: var(--ink-2);
  }
  .wrap {
    position: relative;
  }
  .bar {
    display: flex;
    gap: 2px;
    height: 28px;
  }
  .block {
    flex-basis: 0;
    min-width: 2px;
    border-radius: 4px;
    font-size: 0.8rem;
    font-weight: 600;
    line-height: 28px;
    padding-inline-start: 7px;
    white-space: nowrap;
    overflow: visible;
  }
  .legend {
    display: flex;
    flex-wrap: wrap;
    gap: 4px 14px;
    margin: 10px 0 0;
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
</style>
