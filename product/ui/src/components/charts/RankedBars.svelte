<!--
  Ranked horizontal bars: one row per item, largest first, one colour.
  Every row prints its value, so nothing depends on hovering.
-->
<script lang="ts">
  import { link } from '../../lib/router.svelte';

  export interface RankedRow {
    key: string;
    label: string;
    /** Shown after the label in a quieter style (for example "local"). */
    tag?: string;
    value: number;
    display: string;
    href?: string;
    /** Monospace label (IP addresses). Also kept left-to-right. */
    mono?: boolean;
    /** Keep the label left-to-right in Arabic, for "22 (SSH)". */
    ltr?: boolean;
  }

  let { rows, label }: { rows: RankedRow[]; label: string } = $props();

  const max = $derived(Math.max(1, ...rows.map((row) => row.value)));
</script>

<ol class="ranked" aria-label={label}>
  {#each rows as row (row.key)}
    <li>
      <span class="name" class:mono={row.mono}>
        {#if row.href}
          <a href={row.href} onclick={link} class:ltr={row.mono || row.ltr}>{row.label}</a>
        {:else}
          <span class:ltr={row.mono || row.ltr}>{row.label}</span>
        {/if}
        {#if row.tag}<span class="tag">{row.tag}</span>{/if}
      </span>
      <span class="track" aria-hidden="true">
        <span class="bar" style:width="{Math.max(0.5, (row.value / max) * 100)}%"></span>
      </span>
      <span class="value num">{row.display}</span>
    </li>
  {/each}
</ol>

<style>
  .ranked {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }
  li {
    display: grid;
    grid-template-columns: minmax(0, 10.5rem) minmax(0, 1fr) auto;
    align-items: center;
    gap: 10px;
    padding: 2px 4px;
    border-radius: 6px;
  }
  li:hover {
    background: var(--surface-hover);
  }
  .name {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    font-size: 0.9rem;
  }
  .tag {
    margin-inline-start: 6px;
    font-size: 0.75rem;
    color: var(--ink-2);
    font-family: var(--font);
  }
  .track {
    display: block;
    height: 14px;
  }
  .bar {
    display: block;
    height: 100%;
    background: var(--series-1);
    border-start-end-radius: 4px;
    border-end-end-radius: 4px;
  }
  .value {
    font-size: 0.9rem;
    min-width: 4.5rem;
    text-align: end;
  }
  @media (max-width: 480px) {
    li {
      grid-template-columns: minmax(0, 1fr) auto;
    }
    .name {
      grid-column: 1 / -1;
    }
  }
</style>
