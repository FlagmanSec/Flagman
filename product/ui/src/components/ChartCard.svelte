<!-- A titled card holding a chart, with a button to show the same data as a table
     (the accessible version of every chart). -->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import { t } from '../lib/i18n/index.svelte';

  let {
    title,
    subtitle = '',
    controls,
    chart,
    table,
  }: {
    title: string;
    subtitle?: string;
    controls?: Snippet;
    chart: Snippet;
    table?: Snippet;
  } = $props();

  let showTable = $state(false);
</script>

<section class="card chart-card">
  <div class="head">
    <div>
      <h2>{title}</h2>
      {#if subtitle}<p class="muted sub">{subtitle}</p>{/if}
    </div>
    <div class="actions">
      {@render controls?.()}
      {#if table}
        <button type="button" class="toggle" aria-pressed={showTable} onclick={() => (showTable = !showTable)}>
          {showTable ? t('chart.show_chart') : t('chart.show_table')}
        </button>
      {/if}
    </div>
  </div>
  {#if showTable && table}
    <div class="table-wrap">{@render table()}</div>
  {:else}
    {@render chart()}
  {/if}
</section>

<style>
  .chart-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .head {
    display: flex;
    justify-content: space-between;
    align-items: flex-start;
    gap: 12px;
    flex-wrap: wrap;
  }
  .sub {
    margin: 2px 0 0;
    font-size: 0.85rem;
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
  }
  .toggle {
    min-height: 30px;
    padding: 2px 10px;
    font-size: 0.85rem;
  }
</style>
