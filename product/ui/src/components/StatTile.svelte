<!-- One headline number with its label. The hero tile is the number the page leads with. -->
<script lang="ts">
  let {
    label,
    value,
    note = '',
    hero = false,
  }: { label: string; value: string; note?: string; hero?: boolean } = $props();
</script>

<div class="card tile" class:hero>
  <div class="label muted">{label}</div>
  <div class="value">{value}</div>
  {#if note}<div class="note muted">{note}</div>{/if}
</div>

<style>
  .tile {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .label {
    font-size: 0.85rem;
  }
  .value {
    font-size: 1.75rem;
    font-weight: 600;
    line-height: 1.15;
  }
  .hero .value {
    font-size: 3rem;
  }
  .note {
    font-size: 0.8rem;
  }
</style>
