<!-- The period selector. It writes the choice into the address (?range=…). -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { RANGES, withParams } from '../lib/ranges';
  import { router } from '../lib/router.svelte';
  import type { RangeLabel } from '../lib/types';

  let { value }: { value: RangeLabel } = $props();
</script>

<label class="range">
  <span class="muted">{t('range.label')}</span>
  <select
    {value}
    onchange={(event) =>
      router.go(withParams(router.path, router.search, { range: event.currentTarget.value }), true)}
  >
    {#each RANGES as range (range)}
      <option value={range}>{t(`range.${range}`)}</option>
    {/each}
  </select>
</label>

<style>
  .range {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
</style>
