<!-- Severity as a shape, a colour and a word, so it never relies on colour alone. -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import type { Severity } from '../lib/types';

  let { severity }: { severity: Severity } = $props();
</script>

<span class="badge">
  <svg viewBox="0 0 12 12" width="12" height="12" aria-hidden="true" class={severity}>
    {#if severity === 'low'}
      <circle cx="6" cy="6" r="4.5" />
    {:else if severity === 'medium'}
      <path d="M6 1l5 5-5 5-5-5z" />
    {:else if severity === 'high'}
      <path d="M6 1l5.5 10H.5z" />
    {:else}
      <path d="M3.8 .5h4.4L11.5 3.8v4.4L8.2 11.5H3.8L.5 8.2V3.8z" />
    {/if}
  </svg>
  {t(`severity.${severity}`)}
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    white-space: nowrap;
    font-weight: 500;
  }
  svg {
    flex: none;
  }
  .low {
    fill: var(--sev-low);
  }
  .medium {
    fill: var(--sev-medium);
  }
  .high {
    fill: var(--sev-high);
  }
  .critical {
    fill: var(--sev-critical);
  }
</style>
