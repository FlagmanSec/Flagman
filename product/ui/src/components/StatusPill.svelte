<!-- An incident's review status: open, confirmed, false positive, resolved. -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import type { IncidentStatus } from '../lib/types';

  let { status }: { status: IncidentStatus } = $props();
</script>

<span class="pill {status}">{t(`status.${status}`)}</span>

<style>
  .pill {
    display: inline-block;
    padding: 1px 8px;
    border-radius: 999px;
    border: 1px solid var(--border);
    font-size: 0.85rem;
    white-space: nowrap;
  }
  .open {
    border-color: var(--ink-2);
    font-weight: 600;
  }
  .false_positive,
  .resolved {
    color: var(--ink-2);
  }
</style>
