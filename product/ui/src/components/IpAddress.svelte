<!-- An IP address, marked "local" when it belongs to the home network.
     It links to the traffic page filtered on that address. -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { isLocal } from '../lib/net';
  import { link } from '../lib/router.svelte';

  let { ip, linked = true }: { ip: string; linked?: boolean } = $props();
</script>

{#if linked}
  <a class="ip mono ltr" href={`/flows?ip=${encodeURIComponent(ip)}`} onclick={link}>{ip}</a>
{:else}
  <span class="ip mono ltr">{ip}</span>
{/if}
{#if isLocal(ip)}<span class="tag">{t('common.local')}</span>{/if}

<style>
  .ip {
    white-space: nowrap;
  }
  .tag {
    margin-inline-start: 6px;
    font-size: 0.75rem;
    color: var(--ink-2);
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0 4px;
  }
</style>
