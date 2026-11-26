<!-- Shown when data could not be loaded, with a retry button. -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';

  let { message, onretry }: { message: string; onretry: () => void } = $props();
</script>

<div class="card error" role="alert">
  <p>{message === 'network' ? t('error.unreachable') : t('error.generic', { message })}</p>
  <button type="button" onclick={onretry}>{t('error.retry')}</button>
</div>

<style>
  .error {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
    border-inline-start: 3px solid var(--critical);
  }
  p {
    margin: 0;
  }
</style>
