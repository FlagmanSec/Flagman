<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { link } from '../lib/router.svelte';
</script>

<section class="card">
  <h1>{t('notfound.title')}</h1>
  <p><a href="/" onclick={link}>{t('notfound.back')}</a></p>
</section>
