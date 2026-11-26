<!-- The signed-in layout: header, sensor status, and the current page. -->
<script lang="ts">
  import { api } from '../lib/api';
  import { t } from '../lib/i18n/index.svelte';
  import { poll } from '../lib/poll.svelte';
  import { link, router } from '../lib/router.svelte';
  import HealthStrip from './HealthStrip.svelte';
  import Settings from './Settings.svelte';
  import Overview from '../pages/Overview.svelte';
  import Incidents from '../pages/Incidents.svelte';
  import IncidentDetail from '../pages/IncidentDetail.svelte';
  import Flows from '../pages/Flows.svelte';
  import NotFound from '../pages/NotFound.svelte';

  let { onsignout }: { onsignout: () => void } = $props();

  const health = poll(() => api.health(), () => 5_000);
  const replay = $derived(health.data?.clock === 'latest_data');

  const pages = [
    { href: '/', name: 'overview', label: 'nav.overview' },
    { href: '/incidents', name: 'incidents', label: 'nav.incidents' },
    { href: '/flows', name: 'flows', label: 'nav.flows' },
  ] as const;

  function current(name: string): boolean {
    const route = router.route.name;
    return route === name || (name === 'incidents' && route === 'incident');
  }
</script>

<header>
  <div class="bar">
    <a class="brand" href="/" onclick={link}>
      <img src="/favicon.svg" alt="" width="26" height="26" />
      <span>{t('app.name')}</span>
    </a>
    <nav aria-label={t('nav.main')}>
      {#each pages as page (page.name)}
        <a href={page.href} onclick={link} aria-current={current(page.name) ? 'page' : undefined}>
          {t(page.label)}
        </a>
      {/each}
    </nav>
    <div class="tools">
      <Settings />
      <button type="button" class="signout" onclick={onsignout}>{t('signin.signout')}</button>
    </div>
  </div>
</header>

<main>
  <HealthStrip health={health.data} error={health.error} />
  {#if router.route.name === 'overview'}
    <Overview {replay} />
  {:else if router.route.name === 'incidents'}
    <Incidents {replay} />
  {:else if router.route.name === 'incident'}
    {#key router.route.id}
      <IncidentDetail id={router.route.id} {replay} />
    {/key}
  {:else if router.route.name === 'flows'}
    <Flows {replay} />
  {:else}
    <NotFound />
  {/if}
</main>

<style>
  header {
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    position: sticky;
    top: 0;
    z-index: 10;
  }
  .bar {
    max-width: 1280px;
    margin: 0 auto;
    padding: 8px 16px;
    display: flex;
    align-items: center;
    gap: 16px;
    flex-wrap: wrap;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 8px;
    font-weight: 700;
    color: var(--ink);
    font-size: 1.05rem;
  }
  .brand:hover {
    text-decoration: none;
  }
  nav {
    display: flex;
    gap: 4px;
    flex: 1;
    flex-wrap: wrap;
  }
  nav a {
    color: var(--ink-2);
    padding: 6px 10px;
    border-radius: 8px;
  }
  nav a:hover {
    background: var(--surface-hover);
    text-decoration: none;
  }
  nav a[aria-current='page'] {
    color: var(--ink);
    font-weight: 600;
    background: var(--surface-hover);
  }
  .tools {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .signout {
    min-height: 32px;
    padding: 4px 10px;
  }
  main {
    max-width: 1280px;
    margin: 0 auto;
    padding: 16px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
</style>
