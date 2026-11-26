<!-- All incidents in a period, filterable by severity and review status. -->
<script lang="ts">
  import ErrorBox from '../components/ErrorBox.svelte';
  import IpAddress from '../components/IpAddress.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import SeverityBadge from '../components/SeverityBadge.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import { api } from '../lib/api';
  import { formatNumber, formatTime } from '../lib/format';
  import { fmt, t } from '../lib/i18n/index.svelte';
  import { poll } from '../lib/poll.svelte';
  import { parseRange, withParams } from '../lib/ranges';
  import { link, router } from '../lib/router.svelte';
  import { SEVERITIES } from '../lib/severity';
  import type { IncidentStatus, Severity } from '../lib/types';

  let { replay }: { replay: boolean } = $props();

  const STATUSES: IncidentStatus[] = ['open', 'confirmed', 'false_positive', 'resolved'];

  const range = $derived(parseRange(router.params.get('range'), '7d'));
  const minSeverity = $derived(
    (SEVERITIES.find((s) => s === router.params.get('severity')) ?? '') as Severity | '',
  );
  const status = $derived((STATUSES.find((s) => s === router.params.get('status')) ?? '') as IncidentStatus | '');

  const list = poll(
    () => api.incidents({ range, min_severity: minSeverity, status, limit: 500 }),
    () => (replay ? 60_000 : 15_000),
  );

  function setFilter(name: string, value: string) {
    router.go(withParams(router.path, router.search, { [name]: value }), true);
  }
</script>

<div class="filters">
  <RangePicker value={range} />
  <label>
    <span class="muted">{t('incidents.severity')}</span>
    <select value={minSeverity} onchange={(event) => setFilter('severity', event.currentTarget.value)}>
      <option value="">{t('incidents.any_severity')}</option>
      {#each SEVERITIES.slice(1) as s (s)}
        <option value={s}>{t('incidents.at_least', { severity: t(`severity.${s}`) })}</option>
      {/each}
    </select>
  </label>
  <label>
    <span class="muted">{t('incidents.status')}</span>
    <select value={status} onchange={(event) => setFilter('status', event.currentTarget.value)}>
      <option value="">{t('incidents.any_status')}</option>
      {#each STATUSES as s (s)}
        <option value={s}>{t(`status.${s}`)}</option>
      {/each}
    </select>
  </label>
</div>

<section class="card">
  <h1>{t('incidents.title')}</h1>
  {#if list.error && !list.data}
    <ErrorBox message={list.error} onretry={list.refresh} />
  {:else if !list.data}
    <p class="muted">{t('common.loading')}</p>
  {:else if list.data.length === 0}
    <p class="muted empty">{t('incidents.none')}</p>
  {:else}
    <p class="muted count">{t('incidents.shown', { count: formatNumber(list.data.length, fmt()) })}</p>
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('col.severity')}</th>
            <th>{t('col.incident')}</th>
            <th>{t('col.source')}</th>
            <th>{t('col.targets')}</th>
            <th class="num">{t('col.alerts')}</th>
            <th>{t('col.started')}</th>
            <th>{t('col.last_activity')}</th>
            <th>{t('col.status')}</th>
          </tr>
        </thead>
        <tbody>
          {#each list.data as incident (incident.id)}
            <tr>
              <td><SeverityBadge severity={incident.severity} /></td>
              <td>
                <a href={`/incidents/${incident.id}`} onclick={link}>
                  <span class="num">#{incident.id}</span>
                  {incident.kinds.map((kind) => t(`kind.${kind}`)).join(', ')}
                </a>
              </td>
              <td><IpAddress ip={incident.src_ip} /></td>
              <td>
                {#each incident.targets.slice(0, 2) as target (target)}
                  <div class="mono ltr">{target}</div>
                {/each}
                {#if incident.targets.length > 2}
                  <div class="muted">{t('common.more', { count: incident.targets.length - 2 })}</div>
                {/if}
              </td>
              <td class="num">{formatNumber(incident.alert_count, fmt())}</td>
              <td class="time">{formatTime(incident.first_seen, fmt())}</td>
              <td class="time">{formatTime(incident.last_seen, fmt())}</td>
              <td><StatusPill status={incident.status} /></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</section>

<style>
  .filters {
    display: flex;
    flex-wrap: wrap;
    gap: 8px 16px;
    align-items: center;
  }
  label {
    display: inline-flex;
    align-items: center;
    gap: 8px;
  }
  .card {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .count {
    margin: 0;
    font-size: 0.85rem;
  }
  .empty {
    margin: 24px 0;
  }
</style>
