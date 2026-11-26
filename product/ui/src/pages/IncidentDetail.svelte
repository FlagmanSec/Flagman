<!--
  One incident: what happened in plain words, why it matters, what to check,
  the evidence behind each alert, and the connections involved. The buttons
  record the review (confirmed, false positive, resolved).
-->
<script lang="ts">
  import ErrorBox from '../components/ErrorBox.svelte';
  import IpAddress from '../components/IpAddress.svelte';
  import SeverityBadge from '../components/SeverityBadge.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import { api, ApiError } from '../lib/api';
  import { tacticUrl, techniqueUrl } from '../lib/attack';
  import { advice, storyLines } from '../lib/explain';
  import {
    formatBytes,
    formatDateTime,
    formatDuration,
    formatList,
    formatNumber,
    formatTime,
  } from '../lib/format';
  import { fmt, t } from '../lib/i18n/index.svelte';
  import { errorMessage, poll } from '../lib/poll.svelte';
  import { link } from '../lib/router.svelte';
  import { portLabel } from '../lib/services';
  import type { AlertRow, IncidentStatus } from '../lib/types';

  let { id, replay }: { id: number; replay: boolean } = $props();

  const detail = poll(
    () => api.incident(id),
    () => (replay ? 60_000 : 15_000),
  );
  const data = $derived(detail.data);
  const notFound = $derived(detail.error === 'not found' || detail.error === 'Not Found');

  const story = $derived(data ? storyLines(data.alerts, t, (n) => formatNumber(n, fmt())) : []);
  const tips = $derived(data ? advice(data.alerts, t) : []);
  const attacks = $derived.by(() => {
    const seen = new Map<string, AlertRow['attack']>();
    for (const alert of data?.alerts ?? []) {
      if (alert.attack && !seen.has(alert.attack.technique_id)) seen.set(alert.attack.technique_id, alert.attack);
    }
    return [...seen.values()].filter((attack) => attack !== null);
  });

  let saving = $state(false);
  let saveError: string | null = $state(null);

  async function mark(status: IncidentStatus) {
    saving = true;
    saveError = null;
    try {
      await api.setStatus(id, status);
      await detail.refresh();
    } catch (error) {
      saveError = error instanceof ApiError ? error.message : errorMessage(error);
    } finally {
      saving = false;
    }
  }

  const ACTIONS: IncidentStatus[] = ['confirmed', 'false_positive', 'resolved'];

  // A scan makes hundreds of connections: show the first few, the rest on request.
  const FIRST_FLOWS = 25;
  let allFlows = $state(false);
  const flows = $derived(allFlows ? (data?.flows ?? []) : (data?.flows ?? []).slice(0, FIRST_FLOWS));
</script>

<a class="back" href="/incidents" onclick={link}><span class="flip-rtl" aria-hidden="true">←</span> {t('incident.back')}</a>

{#if detail.error && !data}
  {#if notFound}
    <section class="card"><p>{t('incident.not_found')}</p></section>
  {:else}
    <ErrorBox message={detail.error} onretry={detail.refresh} />
  {/if}
{:else if !data}
  <p class="muted">{t('common.loading')}</p>
{:else}
  {@const incident = data.incident}
  <section class="card head">
    <div class="title-row">
      <h1>{t('incident.title', { id: `#${incident.id}` })}</h1>
      <SeverityBadge severity={incident.severity} />
      <StatusPill status={incident.status} />
    </div>
    <p class="summary">{formatList(incident.kinds.map((kind) => t(`kind.${kind}`)), fmt())}</p>
    <dl class="facts">
      <div>
        <dt>{t('incident.host')}</dt>
        <dd><IpAddress ip={incident.src_ip} /></dd>
      </div>
      <div>
        <dt>{t('incident.when')}</dt>
        <dd>
          <span class="num">{formatDateTime(incident.first_seen, fmt())}</span>
          <span class="muted lasted">{t('incident.lasted', { duration: formatDuration(incident.last_seen - incident.first_seen, fmt()) })}</span>
        </dd>
      </div>
      <div>
        <dt>{t('incident.targets')}</dt>
        <dd>
          {#each incident.targets as target (target)}
            <div><IpAddress ip={target} /></div>
          {:else}
            <span class="muted">–</span>
          {/each}
        </dd>
      </div>
      <div>
        <dt>{t('incident.tactics')}</dt>
        <dd>{incident.tactics.length ? formatList(incident.tactics, fmt()) : '–'}</dd>
      </div>
    </dl>
    <div class="actions">
      <span class="muted">{t('incident.mark')}</span>
      {#each ACTIONS as action (action)}
        <button
          type="button"
          disabled={saving || incident.status === action}
          aria-pressed={incident.status === action}
          onclick={() => mark(action)}>{t(`status.${action}`)}</button
        >
      {/each}
      {#if incident.status !== 'open'}
        <button type="button" disabled={saving} onclick={() => mark('open')}>{t('incident.reopen')}</button>
      {/if}
    </div>
    {#if saveError}<p class="error" role="alert">{t('error.generic', { message: saveError })}</p>{/if}
  </section>

  <div class="columns">
    <section class="card">
      <h2>{t('incident.story')}</h2>
      <ol class="story">
        {#each story as line (line.alert.id)}
          <li>
            <span class="time num muted">{formatTime(line.alert.first_seen, fmt())}</span>
            <div>
              <p>{line.text}</p>
              <div class="meta">
                <SeverityBadge severity={line.alert.severity} />
                {#if line.alert.attack}
                  {@const url = techniqueUrl(line.alert.attack.technique_id)}
                  {#if url}
                    <a href={url} target="_blank" rel="noopener noreferrer" title={t('common.external')}>
                      {line.alert.attack.technique_id} {line.alert.attack.technique}
                    </a>
                  {/if}
                {/if}
              </div>
            </div>
          </li>
        {/each}
      </ol>
    </section>

    <section class="card">
      <h2>{t('incident.why')}</h2>
      {#each tips as tip (tip.kind)}
        <p>{tip.why}</p>
      {/each}
      <h2 class="spaced">{t('incident.check')}</h2>
      <ul class="checks">
        {#each tips as tip (tip.kind)}
          <li>{tip.check}</li>
        {/each}
      </ul>
      {#if attacks.length}
        <h2 class="spaced">{t('incident.attack')}</h2>
        <ul class="attack">
          {#each attacks as attack (attack.technique_id)}
            {@const tactic = tacticUrl(attack.tactic_id)}
            {@const technique = techniqueUrl(attack.technique_id)}
            <li>
              {#if tactic}<a href={tactic} target="_blank" rel="noopener noreferrer">{attack.tactic}</a>{:else}{attack.tactic}{/if}
              <span class="flip-rtl" aria-hidden="true">→</span>
              {#if technique}<a href={technique} target="_blank" rel="noopener noreferrer">{attack.technique_id} {attack.technique}</a>{:else}{attack.technique}{/if}
            </li>
          {/each}
        </ul>
      {/if}
    </section>
  </div>

  <section class="card">
    <h2>{t('incident.evidence')}</h2>
    <div class="evidence">
      {#each data.alerts as alert (alert.id)}
        <article>
          <h3>{t(`kind.${alert.kind}`)} <SeverityBadge severity={alert.severity} /></h3>
          <dl>
            <dt>{t('evidence.count')}</dt>
            <dd class="num">{formatNumber(alert.count, fmt())}</dd>
            <dt>{t('incident.when')}</dt>
            <dd class="num">{formatTime(alert.first_seen, fmt())} – {formatTime(alert.last_seen, fmt())}</dd>
            {#if alert.details.type === 'port_scan'}
              <dt>{t('evidence.protocol')}</dt>
              <dd>{alert.details.protocol.toUpperCase()}</dd>
              <dt>{t('evidence.ports', { count: alert.details.ports_sample.length })}</dt>
              <dd class="chips ltr">
                {#each alert.details.ports_sample as port (port)}<span class="chip mono">{port}</span>{/each}
              </dd>
            {:else if alert.details.type === 'host_sweep'}
              <dt>{t('evidence.method')}</dt>
              <dd>{t(`method.${alert.details.method}`)}</dd>
              <dt>{t('evidence.hosts', { count: alert.details.hosts_sample.length })}</dt>
              <dd class="chips ltr">
                {#each alert.details.hosts_sample as host (host)}<span class="chip mono">{host}</span>{/each}
              </dd>
            {:else if alert.details.type === 'brute_force'}
              <dt>{t('evidence.service')}</dt>
              <dd><span class="ltr">{portLabel(alert.details.service_port)}</span></dd>
            {:else if alert.details.type === 'signature'}
              <dt>{t('evidence.rule')}</dt>
              <dd><span class="mono">{alert.details.signature_id}</span> {alert.details.signature}</dd>
              <dt>{t('evidence.category')}</dt>
              <dd>{alert.details.category}</dd>
            {/if}
          </dl>
          {#if 'window_secs' in alert.details}
            <p class="window muted">{t('evidence.window', { seconds: alert.details.window_secs })}</p>
          {/if}
        </article>
      {/each}
    </div>
  </section>

  <section class="card flows-card">
    <h2>{t('incident.flows', { ip: incident.src_ip })}</h2>
    {#if data.flows_truncated}
      <p class="muted">{t('incident.flows_truncated', { count: formatNumber(data.flows.length, fmt()) })}</p>
    {/if}
    <div class="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{t('col.time')}</th>
            <th>{t('col.protocol')}</th>
            <th>{t('col.from')}</th>
            <th>{t('col.to')}</th>
            <th class="num">{t('col.packets')}</th>
            <th class="num">{t('col.bytes')}</th>
            <th>{t('col.outcome')}</th>
          </tr>
        </thead>
        <tbody>
          {#each flows as flow (flow.id)}
            <tr>
              <td class="time">{formatTime(flow.first_seen, fmt())}</td>
              <td>{flow.protocol.toUpperCase()}</td>
              <td class="nowrap"><IpAddress ip={flow.src_ip} /> <span class="mono muted ltr">:{flow.src_port}</span></td>
              <td class="nowrap"><IpAddress ip={flow.dst_ip} /> <span class="mono muted ltr">{portLabel(flow.dst_port)}</span></td>
              <td class="num">{formatNumber(flow.packets_fwd + flow.packets_rev, fmt())}</td>
              <td class="num">{formatBytes(flow.bytes_fwd + flow.bytes_rev, fmt())}</td>
              <td>{flow.tcp_outcome ? t(`outcome.${flow.tcp_outcome}`) : ''}</td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
    {#if !allFlows && data.flows.length > FIRST_FLOWS}
      <button type="button" class="more" onclick={() => (allFlows = true)}
        >{t('incident.flows_more', { count: formatNumber(data.flows.length, fmt()) })}</button
      >
    {/if}
  </section>
{/if}

<style>
  .back {
    align-self: flex-start;
  }
  .head {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .title-row {
    display: flex;
    align-items: center;
    gap: 12px;
    flex-wrap: wrap;
  }
  .summary {
    margin: 0;
    font-size: 1.05rem;
  }
  .facts {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
    gap: 12px;
    margin: 0;
  }
  dt {
    color: var(--ink-2);
    font-size: 0.85rem;
  }
  dd {
    margin: 0;
  }
  .actions {
    display: flex;
    gap: 8px;
    align-items: center;
    flex-wrap: wrap;
  }
  .actions button[aria-pressed='true'] {
    font-weight: 600;
    border-color: var(--ink-2);
  }
  .error {
    margin: 0;
    border-inline-start: 3px solid var(--critical);
    padding-inline-start: 10px;
  }
  .columns {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 420px), 1fr));
    gap: 16px;
  }
  .columns .card p {
    margin: 8px 0 0;
  }
  .spaced {
    margin-top: 16px;
  }
  .story {
    list-style: none;
    margin: 10px 0 0;
    padding: 0;
    display: grid;
    grid-template-columns: max-content minmax(0, 1fr);
    gap: 14px 12px;
  }
  .story li {
    display: grid;
    grid-column: 1 / -1;
    grid-template-columns: subgrid;
  }
  .time {
    white-space: nowrap;
  }
  .story p {
    margin: 0 !important;
  }
  .meta {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
    margin-top: 4px;
    font-size: 0.85rem;
  }
  .checks,
  .attack {
    margin: 8px 0 0;
    padding-inline-start: 20px;
  }
  .checks li,
  .attack li {
    margin-bottom: 6px;
  }
  .evidence {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
    gap: 12px;
    margin-top: 10px;
  }
  article {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 12px;
  }
  article h3 {
    font-size: 0.95rem;
    display: flex;
    gap: 10px;
    align-items: center;
    margin-bottom: 8px;
  }
  article dl {
    margin: 0;
    display: grid;
    gap: 2px;
  }
  article dd {
    margin-bottom: 8px;
  }
  .chips {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }
  .chip {
    border: 1px solid var(--border);
    border-radius: 4px;
    padding: 0 5px;
    font-size: 0.8rem;
  }
  .lasted {
    display: block;
  }
  .window {
    margin: 0;
    font-size: 0.8rem;
  }
  .nowrap {
    white-space: nowrap;
  }
  .flows-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .flows-card p {
    margin: 0;
  }
  .more {
    align-self: center;
  }
</style>
