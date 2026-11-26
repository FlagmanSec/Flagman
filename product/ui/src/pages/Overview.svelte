<!--
  The home page: headline numbers, traffic and alerts over time, the protocol
  mix, the busiest devices and services, and the latest incidents.
  Everything follows the period chosen at the top.
-->
<script lang="ts">
  import ChartCard from '../components/ChartCard.svelte';
  import ErrorBox from '../components/ErrorBox.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import SeverityBadge from '../components/SeverityBadge.svelte';
  import StatTile from '../components/StatTile.svelte';
  import StatusPill from '../components/StatusPill.svelte';
  import IpAddress from '../components/IpAddress.svelte';
  import RankedBars, { type RankedRow } from '../components/charts/RankedBars.svelte';
  import SegmentedBar, { type Part } from '../components/charts/SegmentedBar.svelte';
  import SeverityColumns from '../components/charts/SeverityColumns.svelte';
  import TimeArea, { type TimePoint } from '../components/charts/TimeArea.svelte';
  import { api } from '../lib/api';
  import {
    compactNumber,
    formatBucket,
    formatBytes,
    formatDateTime,
    formatList,
    formatNumber,
    formatTime,
  } from '../lib/format';
  import { fmt, t } from '../lib/i18n/index.svelte';
  import { isLocal } from '../lib/net';
  import { poll } from '../lib/poll.svelte';
  import { parseRange } from '../lib/ranges';
  import { link, router } from '../lib/router.svelte';
  import { portLabel } from '../lib/services';
  import { SEVERITIES } from '../lib/severity';
  import type { ClassCounts, Dashboard, Severity, TrafficClass } from '../lib/types';

  let { replay }: { replay: boolean } = $props();

  const range = $derived(parseRange(router.params.get('range'), '1h'));
  const dash = poll(
    () => api.dashboard(range),
    () => (replay ? 60_000 : 10_000),
  );
  const data: Dashboard | null = $derived(dash.data);
  const stale = $derived(data !== null && data.range.label !== range);

  let measure: 'bytes' | 'packets' = $state('bytes');

  const CLASSES: TrafficClass[] = ['tcp', 'udp', 'icmp', 'arp', 'other'];
  const CLASS_COLORS: Record<TrafficClass, string> = {
    tcp: '--series-1',
    udp: '--series-2',
    icmp: '--series-3',
    arp: '--series-4',
    other: '--series-5',
  };

  const sum = (counts: ClassCounts) => CLASSES.reduce((total, c) => total + counts[c], 0);
  const formatMeasure = (value: number) =>
    measure === 'bytes' ? formatBytes(value, fmt()) : formatNumber(value, fmt());
  const formatMeasureAxis = (value: number) =>
    measure === 'bytes' ? formatBytes(value, fmt()) : compactNumber(value, fmt());
  const share = (value: number) =>
    new Intl.NumberFormat(fmt(), { style: 'percent', maximumFractionDigits: value < 0.1 ? 1 : 0 }).format(value);

  const spanMs = $derived(data ? data.range.until - data.range.since : 0);
  const bucketNote = $derived(data ? t('chart.bucket', { bucket: formatBucket(data.range.bucket_ms, fmt()) }) : '');

  const trafficPoints: TimePoint[] = $derived(
    (data?.traffic ?? []).map((point) => ({
      t: point.t,
      value: sum(point[measure]),
      parts: CLASSES.filter((c) => point[measure][c] > 0).map((c) => ({
        label: t(`proto.${c}`),
        value: formatMeasure(point[measure][c]),
      })),
    })),
  );
  const hasTraffic = $derived(trafficPoints.some((point) => point.value > 0));

  // Bytes and packets tell different stories: a port scan is many tiny
  // packets, so it barely shows in bytes but stands out in packets.
  function protocolParts(counts: ClassCounts | undefined, format: (n: number) => string): Part[] {
    return CLASSES.map((c) => ({
      key: c,
      label: t(`proto.${c}`),
      value: counts?.[c] ?? 0,
      display: format(counts?.[c] ?? 0),
      color: CLASS_COLORS[c],
      ink: c === 'arp' ? 'var(--on-series-4)' : 'var(--on-series)',
    }));
  }
  const byteParts = $derived(protocolParts(data?.protocol_bytes, (n) => formatBytes(n, fmt())));
  const packetParts = $derived(protocolParts(data?.protocol_packets, (n) => formatNumber(n, fmt())));
  const totalBytes = $derived(data ? sum(data.protocol_bytes) : 0);
  const totalPackets = $derived(data ? sum(data.protocol_packets) : 0);

  const talkerRows: RankedRow[] = $derived(
    (data?.top_talkers ?? []).map((row) => ({
      key: row.ip,
      label: row.ip,
      tag: isLocal(row.ip) ? t('common.local') : undefined,
      value: row.bytes,
      display: formatBytes(row.bytes, fmt()),
      href: `/flows?ip=${encodeURIComponent(row.ip)}&range=${range}`,
      mono: true,
    })),
  );

  const portRows: RankedRow[] = $derived(
    (data?.top_ports ?? []).map((row) => ({
      key: `${row.detail}-${row.name}`,
      label: portLabel(Number(row.name)),
      tag: (row.detail ?? '').toUpperCase(),
      value: row.count,
      display: formatNumber(row.count, fmt()),
      href: `/flows?port=${row.name}&protocol=${row.detail ?? ''}&range=${range}`,
      ltr: true,
    })),
  );

  const alertTypeRows: RankedRow[] = $derived(
    (data?.top_alerts ?? []).map((row) => ({
      key: `${row.name}-${row.detail ?? ''}`,
      label: row.name === 'signature' && row.detail ? row.detail : t(`kind.${row.name as 'port_scan'}`),
      value: row.count,
      display: formatNumber(row.count, fmt()),
    })),
  );

  const alertTotals = $derived(
    (data?.alerts ?? []).map((point) => SEVERITIES.reduce((total, s: Severity) => total + point[s], 0)),
  );
</script>

<div class="filters">
  <RangePicker value={range} />
  {#if replay}<span class="muted note">{t('range.replay')}</span>{/if}
</div>

{#if dash.error && !data}
  <ErrorBox message={dash.error} onretry={dash.refresh} />
{:else if !data}
  <p class="muted">{t('common.loading')}</p>
{:else}
  <div class="content" class:stale>
    <div class="kpis">
      <StatTile
        hero
        label={t('kpi.open_incidents')}
        value={formatNumber(data.overview.open_incidents, fmt())}
        note={t('kpi.incidents_total', { count: formatNumber(data.overview.incidents, fmt()) })}
      />
      <StatTile label={t('kpi.alerts')} value={compactNumber(data.overview.alerts, fmt())} />
      <StatTile label={t('kpi.flows')} value={compactNumber(data.overview.flows, fmt())} />
      <StatTile label={t('kpi.traffic')} value={formatBytes(data.overview.bytes, fmt())} />
      <StatTile label={t('kpi.devices')} value={formatNumber(data.overview.local_hosts, fmt())} />
    </div>

    <div class="grid two">
      <ChartCard title={t('chart.traffic')} subtitle={bucketNote}>
        {#snippet controls()}
          <select
            aria-label={t('chart.traffic.measure')}
            class="small"
            value={measure}
            onchange={(event) => (measure = event.currentTarget.value as 'bytes' | 'packets')}
          >
            <option value="bytes">{t('chart.traffic.bytes')}</option>
            <option value="packets">{t('chart.traffic.packets')}</option>
          </select>
        {/snippet}
        {#snippet chart()}
          {#if hasTraffic}
            <TimeArea
              points={trafficPoints}
              {spanMs}
              label={t('chart.traffic')}
              valueLabel={t('chart.total')}
              formatValue={formatMeasure}
              formatAxis={formatMeasureAxis}
            />
          {:else}
            <p class="empty muted">{t('chart.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.time')}</th>
                <th class="num">{t('chart.total')}</th>
                {#each CLASSES as c (c)}<th class="num">{t(`proto.${c}`)}</th>{/each}
              </tr>
            </thead>
            <tbody>
              {#each data.traffic as point (point.t)}
                <tr>
                  <td class="time">{formatDateTime(point.t, fmt())}</td>
                  <td class="num">{formatMeasure(sum(point[measure]))}</td>
                  {#each CLASSES as c (c)}<td class="num">{formatMeasure(point[measure][c])}</td>{/each}
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>

      <ChartCard title={t('chart.alerts')} subtitle={`${t('chart.alerts.sub')} ${bucketNote}`}>
        {#snippet chart()}
          {#if data.overview.alerts > 0 && alertTotals.some((n) => n > 0)}
            <SeverityColumns points={data.alerts} {spanMs} label={t('chart.alerts')} />
          {:else}
            <p class="empty muted">{t('chart.alerts.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.time')}</th>
                {#each SEVERITIES as s (s)}<th class="num">{t(`severity.${s}`)}</th>{/each}
                <th class="num">{t('chart.total')}</th>
              </tr>
            </thead>
            <tbody>
              {#each data.alerts as point, i (point.t)}
                <tr>
                  <td class="time">{formatDateTime(point.t, fmt())}</td>
                  {#each SEVERITIES as s (s)}<td class="num">{formatNumber(point[s], fmt())}</td>{/each}
                  <td class="num">{formatNumber(alertTotals[i] ?? 0, fmt())}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>
    </div>

    <div class="grid three">
      <ChartCard title={t('chart.protocols')} subtitle={t('chart.protocols.sub')}>
        {#snippet chart()}
          {#if totalBytes > 0}
            <div class="bars">
              <SegmentedBar
                parts={byteParts}
                caption={t('col.bytes')}
                label={`${t('chart.protocols')}: ${t('col.bytes')}`}
                formatShare={share}
                legend={false}
              />
              <SegmentedBar
                parts={packetParts}
                caption={t('col.packets')}
                label={`${t('chart.protocols')}: ${t('col.packets')}`}
                formatShare={share}
              />
            </div>
          {:else}
            <p class="empty muted">{t('chart.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.protocol')}</th>
                <th class="num">{t('col.bytes')}</th>
                <th class="num">{t('col.share')}</th>
                <th class="num">{t('col.packets')}</th>
                <th class="num">{t('col.share')}</th>
              </tr>
            </thead>
            <tbody>
              {#each CLASSES as c (c)}
                <tr>
                  <td>{t(`proto.${c}`)}</td>
                  <td class="num">{formatBytes(data.protocol_bytes[c], fmt())}</td>
                  <td class="num">{totalBytes ? share(data.protocol_bytes[c] / totalBytes) : '–'}</td>
                  <td class="num">{formatNumber(data.protocol_packets[c], fmt())}</td>
                  <td class="num">{totalPackets ? share(data.protocol_packets[c] / totalPackets) : '–'}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>

      <ChartCard title={t('chart.talkers')} subtitle={t('chart.talkers.sub')}>
        {#snippet chart()}
          {#if talkerRows.length}
            <RankedBars rows={talkerRows} label={t('chart.talkers')} />
          {:else}
            <p class="empty muted">{t('chart.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.device')}</th>
                <th class="num">{t('col.bytes')}</th>
                <th class="num">{t('col.connections')}</th>
              </tr>
            </thead>
            <tbody>
              {#each data.top_talkers as row (row.ip)}
                <tr>
                  <td><IpAddress ip={row.ip} /></td>
                  <td class="num">{formatBytes(row.bytes, fmt())}</td>
                  <td class="num">{formatNumber(row.flows, fmt())}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>

      <ChartCard title={t('chart.ports')} subtitle={t('chart.ports.sub')}>
        {#snippet chart()}
          {#if portRows.length}
            <RankedBars rows={portRows} label={t('chart.ports')} />
          {:else}
            <p class="empty muted">{t('chart.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.service')}</th>
                <th>{t('col.protocol')}</th>
                <th class="num">{t('col.connections')}</th>
                <th class="num">{t('col.bytes')}</th>
              </tr>
            </thead>
            <tbody>
              {#each data.top_ports as row (`${row.detail}-${row.name}`)}
                <tr>
                  <td>{portLabel(Number(row.name))}</td>
                  <td>{(row.detail ?? '').toUpperCase()}</td>
                  <td class="num">{formatNumber(row.count, fmt())}</td>
                  <td class="num">{formatBytes(Number(row.value ?? 0), fmt())}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>
    </div>

    <div class="grid two wide-first">
      <section class="card recent">
        <div class="recent-head">
          <h2>{t('recent.title')}</h2>
          <a href={`/incidents?range=${range}`} onclick={link}>{t('recent.all')}</a>
        </div>
        {#if data.recent_incidents.length}
          <ul>
            {#each data.recent_incidents as incident (incident.id)}
              {@const what = formatList(incident.kinds.map((kind) => t(`kind.${kind}`)), fmt())}
              <li>
                <a class="row" href={`/incidents/${incident.id}`} onclick={link}>
                  <SeverityBadge severity={incident.severity} />
                  <span class="what" title={what}>{what}</span>
                  <span class="mono ltr src">{incident.src_ip}</span>
                  <span class="muted num when">{formatTime(incident.last_seen, fmt())}</span>
                  <StatusPill status={incident.status} />
                </a>
              </li>
            {/each}
          </ul>
        {:else}
          <p class="empty muted">{t('recent.none')}</p>
        {/if}
      </section>

      <ChartCard title={t('chart.alert_types')} subtitle={t('chart.alert_types.sub')}>
        {#snippet chart()}
          {#if alertTypeRows.length}
            <RankedBars rows={alertTypeRows} label={t('chart.alert_types')} />
          {:else}
            <p class="empty muted">{t('chart.alerts.empty')}</p>
          {/if}
        {/snippet}
        {#snippet table()}
          <table>
            <thead>
              <tr>
                <th>{t('col.type')}</th>
                <th class="num">{t('col.alerts')}</th>
              </tr>
            </thead>
            <tbody>
              {#each alertTypeRows as row (row.key)}
                <tr>
                  <td>{row.label}</td>
                  <td class="num">{row.display}</td>
                </tr>
              {/each}
            </tbody>
          </table>
        {/snippet}
      </ChartCard>
    </div>
  </div>
{/if}

<style>
  .filters {
    display: flex;
    align-items: center;
    gap: 8px 16px;
    flex-wrap: wrap;
  }
  .note {
    font-size: 0.85rem;
  }
  .content {
    display: flex;
    flex-direction: column;
    gap: 16px;
    transition: opacity 0.2s;
  }
  .stale {
    opacity: 0.55;
  }
  .kpis {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(170px, 1fr));
    gap: 12px;
  }
  .grid {
    display: grid;
    gap: 16px;
  }
  .two {
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 440px), 1fr));
  }
  .three {
    grid-template-columns: repeat(auto-fit, minmax(min(100%, 320px), 1fr));
  }
  .empty {
    margin: 24px 0;
    text-align: center;
  }
  .bars {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }
  .small {
    min-height: 30px;
    padding: 2px 8px;
    font-size: 0.85rem;
  }
  .recent {
    display: flex;
    flex-direction: column;
    gap: 10px;
  }
  .recent-head {
    display: flex;
    justify-content: space-between;
    align-items: baseline;
  }
  .recent ul {
    list-style: none;
    margin: 0;
    padding: 0;
  }
  .row {
    display: grid;
    grid-template-columns: 6.5rem minmax(0, 1fr) auto auto auto;
    gap: 12px;
    align-items: center;
    padding: 8px 6px;
    border-bottom: 1px solid var(--grid);
    color: var(--ink);
  }
  .row:hover {
    background: var(--surface-hover);
    text-decoration: none;
  }
  .what {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }
  @media (max-width: 640px) {
    .row {
      grid-template-columns: 6.5rem minmax(0, 1fr) auto;
    }
    .when,
    .src {
      display: none;
    }
  }
</style>
