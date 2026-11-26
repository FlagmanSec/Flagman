<!-- The connections Flagman recorded, newest first, filterable by address, port and protocol. -->
<script lang="ts">
  import ErrorBox from '../components/ErrorBox.svelte';
  import IpAddress from '../components/IpAddress.svelte';
  import RangePicker from '../components/RangePicker.svelte';
  import { api } from '../lib/api';
  import { formatBytes, formatNumber, formatTime } from '../lib/format';
  import { fmt, t } from '../lib/i18n/index.svelte';
  import { poll } from '../lib/poll.svelte';
  import { parseRange, withParams } from '../lib/ranges';
  import { router } from '../lib/router.svelte';
  import { portLabel } from '../lib/services';

  let { replay }: { replay: boolean } = $props();

  const PROTOCOLS = ['tcp', 'udp', 'icmp', 'other'] as const;
  const PAGE = 200;
  const MAX = 1_000;

  const range = $derived(parseRange(router.params.get('range'), '1h'));
  const ip = $derived(router.params.get('ip') ?? '');
  const port = $derived(router.params.get('port') ?? '');
  const protocol = $derived(PROTOCOLS.find((p) => p === router.params.get('protocol')) ?? '');

  let limit = $state(PAGE);
  // The form keeps its own copy until "Apply".
  let ipInput = $state('');
  let portInput = $state('');
  $effect(() => {
    ipInput = ip;
    portInput = port;
  });

  const flows = poll(
    () =>
      api.flows({
        range,
        ip: ip || undefined,
        port: port === '' ? '' : Number(port),
        protocol: protocol || undefined,
        limit,
      }),
    () => (replay ? 60_000 : 15_000),
  );

  function apply(event: SubmitEvent) {
    event.preventDefault();
    limit = PAGE;
    const cleanPort = /^\d{1,5}$/.test(portInput.trim()) ? portInput.trim() : '';
    router.go(withParams(router.path, router.search, { ip: ipInput.trim(), port: cleanPort }), true);
  }

  function clear() {
    limit = PAGE;
    router.go(withParams(router.path, router.search, { ip: null, port: null, protocol: null }), true);
  }
</script>

<div class="filters">
  <RangePicker value={range} />
  <form onsubmit={apply}>
    <label>
      <span class="muted">{t('flows.ip')}</span>
      <input class="mono ltr" bind:value={ipInput} placeholder={t('flows.ip_placeholder')} size="18" />
    </label>
    <label>
      <span class="muted">{t('flows.port')}</span>
      <input class="mono ltr" bind:value={portInput} inputmode="numeric" size="6" />
    </label>
    <label>
      <span class="muted">{t('flows.protocol')}</span>
      <select
        value={protocol}
        onchange={(event) =>
          router.go(withParams(router.path, router.search, { protocol: event.currentTarget.value }), true)}
      >
        <option value="">{t('flows.any')}</option>
        {#each PROTOCOLS as p (p)}<option value={p}>{t(`proto.${p}`)}</option>{/each}
      </select>
    </label>
    <button type="submit">{t('flows.apply')}</button>
    {#if ip || port || protocol}
      <button type="button" onclick={clear}>{t('flows.clear')}</button>
    {/if}
  </form>
</div>

<section class="card">
  <h1>{t('flows.title')}</h1>
  <p class="muted note">{t('flows.note')}</p>
  {#if flows.error && !flows.data}
    <ErrorBox message={flows.error} onretry={flows.refresh} />
  {:else if !flows.data}
    <p class="muted">{t('common.loading')}</p>
  {:else if flows.data.length === 0}
    <p class="muted empty">{t('flows.none')}</p>
  {:else}
    <p class="muted note">{t('flows.shown', { count: formatNumber(flows.data.length, fmt()) })}</p>
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
          {#each flows.data as flow (flow.id)}
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
    {#if flows.data.length >= limit && limit < MAX}
      <button type="button" class="more" onclick={() => (limit = Math.min(MAX, limit + PAGE))}>{t('flows.more')}</button>
    {/if}
  {/if}
</section>

<style>
  .filters,
  form {
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
    gap: 8px;
  }
  .note {
    margin: 0;
    font-size: 0.85rem;
  }
  .empty {
    margin: 24px 0;
  }
  .nowrap {
    white-space: nowrap;
  }
  .more {
    align-self: center;
  }
</style>
