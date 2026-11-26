<!-- One line on the sensor's state: is it capturing, losing packets, reading Suricata? -->
<script lang="ts">
  import { formatNumber, formatTime } from '../lib/format';
  import { fmt, t } from '../lib/i18n/index.svelte';
  import type { Health } from '../lib/types';
  import StatusIcon from './StatusIcon.svelte';

  let { health, error }: { health: Health | null; error: string | null } = $props();

  const capture = $derived.by(() => {
    if (error || !health) return { level: 'critical' as const, text: t('health.unreachable') };
    if (health.mode === 'replay') return { level: 'neutral' as const, text: t('health.replay', { source: health.source }) };
    if (!health.running) return { level: 'critical' as const, text: t('health.stopped') };
    return { level: 'good' as const, text: t('health.live', { source: health.source }) };
  });

  const suricata = $derived.by(() => {
    const s = health?.suricata;
    if (!s || !s.enabled) return { level: 'neutral' as const, text: t('health.suricata.off'), title: '' };
    if (s.reading) {
      return {
        level: 'good' as const,
        text: t('health.suricata.reading', { hits: formatNumber(s.hits, fmt()) }),
        title: s.eve_path ?? '',
      };
    }
    return { level: 'warning' as const, text: t('health.suricata.waiting'), title: s.last_error ?? '' };
  });
</script>

<section class="strip" aria-label={t('health.title')}>
  <span class="item strong"><StatusIcon level={capture.level} /> <span class="ltr-safe">{capture.text}</span></span>
  {#if health && !error}
    <span class="item">
      <span class="muted">{t('health.packets')}</span>
      <span class="num">{formatNumber(health.packets, fmt())}</span>
    </span>
    {#if health.kernel_dropped !== null}
      {#if health.kernel_dropped > 0}
        <span class="item">
          <StatusIcon level="warning" />
          <span class="muted">{t('health.drops')}</span>
          <span class="num">{formatNumber(health.kernel_dropped, fmt())}</span>
        </span>
      {:else}
        <span class="item"><StatusIcon level="good" /> {t('health.no_drops')}</span>
      {/if}
    {/if}
    <span class="item">
      <span class="muted">{t('health.last_packet')}</span>
      <span class="num">
        {health.last_packet_at ? formatTime(health.last_packet_at, fmt()) : t('health.none_yet')}
      </span>
    </span>
    <span class="item" title={suricata.title}>
      <StatusIcon level={suricata.level} />
      <span class="muted">{t('health.suricata')}</span>
      {suricata.text}
    </span>
    {#if health.storage_errors > 0}
      <span class="item">
        <StatusIcon level="critical" />
        {t('health.storage_errors', { count: formatNumber(health.storage_errors, fmt()) })}
      </span>
    {/if}
  {/if}
</section>

<style>
  .strip {
    display: flex;
    flex-wrap: wrap;
    gap: 6px 20px;
    align-items: center;
    padding: 10px 14px;
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: var(--radius);
    font-size: 0.9rem;
  }
  .item {
    display: inline-flex;
    align-items: center;
    gap: 6px;
  }
  .strong {
    font-weight: 600;
  }
  .ltr-safe {
    unicode-bidi: plaintext;
  }
</style>
