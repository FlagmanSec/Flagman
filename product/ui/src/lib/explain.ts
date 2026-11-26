// Turns an incident's alerts into plain sentences: what happened, why it
// matters, and what to check. The wording lives in the i18n files.

import type { MessageKey } from './i18n/en';
import type { Params } from './i18n/translate';
import { serviceName } from './services';
import type { AlertKind, AlertRow } from './types';

export type Translate = (key: MessageKey, params?: Params) => string;

export interface StoryLine {
  alert: AlertRow;
  text: string;
}

function service(port: number | null, tr: Translate): string {
  if (port === null) return '?';
  return serviceName(port) ?? tr('common.port', { port });
}

/** One sentence per alert, oldest first. */
export function storyLines(alerts: readonly AlertRow[], tr: Translate, formatCount: (n: number) => string): StoryLine[] {
  return [...alerts]
    .sort((a, b) => a.first_seen - b.first_seen || a.id - b.id)
    .map((alert) => {
      const base = {
        src: alert.src_ip,
        dst: alert.dst_ip ?? '?',
        count: formatCount(alert.count),
      };
      const details = alert.details;
      let text: string;
      switch (details.type) {
        case 'port_scan':
          text = tr('story.port_scan', { ...base, protocol: details.protocol.toUpperCase() });
          break;
        case 'host_sweep':
          text = tr('story.host_sweep', { ...base, method: tr(`method.${details.method}`) });
          break;
        case 'brute_force':
          text = tr('story.brute_force', { ...base, service: service(details.service_port, tr) });
          break;
        case 'signature':
          text = tr('story.signature', { ...base, signature: details.signature });
          break;
      }
      return { alert, text };
    });
}

export interface Advice {
  kind: AlertKind;
  why: string;
  check: string;
}

/** "Why it matters" and "What to check", once per kind of alert, in story order. */
export function advice(alerts: readonly AlertRow[], tr: Translate): Advice[] {
  const seen = new Set<AlertKind>();
  const result: Advice[] = [];
  for (const { alert } of storyLines(alerts, tr, String)) {
    if (seen.has(alert.kind)) continue;
    seen.add(alert.kind);
    const sid = alert.details.type === 'signature' ? alert.details.signature_id : '';
    const params = { src: alert.src_ip, dst: alert.dst_ip ?? '?', sid };
    result.push({
      kind: alert.kind,
      why: tr(`why.${alert.kind}`),
      check: tr(`check.${alert.kind}`, params),
    });
  }
  return result;
}
