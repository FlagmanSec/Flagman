import { describe, expect, it } from 'vitest';
import { advice, storyLines } from './explain';
import { translate } from './i18n/translate';
import type { AlertRow } from './types';

const tr: Parameters<typeof storyLines>[1] = (key, params) => translate('en', key, params);

function alert(id: number, firstSeen: number, details: AlertRow['details'], count = 10): AlertRow {
  const kind = details.type;
  return {
    id,
    incident_id: 1,
    kind,
    severity: 'medium',
    first_seen: firstSeen,
    last_seen: firstSeen + 5_000,
    src_ip: '192.168.77.66',
    dst_ip: kind === 'host_sweep' ? null : '192.168.77.10',
    dst_port: kind === 'brute_force' ? 22 : null,
    count,
    details,
    attack: null,
  };
}

const sweep = alert(1, 1_000, { type: 'host_sweep', method: 'arp', hosts_sample: ['192.168.77.1'], window_secs: 60 }, 255);
const scan = alert(2, 5_000, { type: 'port_scan', protocol: 'tcp', ports_sample: [22, 80], window_secs: 60 }, 1_000);
const brute = alert(3, 4_000, { type: 'brute_force', service_port: 22, window_secs: 60 }, 16);

describe('storyLines', () => {
  it('tells the alerts oldest first', () => {
    const lines = storyLines([scan, brute, sweep], tr, String);
    expect(lines.map((line) => line.alert.id)).toEqual([1, 3, 2]);
  });

  it('names the source, the count and the service', () => {
    const [sweepLine, bruteLine, scanLine] = storyLines([sweep, brute, scan], tr, String).map((l) => l.text);
    expect(sweepLine).toContain('192.168.77.66');
    expect(sweepLine).toContain('255');
    expect(sweepLine).toContain('ARP');
    expect(bruteLine).toContain('SSH');
    expect(scanLine).toContain('1000');
    expect(scanLine).toContain('TCP');
  });

  it('says "port N" for a service without a well-known name', () => {
    const odd = alert(4, 1_000, { type: 'brute_force', service_port: 2222, window_secs: 60 });
    expect(storyLines([odd], tr, String)[0]?.text).toContain('port 2222');
  });

  it('uses the number format it is given', () => {
    const text = storyLines([scan], tr, (n) => n.toLocaleString('en'))[0]?.text;
    expect(text).toContain('1,000');
  });
});

describe('advice', () => {
  it('explains each kind of alert once', () => {
    const second = alert(5, 9_000, { type: 'port_scan', protocol: 'udp', ports_sample: [53], window_secs: 60 });
    const tips = advice([scan, second, sweep], tr);
    expect(tips.map((tip) => tip.kind)).toEqual(['host_sweep', 'port_scan']);
    expect(tips[0]?.check).toContain('192.168.77.66');
  });
});
