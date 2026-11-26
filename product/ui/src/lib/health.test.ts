import { describe, expect, it } from 'vitest';
import { RECENT_SATURATION_MS, saturation } from './health';
import type { Health } from './types';

function health(overrides: Partial<Health>): Health {
  return {
    version: '0.1.0',
    mode: 'live',
    source: 'eth0',
    started_at: 0,
    last_packet_at: null,
    packets: 0,
    bytes: 0,
    packets_skipped: 0,
    kernel_received: null,
    kernel_dropped: null,
    flows_active: 0,
    flows_evicted: 0,
    detector_evicted: 0,
    saturated_at: null,
    suricata: { enabled: false, eve_path: null, reading: false, hits: 0, last_error: null },
    storage_errors: 0,
    running: true,
    server_time: 100 * 60_000,
    clock: 'live',
    ...overrides,
  };
}

describe('saturation', () => {
  it('is absent while the sensor was never full', () => {
    expect(saturation(health({}))).toBeNull();
  });

  it('is a warning while recent, then a quiet note', () => {
    const now = 100 * 60_000;
    expect(saturation(health({ saturated_at: now - 60_000 }))).toEqual({ level: 'warning', at: now - 60_000 });
    const old = now - RECENT_SATURATION_MS - 1;
    expect(saturation(health({ saturated_at: old }))?.level).toBe('neutral');
  });

  it('measures time from the last packet in replay mode', () => {
    const replay = health({ clock: 'latest_data', mode: 'replay', last_packet_at: 5_000, saturated_at: 4_000 });
    expect(saturation(replay)?.level).toBe('warning');
  });
});
