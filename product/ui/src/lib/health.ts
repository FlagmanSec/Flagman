// Small decisions about the sensor's health, kept out of the components so
// they can be tested.

import type { Health } from './types';

/** A saturation that happened less than this long ago is shown as a warning. */
export const RECENT_SATURATION_MS = 10 * 60_000;

export interface Saturation {
  level: 'warning' | 'neutral';
  /** When the sensor was last full (milliseconds since 1970). */
  at: number;
}

/**
 * Whether the detector was saturated during this run, and how recently.
 * In replay mode "now" is the last packet of the capture, not the clock.
 */
export function saturation(health: Health): Saturation | null {
  if (health.saturated_at === null) return null;
  const now = health.clock === 'live' ? health.server_time : (health.last_packet_at ?? health.server_time);
  const recent = now - health.saturated_at < RECENT_SATURATION_MS;
  return { level: recent ? 'warning' : 'neutral', at: health.saturated_at };
}
