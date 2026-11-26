// The periods the dashboard offers (the API accepts exactly these).

import type { RangeLabel } from './types';

export const RANGES: readonly RangeLabel[] = ['15m', '1h', '6h', '24h', '7d', '30d'];

export function parseRange(value: string | null, fallback: RangeLabel): RangeLabel {
  return RANGES.find((range) => range === value) ?? fallback;
}

/** The current address with some query parameters changed (empty removes them). */
export function withParams(path: string, search: string, changes: Record<string, string | null>): string {
  const params = new URLSearchParams(search);
  for (const [key, value] of Object.entries(changes)) {
    if (value === null || value === '') params.delete(key);
    else params.set(key, value);
  }
  const text = params.toString();
  return text ? `${path}?${text}` : path;
}
