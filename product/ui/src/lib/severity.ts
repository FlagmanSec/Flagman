// Severity levels, from least to most serious.

import type { Severity } from './types';

export const SEVERITIES: readonly Severity[] = ['low', 'medium', 'high', 'critical'];

export function severityRank(severity: Severity): number {
  return SEVERITIES.indexOf(severity);
}
