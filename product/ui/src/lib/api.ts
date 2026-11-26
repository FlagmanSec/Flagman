// Talking to flagmand's API. Every request carries the token; a 401 answer
// sends the person back to the sign-in screen.

import { loadToken } from './token';
import type {
  AlertRow,
  Dashboard,
  FlowRow,
  Health,
  IncidentDetail,
  IncidentRow,
  IncidentStatus,
  RangeLabel,
  Severity,
} from './types';

export class ApiError extends Error {
  constructor(
    readonly status: number,
    message: string,
  ) {
    super(message);
  }
}

let unauthorized: () => void = () => {};

/** Called whenever the API refuses the token. */
export function onUnauthorized(handler: () => void): void {
  unauthorized = handler;
}

type Params = Record<string, string | number | null | undefined>;

/** Builds "?a=1&b=2", leaving out empty values. */
export function queryString(params: Params): string {
  const query = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value !== null && value !== undefined && value !== '') query.set(key, String(value));
  }
  const text = query.toString();
  return text ? `?${text}` : '';
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  headers.set('Accept', 'application/json');
  const token = loadToken();
  if (token) headers.set('Authorization', `Bearer ${token}`);
  const response = await fetch(`/api${path}`, { ...init, headers, cache: 'no-store' });
  if (response.status === 401) {
    unauthorized();
    throw new ApiError(401, 'the access token was refused');
  }
  if (!response.ok) {
    let message = response.statusText;
    try {
      message = ((await response.json()) as { error?: string }).error ?? message;
    } catch {
      // Not JSON: keep the status text.
    }
    throw new ApiError(response.status, message);
  }
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

export interface IncidentQuery {
  range: RangeLabel;
  min_severity?: Severity | '';
  status?: IncidentStatus | '';
  limit?: number;
}

export interface FlowQuery {
  range: RangeLabel;
  ip?: string;
  port?: number | '';
  protocol?: string;
  limit?: number;
}

export const api = {
  health: () => request<Health>('/health'),
  dashboard: (range: RangeLabel) => request<Dashboard>(`/dashboard${queryString({ range })}`),
  incidents: (query: IncidentQuery) =>
    request<IncidentRow[]>(`/incidents${queryString({ ...query })}`),
  incident: (id: number) => request<IncidentDetail>(`/incidents/${id}`),
  setStatus: (id: number, status: IncidentStatus) =>
    request<void>(`/incidents/${id}/status`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ status }),
    }),
  alerts: (range: RangeLabel, limit = 100) =>
    request<AlertRow[]>(`/alerts${queryString({ range, limit })}`),
  flows: (query: FlowQuery) => request<FlowRow[]>(`/flows${queryString({ ...query })}`),
};
