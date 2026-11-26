// Loads data now, again whenever its inputs change, and every few seconds
// while the tab is visible. Old data stays on screen while new data loads,
// so the page never flashes empty.
//
// Call it while a component starts: `const dash = poll(() => api.dashboard(range), () => 10_000)`.
// Everything `load` reads before its first `await` (here `range`) is tracked.

import { ApiError } from './api';

export interface Polled<T> {
  readonly data: T | null;
  readonly error: string | null;
  readonly loading: boolean;
  refresh(): Promise<void>;
}

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof TypeError) return 'network';
  return error instanceof Error ? error.message : String(error);
}

export function poll<T>(load: () => Promise<T>, everyMs: () => number): Polled<T> {
  const state = $state({ data: null as T | null, error: null as string | null, loading: false });
  let latest = 0;

  async function run(): Promise<void> {
    const mine = ++latest;
    state.loading = true;
    try {
      const data = await load();
      if (mine === latest) {
        state.data = data;
        state.error = null;
      }
    } catch (error) {
      if (mine === latest) state.error = errorMessage(error);
    } finally {
      if (mine === latest) state.loading = false;
    }
  }

  $effect(() => {
    void run();
    const timer = setInterval(() => {
      if (document.visibilityState === 'visible') void run();
    }, everyMs());
    const onVisible = () => {
      if (document.visibilityState === 'visible') void run();
    };
    document.addEventListener('visibilitychange', onVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onVisible);
    };
  });

  return {
    get data() {
      return state.data;
    },
    get error() {
      return state.error;
    },
    get loading() {
      return state.loading;
    },
    refresh: run,
  };
}
