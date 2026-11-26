// Light, dark, or following the operating system ("auto").

export type Theme = 'auto' | 'light' | 'dark';

const STORAGE_KEY = 'flagman.theme';

function initialTheme(): Theme {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'light' || saved === 'dark') return saved;
  } catch {
    // Storage blocked: follow the system.
  }
  return 'auto';
}

const state = $state({ theme: initialTheme() });

function apply(theme: Theme): void {
  if (theme === 'auto') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = theme;
}

apply(state.theme);

export function theme(): Theme {
  return state.theme;
}

export function setTheme(next: Theme): void {
  state.theme = next;
  apply(next);
  try {
    if (next === 'auto') localStorage.removeItem(STORAGE_KEY);
    else localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Applied for this visit only.
  }
}
