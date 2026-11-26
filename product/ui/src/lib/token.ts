// The dashboard's access token.
//
// flagmand prints a link such as http://127.0.0.1:8750/#token=abc… The part
// after "#" never leaves the browser. The token is kept for this tab
// (sessionStorage), or on this computer when the person asks for it
// (localStorage), and removed from the address bar so it does not end up in
// a bookmark or a screenshot.

const KEY = 'flagman.token';

/** The token in a URL fragment such as "#token=abc", if it looks valid. */
export function tokenFromHash(hash: string): string | null {
  const token = new URLSearchParams(hash.replace(/^#/, '')).get('token')?.trim();
  return token && /^[A-Za-z0-9]{32,128}$/.test(token) ? token : null;
}

// Storage can be missing or blocked (private windows, strict settings).
function read(storage: () => Storage): string | null {
  try {
    return storage().getItem(KEY);
  } catch {
    return null;
  }
}

function write(storage: () => Storage, value: string | null): void {
  try {
    if (value === null) storage().removeItem(KEY);
    else storage().setItem(KEY, value);
  } catch {
    // Not fatal: the person will be asked for the token again.
  }
}

export function loadToken(): string | null {
  return read(() => sessionStorage) ?? read(() => localStorage);
}

export function saveToken(token: string, remember: boolean): void {
  write(() => sessionStorage, token);
  if (remember) write(() => localStorage, token);
}

export function forgetToken(): void {
  write(() => sessionStorage, null);
  write(() => localStorage, null);
}

/** Takes the token from the link the page was opened with, then hides it. */
export function takeTokenFromUrl(): void {
  const token = tokenFromHash(location.hash);
  if (token) {
    saveToken(token, false);
    history.replaceState(history.state, '', location.pathname + location.search);
  }
}
