// A small router on top of the browser's history. Addresses are real paths
// (/incidents/3); flagmand answers every unknown path with the dashboard, so
// reloading or sharing a link works.

import { matchRoute, type Route } from './routes';

class Router {
  path = $state(location.pathname);
  search = $state(location.search);
  route: Route = $derived(matchRoute(this.path));
  params: URLSearchParams = $derived(new URLSearchParams(this.search));

  constructor() {
    window.addEventListener('popstate', () => this.sync());
  }

  /** Goes to another page. `replace` updates the address without a new history entry. */
  go(to: string, replace = false): void {
    if (to === location.pathname + location.search) return;
    history[replace ? 'replaceState' : 'pushState'](null, '', to);
    const samePage = new URL(to, location.origin).pathname === this.path;
    this.sync();
    if (!samePage) window.scrollTo(0, 0);
  }

  private sync(): void {
    this.path = location.pathname;
    this.search = location.search;
  }
}

export const router = new Router();

/** Click handler for internal links. Ctrl-click and middle-click still open a new tab. */
export function link(event: MouseEvent): void {
  if (event.defaultPrevented || event.button !== 0) return;
  if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  const anchor = event.currentTarget as HTMLAnchorElement;
  if (anchor.target || anchor.origin !== location.origin) return;
  event.preventDefault();
  router.go(anchor.pathname + anchor.search);
}
