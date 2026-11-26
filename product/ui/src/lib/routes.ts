// The dashboard's pages and their addresses.

export type Route =
  | { name: 'overview' }
  | { name: 'incidents' }
  | { name: 'incident'; id: number }
  | { name: 'flows' }
  | { name: 'not_found' };

export function matchRoute(path: string): Route {
  const clean = path.replace(/\/+$/, '') || '/';
  if (clean === '/') return { name: 'overview' };
  if (clean === '/incidents') return { name: 'incidents' };
  if (clean === '/flows') return { name: 'flows' };
  const incident = /^\/incidents\/(\d{1,15})$/.exec(clean);
  if (incident) return { name: 'incident', id: Number(incident[1]) };
  return { name: 'not_found' };
}
