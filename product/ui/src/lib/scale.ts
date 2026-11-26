// Axis helpers for the hand-made SVG charts.

/** Round axis ticks from 0 to at least `max`, about `count` of them. */
export function niceTicks(max: number, count = 4, integer = false): number[] {
  if (!(max > 0)) return [0, 1];
  const rough = max / count;
  const power = 10 ** Math.floor(Math.log10(rough));
  const multipliers = integer ? [1, 2, 5, 10] : [1, 2, 2.5, 5, 10];
  let step = (multipliers.find((m) => m * power >= rough) ?? 10) * power;
  if (integer) step = Math.max(1, Math.round(step));
  const top = Math.ceil(max / step) * step;
  const ticks: number[] = [];
  for (let value = 0; value <= top + step / 2; value += step) {
    ticks.push(Math.round(value * 1e6) / 1e6);
  }
  return ticks;
}

/** Indexes of about `count` evenly spread labels among `n` points. */
export function labelIndexes(n: number, count = 5): number[] {
  if (n <= 0) return [];
  if (n <= count) return Array.from({ length: n }, (_, i) => i);
  const every = Math.ceil(n / count);
  const indexes: number[] = [];
  for (let i = 0; i < n; i += every) indexes.push(i);
  return indexes;
}

/** An SVG path for a bar with 4px rounded top corners and a square base. */
export function columnPath(x: number, y: number, width: number, height: number, radius = 4): string {
  const r = Math.max(0, Math.min(radius, width / 2, height));
  const bottom = y + height;
  return [
    `M${x},${bottom}`,
    `V${y + r}`,
    `Q${x},${y} ${x + r},${y}`,
    `H${x + width - r}`,
    `Q${x + width},${y} ${x + width},${y + r}`,
    `V${bottom}`,
    'Z',
  ].join(' ');
}

/** Index of the point nearest to pixel `px`, for points spread from `left` over `width`. */
export function nearestIndex(px: number, left: number, width: number, n: number): number {
  if (n <= 1) return 0;
  const step = width / (n - 1);
  return Math.min(n - 1, Math.max(0, Math.round((px - left) / step)));
}
