// Numbers, sizes, times and durations, written the way each language expects
// (the browser's Intl library does the localisation).

const numberFormats = new Map<string, Intl.NumberFormat>();

function cached(locale: string, options: Intl.NumberFormatOptions): Intl.NumberFormat {
  const key = `${locale}|${JSON.stringify(options)}`;
  let format = numberFormats.get(key);
  if (!format) {
    format = new Intl.NumberFormat(locale, options);
    numberFormats.set(key, format);
  }
  return format;
}

/** 1234567 -> "1,234,567" (en) or "1 234 567" (fr). */
export function formatNumber(value: number, locale: string): string {
  return cached(locale, {}).format(value);
}

/** 12900 -> "12.9K": for stat tiles and axis ticks. Below 10,000, in full. */
export function compactNumber(value: number, locale: string): string {
  if (Math.abs(value) < 10_000) return formatNumber(value, locale);
  return cached(locale, { notation: 'compact', maximumFractionDigits: 1 }).format(value);
}

const BYTE_UNITS = ['byte', 'kilobyte', 'megabyte', 'gigabyte', 'terabyte'] as const;

/**
 * 1_500_000 -> "1.5 MB" (decimal units, like network tools).
 * Plain bytes use the long name ("112 bytes"), because the short English
 * form is "112 byte" and French "112 o" is easy to misread.
 */
export function formatBytes(value: number, locale: string): string {
  let size = value;
  let unit = 0;
  while (size >= 1000 && unit < BYTE_UNITS.length - 1) {
    size /= 1000;
    unit += 1;
  }
  const digits = unit === 0 || size >= 100 ? 0 : 1;
  return cached(locale, {
    style: 'unit',
    unit: BYTE_UNITS[unit],
    unitDisplay: unit === 0 ? 'long' : 'short',
    maximumFractionDigits: digits,
  }).format(size);
}

/** 65_000 ms -> "1 min 5 s". */
export function formatDuration(ms: number, locale: string): string {
  const unit = (value: number, name: 'second' | 'minute' | 'hour' | 'day') =>
    cached(locale, { style: 'unit', unit: name, unitDisplay: 'short' }).format(value);
  const seconds = Math.round(ms / 1000);
  if (seconds < 60) return unit(seconds, 'second');
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    const rest = seconds % 60;
    return rest ? `${unit(minutes, 'minute')} ${unit(rest, 'second')}` : unit(minutes, 'minute');
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 48) {
    const rest = minutes % 60;
    return rest ? `${unit(hours, 'hour')} ${unit(rest, 'minute')}` : unit(hours, 'hour');
  }
  return unit(Math.floor(hours / 24), 'day');
}

/** ["Port scan", "Host sweep"] -> "Port scan and Host sweep" (fr: "et", ar: "و"). */
export function formatList(items: string[], locale: string): string {
  return new Intl.ListFormat(locale, { style: 'long', type: 'conjunction' }).format(items);
}

/** A chart bucket size: 300_000 -> "5 min". */
export function formatBucket(ms: number, locale: string): string {
  return formatDuration(ms, locale);
}

function sameDay(a: Date, b: Date): boolean {
  return a.toDateString() === b.toDateString();
}

/** A moment, in the browser's time zone. The date is added when it is not today. */
export function formatTime(ms: number, locale: string, now = Date.now()): string {
  const date = new Date(ms);
  const options: Intl.DateTimeFormatOptions = sameDay(date, new Date(now))
    ? { hour: '2-digit', minute: '2-digit', second: '2-digit' }
    : { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' };
  return new Intl.DateTimeFormat(locale, options).format(date);
}

/** Full date and time, for tooltips and detail pages. */
export function formatDateTime(ms: number, locale: string): string {
  return new Intl.DateTimeFormat(locale, {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  }).format(new Date(ms));
}

/** An axis label: the time for short ranges, the day for long ones. */
export function formatTick(ms: number, spanMs: number, locale: string): string {
  const options: Intl.DateTimeFormatOptions =
    spanMs > 2 * 24 * 3600_000
      ? { month: 'short', day: 'numeric' }
      : { hour: '2-digit', minute: '2-digit' };
  return new Intl.DateTimeFormat(locale, options).format(new Date(ms));
}
