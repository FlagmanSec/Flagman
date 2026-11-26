import { describe, expect, it } from 'vitest';
import { compactNumber, formatBytes, formatDuration, formatList, formatNumber } from './format';

// Intl uses special spaces (no-break, narrow no-break) in French. The tests
// compare with plain spaces so they stay readable.
const plain = (text: string) => text.replace(/\s/g, ' ');

describe('formatNumber', () => {
  it('groups digits the way each language does', () => {
    expect(formatNumber(1_234_567, 'en')).toBe('1,234,567');
    expect(plain(formatNumber(1_234_567, 'fr'))).toBe('1 234 567');
  });

  it('keeps Western digits in Arabic', () => {
    expect(formatNumber(2676, 'ar-u-nu-latn')).toMatch(/^2.?676$/);
  });
});

describe('compactNumber', () => {
  it('writes small numbers in full', () => {
    expect(compactNumber(9_999, 'en')).toBe('9,999');
  });

  it('shortens large numbers', () => {
    expect(compactNumber(12_900, 'en')).toBe('12.9K');
  });
});

describe('formatBytes', () => {
  it('uses the long name for plain bytes', () => {
    expect(formatBytes(0, 'en')).toBe('0 bytes');
    expect(formatBytes(1, 'en')).toBe('1 byte');
    expect(formatBytes(112, 'en')).toBe('112 bytes');
    expect(plain(formatBytes(112, 'fr'))).toBe('112 octets');
  });

  it('uses decimal units with one decimal below 100', () => {
    expect(formatBytes(1_500, 'en')).toBe('1.5 kB');
    expect(formatBytes(150_000, 'en')).toBe('150 kB');
    expect(formatBytes(1_500_000, 'en')).toBe('1.5 MB');
    expect(plain(formatBytes(1_500, 'fr'))).toBe('1,5 ko');
  });

  it('stops at terabytes', () => {
    expect(formatBytes(5e15, 'en')).toBe('5,000 TB');
  });
});

describe('formatDuration', () => {
  it('writes seconds, then minutes and seconds, then hours', () => {
    expect(plain(formatDuration(10_000, 'en'))).toBe('10 sec');
    expect(plain(formatDuration(65_000, 'en'))).toBe('1 min 5 sec');
    expect(plain(formatDuration(3_600_000, 'en'))).toBe('1 hr');
  });

  it('switches to days after two days', () => {
    expect(plain(formatDuration(3 * 24 * 3_600_000, 'en'))).toBe('3 days');
  });
});

describe('formatList', () => {
  it('joins with the word for "and" of each language', () => {
    expect(formatList(['A', 'B', 'C'], 'en')).toBe('A, B, and C');
    expect(formatList(['A', 'B', 'C'], 'fr')).toBe('A, B et C');
    expect(formatList(['A', 'B'], 'ar-u-nu-latn')).toBe('A وB');
  });

  it('returns a single item unchanged', () => {
    expect(formatList(['A'], 'en')).toBe('A');
  });
});
