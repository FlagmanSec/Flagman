import { describe, expect, it } from 'vitest';
import { columnPath, labelIndexes, nearestIndex, niceTicks } from './scale';

describe('niceTicks', () => {
  it('gives a 0 to 1 axis when there is no data', () => {
    expect(niceTicks(0)).toEqual([0, 1]);
    expect(niceTicks(Number.NaN)).toEqual([0, 1]);
  });

  it('picks round steps', () => {
    expect(niceTicks(150_000)).toEqual([0, 50_000, 100_000, 150_000]);
    expect(niceTicks(7, 4, true)).toEqual([0, 2, 4, 6, 8]);
    expect(niceTicks(3, 4, true)).toEqual([0, 1, 2, 3]);
  });

  it('never uses fractions for counts', () => {
    for (const ticks of [niceTicks(1, 4, true), niceTicks(2, 4, true)]) {
      expect(ticks.every(Number.isInteger)).toBe(true);
    }
  });

  it('always starts at 0 and reaches the largest value', () => {
    for (const max of [0.3, 1, 9, 42, 999, 1_234, 87_654, 3.2e9]) {
      const ticks = niceTicks(max);
      expect(ticks[0]).toBe(0);
      expect(ticks[ticks.length - 1]).toBeGreaterThanOrEqual(max);
      expect(ticks.length).toBeLessThanOrEqual(7);
    }
  });
});

describe('labelIndexes', () => {
  it('labels every point when there are few', () => {
    expect(labelIndexes(0)).toEqual([]);
    expect(labelIndexes(3, 5)).toEqual([0, 1, 2]);
  });

  it('spreads about the asked number of labels', () => {
    expect(labelIndexes(60, 5)).toEqual([0, 12, 24, 36, 48]);
  });
});

describe('nearestIndex', () => {
  it('snaps to the closest point and stays inside the data', () => {
    // 5 points spread over 400 px starting at x = 50: one every 100 px.
    expect(nearestIndex(50, 50, 400, 5)).toBe(0);
    expect(nearestIndex(240, 50, 400, 5)).toBe(2);
    expect(nearestIndex(-100, 50, 400, 5)).toBe(0);
    expect(nearestIndex(9_999, 50, 400, 5)).toBe(4);
    expect(nearestIndex(123, 50, 400, 1)).toBe(0);
  });
});

describe('columnPath', () => {
  it('rounds the top corners by 4 px', () => {
    expect(columnPath(0, 0, 10, 20)).toBe('M0,20 V4 Q0,0 4,0 H6 Q10,0 10,4 V20 Z');
  });

  it('shrinks the rounding for tiny columns', () => {
    expect(columnPath(0, 18, 10, 2)).toBe('M0,20 V20 Q0,18 2,18 H8 Q10,18 10,20 V20 Z');
  });
});
