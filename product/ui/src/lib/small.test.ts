// Tests for the small helpers: addresses, links, routes, periods, ports, token.
import { describe, expect, it } from 'vitest';
import { tacticUrl, techniqueUrl } from './attack';
import { isLocal } from './net';
import { parseRange, withParams } from './ranges';
import { matchRoute } from './routes';
import { portLabel } from './services';
import { loadToken, tokenFromHash } from './token';

describe('isLocal (same rules as flagman-core net.rs)', () => {
  it('knows the private IPv4 ranges', () => {
    for (const ip of ['10.1.2.3', '172.16.0.1', '172.31.255.255', '192.168.1.5', '169.254.1.1', '127.0.0.1']) {
      expect(isLocal(ip), ip).toBe(true);
    }
    for (const ip of ['172.15.0.1', '172.32.0.1', '8.8.8.8', '100.64.0.1', '1.2.3', 'garbage', '256.1.1.1']) {
      expect(isLocal(ip), ip).toBe(false);
    }
  });

  it('knows the local IPv6 ranges', () => {
    for (const ip of ['::1', 'fe80::1', 'FE80::1', 'fd12:3456::1', 'fc00::1', 'febf::1']) {
      expect(isLocal(ip), ip).toBe(true);
    }
    // "fd1::" means 0fd1::, which is a public address.
    for (const ip of ['2001:db8::1', 'fd1::1', 'fe8::1', 'fec0::1', '::ffff:192.168.1.1']) {
      expect(isLocal(ip), ip).toBe(false);
    }
  });
});

describe('MITRE ATT&CK links', () => {
  it('builds technique and sub-technique pages', () => {
    expect(techniqueUrl('T1046')).toBe('https://attack.mitre.org/techniques/T1046/');
    expect(techniqueUrl('T1110.001')).toBe('https://attack.mitre.org/techniques/T1110/001/');
    expect(tacticUrl('TA0007')).toBe('https://attack.mitre.org/tactics/TA0007/');
  });

  it('refuses anything else', () => {
    expect(techniqueUrl('javascript:alert(1)')).toBeNull();
    expect(techniqueUrl('T104')).toBeNull();
    expect(tacticUrl('T1046')).toBeNull();
  });
});

describe('matchRoute', () => {
  it('finds each page', () => {
    expect(matchRoute('/')).toEqual({ name: 'overview' });
    expect(matchRoute('')).toEqual({ name: 'overview' });
    expect(matchRoute('/incidents')).toEqual({ name: 'incidents' });
    expect(matchRoute('/incidents/')).toEqual({ name: 'incidents' });
    expect(matchRoute('/incidents/12')).toEqual({ name: 'incident', id: 12 });
    expect(matchRoute('/flows')).toEqual({ name: 'flows' });
  });

  it('sends anything else to "not found"', () => {
    expect(matchRoute('/incidents/abc')).toEqual({ name: 'not_found' });
    expect(matchRoute('/incidents/1234567890123456')).toEqual({ name: 'not_found' });
    expect(matchRoute('/settings')).toEqual({ name: 'not_found' });
  });
});

describe('periods', () => {
  it('accepts only the periods the API knows', () => {
    expect(parseRange('7d', '1h')).toBe('7d');
    expect(parseRange('2y', '1h')).toBe('1h');
    expect(parseRange(null, '24h')).toBe('24h');
  });

  it('changes query parameters and removes empty ones', () => {
    expect(withParams('/flows', '?range=1h', { ip: '10.0.0.1' })).toBe('/flows?range=1h&ip=10.0.0.1');
    expect(withParams('/flows', '?range=1h&ip=10.0.0.1', { ip: '', range: null })).toBe('/flows');
  });
});

describe('portLabel', () => {
  it('adds the service name when it is well known', () => {
    expect(portLabel(22)).toBe('22 (SSH)');
    expect(portLabel(40_000)).toBe('40000');
  });
});

describe('token', () => {
  const token = 'a'.repeat(64);

  it('reads the token from the link fragment', () => {
    expect(tokenFromHash(`#token=${token}`)).toBe(token);
    expect(tokenFromHash(`#x=1&token=${token}`)).toBe(token);
  });

  it('ignores anything that does not look like a token', () => {
    expect(tokenFromHash('')).toBeNull();
    expect(tokenFromHash('#token=short')).toBeNull();
    expect(tokenFromHash(`#token=${'a'.repeat(31)}<script>`)).toBeNull();
  });

  it('does not crash when the browser has no storage', () => {
    expect(loadToken()).toBeNull();
  });
});
