import { describe, expect, it } from 'vitest';
import en, { type MessageKey } from './en';
import { LOCALES, dictionaries, intlLocale, pickLocale, translate } from './translate';

const keys = Object.keys(en) as MessageKey[];
const placeholders = (text: string) => [...text.matchAll(/\{(\w+)\}/g)].map((m) => m[1]).sort();

describe('dictionaries', () => {
  it('translate every message, with no empty text', () => {
    for (const locale of LOCALES) {
      for (const key of keys) {
        expect(dictionaries[locale][key], `${locale} ${key}`).toBeTruthy();
      }
    }
  });

  it('use the same {placeholders} as English', () => {
    for (const locale of LOCALES) {
      for (const key of keys) {
        expect(placeholders(dictionaries[locale][key]), `${locale} ${key}`).toEqual(placeholders(en[key]));
      }
    }
  });

  it('close every direction mark they open (Arabic)', () => {
    for (const key of keys) {
      const text = dictionaries.ar[key];
      const opened = [...text].filter((c) => c === '⁦' || c === '⁧' || c === '⁨').length;
      const closed = [...text].filter((c) => c === '⁩').length;
      expect(closed, key).toBe(opened);
    }
  });
});

describe('translate', () => {
  it('fills in values', () => {
    expect(translate('en', 'incident.title', { id: '#3' })).toBe('Incident #3');
    expect(translate('fr', 'incident.title', { id: '#3' })).toContain('#3');
  });

  it('wraps values in isolate marks in Arabic only', () => {
    expect(translate('ar', 'incident.title', { id: '#3' })).toContain('⁨#3⁩');
    expect(translate('en', 'incident.title', { id: '#3' })).not.toMatch(/[⁦-⁩]/);
  });

  it('leaves a missing value visible instead of hiding it', () => {
    expect(translate('en', 'incident.title')).toBe('Incident {id}');
  });
});

describe('pickLocale', () => {
  it('takes the first language the dashboard knows', () => {
    expect(pickLocale(['de-DE', 'fr-FR', 'en'])).toBe('fr');
    expect(pickLocale(['AR-EG'])).toBe('ar');
  });

  it('falls back to English', () => {
    expect(pickLocale(['de', 'es'])).toBe('en');
    expect(pickLocale([])).toBe('en');
  });
});

describe('intlLocale', () => {
  it('keeps Western digits for Arabic', () => {
    expect(intlLocale('ar')).toBe('ar-u-nu-latn');
    expect(intlLocale('fr')).toBe('fr');
  });
});
