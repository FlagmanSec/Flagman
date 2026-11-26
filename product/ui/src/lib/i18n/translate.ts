// Filling a message: "Watching {source}" + { source: "eth0" } -> "Watching eth0".

import ar from './ar';
import en, { type MessageKey } from './en';
import fr from './fr';

export type Locale = 'en' | 'fr' | 'ar';
export type Params = Record<string, string | number>;

export const LOCALES: readonly Locale[] = ['en', 'fr', 'ar'];

export const LOCALE_NAMES: Record<Locale, string> = {
  en: 'English',
  fr: 'Français',
  ar: 'العربية',
};

export const dictionaries: Record<Locale, Record<MessageKey, string>> = { en, fr, ar };

/** The locale given to Intl. Arabic keeps Western digits, like IP addresses. */
export function intlLocale(locale: Locale): string {
  return locale === 'ar' ? 'ar-u-nu-latn' : locale;
}

// In right-to-left text, a filled-in value (an IP address, "#3", a port) is
// wrapped in invisible "isolate" marks, so its characters keep their order.
// Left-to-right languages skip this, so copied addresses stay clean.
const ISOLATE_START = '\u2068';
const ISOLATE_END = '\u2069';

export function translate(locale: Locale, key: MessageKey, params: Params = {}): string {
  const template = dictionaries[locale][key] ?? en[key];
  const rtl = locale === 'ar';
  return template.replace(/\{(\w+)\}/g, (whole, name: string) => {
    if (!(name in params)) return whole;
    const value = String(params[name]);
    return rtl ? `${ISOLATE_START}${value}${ISOLATE_END}` : value;
  });
}

/** The best locale for a browser language list such as ["fr-FR", "en"]. */
export function pickLocale(languages: readonly string[]): Locale {
  for (const language of languages) {
    const base = language.toLowerCase().split('-')[0];
    if (base === 'en' || base === 'fr' || base === 'ar') return base;
  }
  return 'en';
}
