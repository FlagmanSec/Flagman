// The current language, and `t()` to translate. Components that call `t()`
// update by themselves when the language changes.

import type { MessageKey } from './en';
import { intlLocale, pickLocale, translate, type Locale, type Params } from './translate';

export type { MessageKey } from './en';
export { LOCALES, LOCALE_NAMES, type Locale } from './translate';

const STORAGE_KEY = 'flagman.locale';

function initialLocale(): Locale {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === 'en' || saved === 'fr' || saved === 'ar') return saved;
  } catch {
    // Storage blocked: fall back to the browser's languages.
  }
  return pickLocale(navigator.languages ?? [navigator.language]);
}

const state = $state({ locale: initialLocale() });

function applyToDocument(locale: Locale): void {
  document.documentElement.lang = locale;
  document.documentElement.dir = locale === 'ar' ? 'rtl' : 'ltr';
}

applyToDocument(state.locale);

export function locale(): Locale {
  return state.locale;
}

/** The locale string for number and date formatting. */
export function fmt(): string {
  return intlLocale(state.locale);
}

export function setLocale(next: Locale): void {
  state.locale = next;
  applyToDocument(next);
  try {
    localStorage.setItem(STORAGE_KEY, next);
  } catch {
    // Not remembered; still applied for this visit.
  }
}

export function t(key: MessageKey, params?: Params): string {
  return translate(state.locale, key, params);
}
