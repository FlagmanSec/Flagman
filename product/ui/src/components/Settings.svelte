<!-- Language and theme pickers. -->
<script lang="ts">
  import { LOCALES, LOCALE_NAMES, locale, setLocale, t, type Locale } from '../lib/i18n/index.svelte';
  import { setTheme, theme, type Theme } from '../lib/theme.svelte';

  const themes: Theme[] = ['auto', 'light', 'dark'];
</script>

<div class="settings">
  <label>
    <span class="visually-hidden">{t('settings.language')}</span>
    <select
      aria-label={t('settings.language')}
      value={locale()}
      onchange={(event) => setLocale(event.currentTarget.value as Locale)}
    >
      {#each LOCALES as code (code)}
        <option value={code} lang={code}>{LOCALE_NAMES[code]}</option>
      {/each}
    </select>
  </label>
  <label>
    <span class="visually-hidden">{t('settings.theme')}</span>
    <select
      aria-label={t('settings.theme')}
      value={theme()}
      onchange={(event) => setTheme(event.currentTarget.value as Theme)}
    >
      {#each themes as option (option)}
        <option value={option}>{t(`theme.${option}`)}</option>
      {/each}
    </select>
  </label>
</div>

<style>
  .settings {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  select {
    min-height: 32px;
    padding: 4px 8px;
  }
</style>
