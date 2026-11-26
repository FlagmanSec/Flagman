<!-- Shown when there is no valid token: explains where the link comes from. -->
<script lang="ts">
  import { t } from '../lib/i18n/index.svelte';
  import { saveToken, tokenFromHash } from '../lib/token';
  import Settings from './Settings.svelte';

  let { refused, onsignin }: { refused: boolean; onsignin: () => void } = $props();

  let pasted = $state('');
  let remember = $state(false);
  let invalid = $state(false);

  function submit(event: SubmitEvent) {
    event.preventDefault();
    // Accept the bare token or the whole link.
    const text = pasted.trim();
    const token = tokenFromHash(text.includes('#') ? text.slice(text.indexOf('#')) : `token=${text}`);
    if (!token) {
      invalid = true;
      return;
    }
    saveToken(token, remember);
    onsignin();
  }
</script>

<main class="signin">
  <div class="card box">
    <div class="brand">
      <img src="/favicon.svg" alt="" width="32" height="32" />
      <div>
        <div class="name">{t('app.name')}</div>
        <div class="muted small">{t('app.tagline')}</div>
      </div>
    </div>
    <h1>{t('signin.title')}</h1>
    <p>{t('signin.text')}</p>
    <pre class="mono ltr">sudo flagmand token</pre>
    {#if refused || invalid}
      <p class="error" role="alert">{t('signin.refused')}</p>
    {/if}
    <form onsubmit={submit}>
      <label for="token">{t('signin.paste')}</label>
      <input
        id="token"
        class="mono ltr"
        type="password"
        autocomplete="off"
        spellcheck="false"
        bind:value={pasted}
        oninput={() => (invalid = false)}
      />
      <label class="check">
        <input type="checkbox" bind:checked={remember} />
        {t('signin.remember')}
      </label>
      <button type="submit" class="primary" disabled={!pasted.trim()}>{t('signin.submit')}</button>
    </form>
  </div>
  <div class="settings"><Settings /></div>
</main>

<style>
  .signin {
    min-height: 100vh;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 24px 16px;
  }
  .box {
    width: min(460px, 100%);
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 24px;
  }
  .brand {
    display: flex;
    align-items: center;
    gap: 10px;
  }
  .name {
    font-weight: 700;
    font-size: 1.1rem;
  }
  .small {
    font-size: 0.85rem;
  }
  p {
    margin: 0;
  }
  pre {
    margin: 0;
    padding: 10px 12px;
    background: var(--page);
    border: 1px solid var(--border);
    border-radius: 8px;
  }
  form {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .check {
    display: flex;
    align-items: center;
    gap: 8px;
  }
  .check input {
    min-height: auto;
  }
  .error {
    color: var(--ink);
    border-inline-start: 3px solid var(--critical);
    padding-inline-start: 10px;
  }
  .primary {
    background: var(--link);
    color: #fff;
    border-color: transparent;
    font-weight: 600;
  }
  .primary:hover:not(:disabled) {
    background: var(--link);
    filter: brightness(1.1);
  }
</style>
