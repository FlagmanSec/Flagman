<!--
  The root: decides between the sign-in screen and the dashboard.
  The token arrives in the link flagmand prints (#token=…), see lib/token.ts.
-->
<script lang="ts">
  import { onUnauthorized } from './lib/api';
  import { forgetToken, loadToken, takeTokenFromUrl } from './lib/token';
  import SignIn from './components/SignIn.svelte';
  import Shell from './components/Shell.svelte';

  takeTokenFromUrl();
  let signedIn = $state(loadToken() !== null);
  let refused = $state(false);

  onUnauthorized(() => {
    forgetToken();
    refused = signedIn;
    signedIn = false;
  });

  function signOut() {
    forgetToken();
    refused = false;
    signedIn = false;
  }
</script>

{#if signedIn}
  <Shell onsignout={signOut} />
{:else}
  <SignIn
    {refused}
    onsignin={() => {
      refused = false;
      signedIn = true;
    }}
  />
{/if}
