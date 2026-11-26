<!-- A small shape that says the state without colour alone:
     check (good), triangle (warning), octagon (critical), circle (neutral). -->
<script lang="ts">
  let { level }: { level: 'good' | 'warning' | 'critical' | 'neutral' } = $props();
</script>

<svg class="icon {level}" viewBox="0 0 16 16" width="14" height="14" aria-hidden="true">
  {#if level === 'good'}
    <circle cx="8" cy="8" r="7" />
    <path d="M4.5 8.2l2.2 2.2 4.8-4.8" fill="none" stroke="#fff" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" />
  {:else if level === 'warning'}
    <path d="M8 1.5l7 12.5H1z" />
    <path d="M8 6v4" stroke="#0b0b0b" stroke-width="1.6" stroke-linecap="round" />
    <circle cx="8" cy="12" r="0.9" fill="#0b0b0b" />
  {:else if level === 'critical'}
    <path d="M5.1 1h5.8L15 5.1v5.8L10.9 15H5.1L1 10.9V5.1z" />
    <path d="M8 4.5v4.2" stroke="#fff" stroke-width="1.6" stroke-linecap="round" />
    <circle cx="8" cy="11.3" r="0.9" fill="#fff" />
  {:else}
    <circle cx="8" cy="8" r="6" />
  {/if}
</svg>

<style>
  .icon {
    flex: none;
    vertical-align: -2px;
  }
  .good {
    fill: var(--good);
  }
  .warning {
    fill: var(--warning);
  }
  .critical {
    fill: var(--critical);
  }
  .neutral {
    fill: var(--sev-low);
  }
</style>
