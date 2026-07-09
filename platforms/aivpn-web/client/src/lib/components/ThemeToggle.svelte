<script lang="ts">
  import { themeStore } from '$lib/stores/theme.svelte';
  import { Sun, Moon } from 'lucide-svelte';
</script>

<button
  onclick={() => themeStore.toggle()}
  class="p-2 rounded-lg text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
  title="Toggle theme"
>
  {#if themeStore.theme === 'dark'}
    <Sun size={18} />
  {:else}
    <Moon size={18} />
  {/if}
</button>
