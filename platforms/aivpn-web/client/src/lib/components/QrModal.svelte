<script lang="ts">
  import { onMount } from 'svelte';
  import QRCode from 'qrcode';
  import { X } from 'lucide-svelte';

  let { open, data, title, onClose }: {
    open: boolean;
    data: string;
    title: string;
    onClose: () => void;
  } = $props();

  let qrDataUrl = $state('');
  let error = $state('');

  $effect(() => {
    if (open && data) {
      QRCode.toDataURL(data, { width: 256, margin: 2 })
        .then((url) => { qrDataUrl = url; })
        .catch((e: Error) => { error = e.message; });
    }
  });
</script>

{#if open}
  <div class="fixed inset-0 z-50 flex items-center justify-center">
    <button class="absolute inset-0 bg-black/60" onclick={onClose}></button>
    <div class="relative bg-white dark:bg-gray-800 rounded-xl p-6 shadow-2xl max-w-sm w-full mx-4">
      <div class="flex items-center justify-between mb-4">
        <h2 class="text-lg font-semibold text-gray-900 dark:text-white">{title}</h2>
        <button onclick={onClose} class="text-gray-400 hover:text-gray-600 dark:hover:text-gray-200">
          <X size={20} />
        </button>
      </div>
      {#if error}
        <p class="text-red-500 text-sm">{error}</p>
      {:else if qrDataUrl}
        <div class="flex justify-center p-4 bg-white rounded-lg">
          <img src={qrDataUrl} alt="QR Code" class="w-64 h-64" />
        </div>
      {:else}
        <div class="flex justify-center py-8">
          <div class="w-8 h-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin"></div>
        </div>
      {/if}
    </div>
  </div>
{/if}
