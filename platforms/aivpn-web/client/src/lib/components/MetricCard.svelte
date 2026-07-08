<script lang="ts">
  import type { Component } from 'svelte';
  let { title, value, subtitle, icon: Icon }: {
    title: string;
    value: string | number;
    subtitle?: string;
    icon?: Component;
  } = $props();
</script>

<div class="bg-white dark:bg-gray-800 rounded-xl p-5 border border-gray-200 dark:border-gray-700 shadow-sm">
  <div class="flex items-start justify-between">
    <div>
      <p class="text-sm text-gray-500 dark:text-gray-400">{title}</p>
      <p class="text-2xl font-bold text-gray-900 dark:text-white mt-1">{value}</p>
      {#if subtitle}
        <p class="text-xs text-gray-400 mt-1">{subtitle}</p>
      {/if}
    </div>
    {#if Icon}
      <div class="p-2 bg-indigo-50 dark:bg-indigo-900/30 rounded-lg">
        <Icon size={20} class="text-indigo-600 dark:text-indigo-400" />
      </div>
    {/if}
  </div>
</div>
