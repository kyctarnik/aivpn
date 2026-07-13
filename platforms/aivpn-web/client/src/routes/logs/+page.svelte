<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { createQuery } from '@tanstack/svelte-query';
  import { auditLog, events } from '$lib/api';
  import type { AuditLogEntry } from '$lib/api';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import { Search } from 'lucide-svelte';

  const query = createQuery({ queryKey: ['audit-log'], queryFn: () => auditLog.list(200) });

  let search = $state('');
  let filterResult = $state('');
  let autoScroll = $state(true);
  let liveEntries = $state<AuditLogEntry[]>([]);
  let es: EventSource | null = null;
  let tableEl: HTMLElement | undefined;
  let reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  let destroyed = false;

  async function connectSSE() {
    // EventSource cannot set an Authorization header, so /api/v1/events would
    // always 401 through the proxy. Mint a short-lived single-use SSE ticket
    // over an authenticated POST (same pattern as the dashboard) — the general
    // access token must never appear in a URL.
    let ticket: string;
    try {
      ticket = await events.ticket();
    } catch {
      if (!destroyed) reconnectTimer = setTimeout(connectSSE, 5000);
      return;
    }
    if (destroyed) return;
    es = new EventSource(`/web/events?ticket=${encodeURIComponent(ticket)}`);
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data) as { type?: string; entry?: AuditLogEntry };
        if (parsed.type === 'audit' && parsed.entry) {
          liveEntries = [...liveEntries, parsed.entry];
          if (autoScroll && tableEl) {
            setTimeout(() => tableEl?.scrollIntoView({ block: 'end' }), 50);
          }
        }
      } catch { /* ignore */ }
    };
    es.onerror = () => {
      es?.close();
      if (!destroyed) reconnectTimer = setTimeout(connectSSE, 5000);
    };
  }

  onMount(connectSSE);
  onDestroy(() => {
    destroyed = true;
    if (reconnectTimer !== null) clearTimeout(reconnectTimer);
    es?.close();
  });

  const allEntries = $derived([...($query.data ?? []), ...liveEntries]);

  const filtered = $derived(allEntries.filter((e) => {
    const matchSearch = !search || [e.actor, e.action, e.target].some((f) => f?.toLowerCase().includes(search.toLowerCase()));
    const matchResult = !filterResult || e.result === filterResult;
    return matchSearch && matchResult;
  }));
</script>

<div class="space-y-4">
  <div class="flex items-center justify-between">
    <h1 class="text-2xl font-bold text-gray-900 dark:text-white">Audit Log</h1>
    <label class="flex items-center gap-2 text-sm text-gray-600 dark:text-gray-400 cursor-pointer">
      <input type="checkbox" bind:checked={autoScroll} class="rounded" />
      Auto-scroll
    </label>
  </div>

  <div class="flex items-center gap-3">
    <div class="relative flex-1 max-w-xs">
      <Search class="absolute left-3 top-1/2 -translate-y-1/2 text-gray-400" size={16} />
      <input
        type="text"
        bind:value={search}
        placeholder="Search..."
        class="w-full pl-9 pr-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-indigo-500"
      />
    </div>
    <select
      bind:value={filterResult}
      class="px-3 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-800 text-sm text-gray-900 dark:text-white focus:outline-none"
    >
      <option value="">All Results</option>
      <option value="success">Success</option>
      <option value="error">Error</option>
    </select>
  </div>

  <div class="bg-white dark:bg-gray-800 rounded-xl border border-gray-200 dark:border-gray-700 overflow-hidden">
    <div class="overflow-x-auto">
      <table class="w-full text-sm" bind:this={tableEl}>
        <thead class="bg-gray-50 dark:bg-gray-900 text-gray-500 dark:text-gray-400 sticky top-0">
          <tr>
            <th class="px-4 py-3 text-left font-medium">Time</th>
            <th class="px-4 py-3 text-left font-medium">Actor</th>
            <th class="px-4 py-3 text-left font-medium">Action</th>
            <th class="px-4 py-3 text-left font-medium">Target</th>
            <th class="px-4 py-3 text-left font-medium">Result</th>
          </tr>
        </thead>
        <tbody class="divide-y divide-gray-100 dark:divide-gray-700">
          {#each filtered as entry (entry.id)}
            <tr class="hover:bg-gray-50 dark:hover:bg-gray-800/50">
              <td class="px-4 py-2.5 text-gray-500 dark:text-gray-400 text-xs whitespace-nowrap">
                {new Date(entry.ts).toLocaleString()}
              </td>
              <td class="px-4 py-2.5 text-gray-700 dark:text-gray-300 text-xs">{entry.actor}</td>
              <td class="px-4 py-2.5 text-gray-700 dark:text-gray-300 font-mono text-xs">{entry.action}</td>
              <td class="px-4 py-2.5 text-gray-600 dark:text-gray-400 text-xs">{entry.target}</td>
              <td class="px-4 py-2.5">
                <StatusBadge
                  status={entry.result}
                  variant={entry.result === 'success' ? 'success' : 'error'}
                />
              </td>
            </tr>
          {/each}
          {#if filtered.length === 0}
            <tr>
              <td colspan="5" class="px-4 py-8 text-center text-gray-400">No log entries</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
  </div>
</div>
