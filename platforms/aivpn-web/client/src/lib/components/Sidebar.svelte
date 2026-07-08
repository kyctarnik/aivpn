<script lang="ts">
  import { page } from '$app/stores';
  import { goto } from '$app/navigation';
  import { authStore } from '$lib/stores/auth.svelte';
  import { auth } from '$lib/api';
  import {
    LayoutDashboard, Users, Settings2, Shield, Archive,
    ScrollText, Settings, LogOut, Radio
  } from 'lucide-svelte';

  const navItems = [
    { href: '/dashboard', label: 'Dashboard', icon: LayoutDashboard },
    { href: '/clients', label: 'Clients', icon: Users },
    { href: '/config', label: 'Config', icon: Settings2 },
    { href: '/masks', label: 'Masks', icon: Shield },
    { href: '/backup', label: 'Backup', icon: Archive },
    { href: '/logs', label: 'Logs', icon: ScrollText },
    { href: '/settings', label: 'Settings', icon: Settings },
  ];

  async function handleLogout() {
    try {
      await auth.logout();
    } catch {
      // ignore
    }
    authStore.clearToken();
    goto('/login');
  }
</script>

<aside class="fixed left-0 top-0 h-full w-60 bg-gray-900 dark:bg-gray-950 flex flex-col border-r border-gray-700 z-20">
  <div class="px-6 py-5 border-b border-gray-700">
    <div class="flex items-center gap-2">
      <Radio class="text-indigo-400" size={20} />
      <span class="text-white font-bold text-lg tracking-tight">aiVPN</span>
    </div>
  </div>

  <nav class="flex-1 px-3 py-4 space-y-1 overflow-y-auto">
    {#each navItems as item}
      {@const active = $page.url.pathname.startsWith(item.href)}
      <a
        href={item.href}
        class="flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors
          {active
            ? 'bg-indigo-600 text-white'
            : 'text-gray-400 hover:text-white hover:bg-gray-800'}"
      >
        <item.icon size={18} />
        {item.label}
      </a>
    {/each}
  </nav>

  <div class="px-3 py-4 border-t border-gray-700">
    <div class="px-3 py-2 mb-2">
      <p class="text-xs text-gray-500 truncate">{authStore.user?.username ?? ''}</p>
      <p class="text-xs text-gray-600 capitalize">{authStore.user?.role ?? ''}</p>
    </div>
    <button
      onclick={handleLogout}
      class="flex items-center gap-3 w-full px-3 py-2 rounded-lg text-sm font-medium text-gray-400 hover:text-white hover:bg-gray-800 transition-colors"
    >
      <LogOut size={18} />
      Logout
    </button>
  </div>
</aside>
