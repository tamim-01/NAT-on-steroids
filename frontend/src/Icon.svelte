<script lang="ts">
  export let name: string;
  export let size = 22;
  const paths: Record<string, string> = {
    palette: 'M12 3a9 9 0 1 0 0 18h2a2 2 0 0 0 1-4c-1-1 0-2 1-2h2a3 3 0 0 0 3-3 9 9 0 0 0-9-9ZM7 10h.1M10 6h.1M15 7h.1M7 15h.1',
    settings: 'M4 7h16M4 17h16M8 4v6m8 4v6',
    shield: 'M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z',
    power: 'M12 3v9m-6-6a8 8 0 1 0 12 0',
    globe: 'M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0ZM3 12h18M12 3c4 5 4 13 0 18-4-5-4-13 0-18Z',
    arrow: 'm8 5 7 7-7 7',
    check: 'm5 12 4 4L19 6',
    chevron: 'm6 9 6 6 6-6',
    account: 'M16 7a4 4 0 1 1-8 0 4 4 0 0 1 8 0ZM4 21v-2a8 8 0 0 1 16 0v2',
    refresh: 'M20 7v5h-5M4 17v-5h5M6 6a8 8 0 0 1 13 3M5 15a8 8 0 0 0 13 3',
    info: 'M12 11v6m0-10v.1M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
    upload: 'M12 20V4m-6 6 6-6 6 6',
    download: 'M12 4v16m-6-6 6 6 6-6',
    lock: 'M7 10V7a5 5 0 0 1 10 0v3M5 10h14v11H5V10Zm7 4v3',
    close: 'm6 6 12 12M18 6 6 18',
    logout: 'M9 4H4v16h5m5-12 4 4-4 4m-5-4h12',
  };
</script>
<svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[name] || paths.shield} /></svg>
