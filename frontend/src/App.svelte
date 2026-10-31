<script lang="ts">
  import { onMount, tick } from 'svelte';
  import { backend, defaultPreferences, type Preferences, type State, type Location, type SteroidConfig } from './api';
  import Icon from './Icon.svelte';
  import Traffic from './Traffic.svelte';
  import Steroid from './Steroid.svelte';
  import { quotaBytes } from './format';

  let state: State = { steroidConfig:{pacPort:8099,rules:[]},observedDomains:[],directIp:'',directUpload:0,directDownload:0, preferences: {...defaultPreferences}, accounts: [], pendingEmail:'', socksPort:1088, httpPort:8088, status: 'disconnected', signedIn: false, needsCode: false, email: '', locations: [], serverPingsChecking: false, serverPingsCompleted: 0, serverPingsTotal: 0, serverPingsCheckedAt: 0, serverPingsError: '', country: '', mode: 'tun', ip: '', since: 0, upload: 0, download: 0, uploadSpeed: 0, downloadSpeed: 0, latencyMs: -1, latencyCheckedAt: 0, latencyChecking: false, latencyError: '', quotaLimit: 0, quotaRemaining: -1, error: '', notice: '' };
  let country = '';
  let serversExpanded = false;
  let refreshingPings = false;
  let mode = 'tun';
  let email = '';
  let password = '';
  let code = '';
  let busy = false;
  let error = '';
  let clock = Date.now();
  let showAppearance = false;
  let preferences = {...defaultPreferences};
  let preferenceSaving = false;
  let preferenceError = '';
  let preferenceVersion = 0;
  const themes = [
    {id:'midnight',name:'Midnight',colors:['#0c1425','#a8c7ff','#8ed5b3']},
    {id:'nord',name:'Nord',colors:['#242b39','#88c0d0','#a3be8c']},
    {id:'dracula',name:'Dracula',colors:['#1d1b2b','#bd93f9','#ff79c6']},
    {id:'forest',name:'Forest',colors:['#0b1b18','#8bd5aa','#d4c18a']},
    {id:'ember',name:'Ember',colors:['#201715','#ffb48b','#f7cf81']},
    {id:'daylight',name:'Daylight',colors:['#eef2f8','#315ca8','#a14477']},
  ];
  const latencyPresets = [{seconds:1,label:'1 second'},{seconds:15,label:'15 seconds'},{seconds:30,label:'30 seconds'},{seconds:45,label:'45 seconds'},{seconds:60,label:'1 minute'},{seconds:600,label:'10 minutes'},{seconds:900,label:'15 minutes'}];
  let latencyChoice = '30';
  let customInterval: number | undefined = 40;
  $: intervalLabel = latencyPresets.find(option=>option.seconds===preferences.latencyRefreshSeconds)?.label || `${preferences.latencyRefreshSeconds} seconds`;
  $: if (typeof document !== 'undefined') document.documentElement.dataset.theme = preferences.theme;
  let showAbout = false;
  let showAccount = false;
  let showAddAccount = false;
  let showPorts = false;
  let socksPort: number | undefined = 1088;
  let httpPort: number | undefined = 8088;
  let portsSaved = false;
  let pollPending = false;
  let refreshingQuota = '';
  let testingLatency = false;
  let latencyActionError = '';
  $: connected = state.status === 'connected';
  $: connecting = state.status === 'connecting';
  $: elapsed = state.since ? Math.max(0, Math.floor(clock / 1000) - state.since) : 0;
  $: time = `${Math.floor(elapsed / 3600).toString().padStart(2, '0')}:${Math.floor(elapsed % 3600 / 60).toString().padStart(2, '0')}:${(elapsed % 60).toString().padStart(2, '0')}`;
  $: selectedLocation = state.locations.find(location => location.code === country);
  $: locationName = selectedLocation?.name || 'Choose a location';
  $: activeAccount = state.accounts.find(account => account.email === state.email);
  $: scanning = refreshingPings || state.serverPingsChecking;

  function focusDialog(node: HTMLElement) {
    const previous = document.activeElement as HTMLElement | null;
    node.focus();
    function trap(event: KeyboardEvent) {
      if (event.key !== 'Tab') return;
      const controls = Array.from(node.querySelectorAll<HTMLElement>('button:not(:disabled), input:not(:disabled), select:not(:disabled), [tabindex="0"]'));
      const first = controls[0], last = controls[controls.length - 1];
      if (!first) { event.preventDefault(); return; }
      if (event.shiftKey && (document.activeElement === first || document.activeElement === node)) { event.preventDefault(); last.focus(); }
      else if (!event.shiftKey && (document.activeElement === last || document.activeElement === node)) { event.preventDefault(); first.focus(); }
    }
    node.addEventListener('keydown', trap);
    return { destroy() { node.removeEventListener('keydown', trap); previous?.focus(); } };
  }
  async function poll() {
    if (pollPending) return;
    pollPending = true;
    const version = preferenceVersion;
    try {
      state = await backend().GetState();
      state.locations ||= [];
      state.accounts ||= [];
      state.steroidConfig ||= {pacPort:8099,rules:[]};
      state.observedDomains ||= [];
      if (state.status === 'connected' || state.status === 'connecting') mode = state.mode;
      if (!preferenceSaving && version === preferenceVersion) preferences = {...defaultPreferences,...state.preferences};
      if (!state.locations.some(location => location.code === country) && state.locations.length) country = state.locations.some(l => l.code === state.country) ? state.country : (state.locations.some(l => l.code === 'US') ? 'US' : state.locations[0].code);
    } catch (e) { error = String(e instanceof Error ? e.message : e); }
    finally { pollPending = false; }
  }
  onMount(() => {
    void poll();
    const timer = setInterval(() => { clock = Date.now(); void poll(); }, 1000);
    return () => clearInterval(timer);
  });
  async function act(action: () => Promise<unknown>) {
    if (busy) return;
    busy = true; error = '';
    try { await action(); } catch (e) { error = String(e instanceof Error ? e.message : e); }
    finally {
      busy = false; await poll(); await tick();
      const dialog = document.querySelector<HTMLElement>('.modal');
      if (dialog && !dialog.contains(document.activeElement)) dialog.focus();
    }
  }
  async function signIn(event: SubmitEvent) {
    event.preventDefault();
    const submitted = password; password = '';
    await act(() => backend().Login(email, submitted));
    if (!error && !state.error && !state.needsCode) showAddAccount = false;
  }
  async function verify(event: SubmitEvent) { event.preventDefault(); const value = code; code = ''; await act(() => backend().Verify(value)); if (!error && !state.error && !state.needsCode) showAddAccount = false; }
  async function closeDialogs() {
    if (busy || preferenceSaving) return;
    if (showAddAccount) { await act(() => backend().CancelVerification()); password = ''; code = ''; }
    showAbout = false; showAccount = false; showAddAccount = false; showPorts = false; showAppearance = false;
  }
  function openPorts() { socksPort = state.socksPort; httpPort = state.httpPort; portsSaved = false; showPorts = true; }
  async function refreshQuota(email: string) {
    if (refreshingQuota || busy) return;
    refreshingQuota = email;
    await act(() => backend().RefreshAccountQuota(email));
    refreshingQuota = '';
  }
  async function testLatency() {
    if (testingLatency || state.latencyChecking) return;
    testingLatency = true; latencyActionError = '';
    try { await backend().MeasureLatency(); }
    catch (e) { latencyActionError = String(e instanceof Error ? e.message : e); }
    finally { testingLatency = false; await poll(); }
  }
  async function refreshPings() {
    if (busy || scanning) return;
    refreshingPings = true;
    try { await act(() => backend().RefreshServerPings()); }
    finally { refreshingPings = false; }
  }
  function locationPing(location: Location) {
    return location.pingCheckedAt > 0 ? location.pingMs >= 0 ? `${location.pingMs} ms` : 'Unavailable' : 'Not tested';
  }
  function flag(code: string) {
    const letters = code.toUpperCase();
    return /^[A-Z]{2}$/.test(letters) ? String.fromCodePoint(...[...letters].map(letter => 127397 + letter.charCodeAt(0))) : '🌐';
  }
  function checkedTime(value: number) { return new Date(value * 1000).toLocaleString(); }
  async function savePorts(event: SubmitEvent) {
    event.preventDefault(); portsSaved = false;
    if (!Number.isInteger(socksPort) || !Number.isInteger(httpPort)) { error = 'Enter a whole number for each port.'; return; }
    await act(() => backend().SavePorts(socksPort!, httpPort!));
    portsSaved = !error && !state.error;
  }
  function openAppearance() {
    latencyChoice = latencyPresets.some(option=>option.seconds===preferences.latencyRefreshSeconds) ? String(preferences.latencyRefreshSeconds) : 'custom';
    customInterval = preferences.latencyRefreshSeconds;
    showAppearance = true;
  }
  async function changePreference(patch: Partial<Preferences>) {
    if (preferenceSaving) return;
    const previous = {...preferences};
    const next = {...preferences,...patch};
    preferenceVersion++;
    preferences = next; preferenceSaving = true; preferenceError = '';
    try { await backend().SavePreferences(next); }
    catch (e) { preferences = previous; preferenceError = String(e instanceof Error ? e.message : e); }
    finally { preferenceSaving = false; await poll(); }
  }
  async function changeInterval(value: string) {
    latencyChoice = value;
    if (value !== 'custom') {
      await changePreference({latencyRefreshSeconds:Number(value)});
      if (preferenceError) latencyChoice = latencyPresets.some(option=>option.seconds===preferences.latencyRefreshSeconds) ? String(preferences.latencyRefreshSeconds) : 'custom';
    }
    else customInterval = preferences.latencyRefreshSeconds;
  }
  async function saveCustomInterval(event: SubmitEvent) {
    event.preventDefault();
    if (!Number.isInteger(customInterval) || customInterval! < 1 || customInterval! > 900) { preferenceError = 'Enter a whole number from 1 to 900 seconds.'; return; }
    await changePreference({latencyRefreshSeconds:customInterval!});
  }

  function modeName(value: string) { return value === 'steroid' ? 'TUN on steroid' : value === 'tun' ? 'System-wide TUN' : 'Local proxy'; }
  async function saveSteroidConfig(config: SteroidConfig) {
    await act(() => backend().SaveSteroidConfig(config));
    return !error;
  }

</script>

{#snippet signInForm()}
  <div class="panel-heading"><div class="symbol"><Icon name="account"/></div><div><h2 id="signin-title">{state.needsCode ? 'Check your email' : showAddAccount ? 'Add a Mozilla account' : 'Make yourself at home'}</h2><p>{state.needsCode ? `Enter the verification code for ${state.pendingEmail}.` : 'Continue with your Mozilla account.'}</p></div></div>
  {#if state.needsCode}
    <form onsubmit={verify}><label for="code">Verification code</label><input id="code" bind:value={code} autocomplete="one-time-code" required disabled={busy}/><button class="primary-button" disabled={busy}>{busy ? 'Verifying…' : 'Verify and continue'}<Icon name="arrow" size={18}/></button><button type="button" class="text-button" disabled={busy} onclick={() => act(() => backend().CancelVerification())}>Back to sign in</button></form>
  {:else}
    <form onsubmit={signIn}><label for="email">Email address</label><input id="email" type="email" placeholder="you@example.com" bind:value={email} autocomplete="username" required disabled={busy}/><label for="password">Password</label><input id="password" type="password" placeholder="Your Mozilla password" bind:value={password} autocomplete="current-password" required disabled={busy}/><button class="primary-button" disabled={busy}>{busy ? 'Signing in…' : 'Sign in'}<Icon name="arrow" size={18}/></button></form>
  {/if}
  <p class="privacy-note"><Icon name="lock" size={14}/>Your password is never saved.</p>
{/snippet}


<svelte:window onkeydown={(event) => { if (event.key === 'Escape') void closeDialogs(); }} />

<div class="shell">
  <header class="topbar">
    <div class="brand">
      <img class="brand-logo" src="/logo.png" width="42" height="42" alt="" />
      <div><span class="wordmark">NAT-on-steroids</span><span class="platform">FOR LINUX</span></div>
    </div>
    <div class="top-actions"><span class="version">0.7.1</span><button class="icon-button" aria-label="Appearance and monitoring" title="Themes and latency refresh" onclick={openAppearance}><Icon name="palette"/></button><button class="icon-button" aria-label="Local proxy settings" onclick={openPorts}><Icon name="settings" /></button><button class="icon-button" aria-label="About NAT-on-steroids" onclick={() => showAbout = true}><Icon name="info" /></button>{#if state.signedIn}<button class="account-button" onclick={() => showAccount = true}><Icon name="account" size={18} /><span>Accounts ({state.accounts.length})</span></button>{/if}</div>
  </header>

  <main>
    <div class="page-heading"><div><h1>Connection overview</h1></div></div>
    {#if (error || state.error || preferenceError) && !showAccount && !showAddAccount && !showPorts && !showAbout && !showAppearance}<div class="alert" role="alert"><Icon name="info" /><span>{error || state.error || preferenceError}</span></div>{/if}
    {#if state.notice}<div class="notice" role="status"><Icon name="lock" size={18} /><span>{state.notice}</span></div>{/if}

    <div class="dashboard">
      <div class="left-column">
        <section class:active={connected} class="connection-card" aria-label="Connection status">
          <div class="card-top"><span class="small-label">CONNECTION</span><span class:online={connected} class="status-chip"><span class="status-dot"></span>{connected ? 'Connected' : connecting ? 'Connecting' : 'Disconnected'}</span></div>
          <div class="connection-hero">
            <div class:spinning={connecting} class="connection-orb" aria-hidden="true"><Icon name={connected ? 'check' : 'shield'} size={32}/></div>
            <div class="connection-message"><h2>{connected ? 'You’re connected' : connecting ? 'Connecting…' : 'Ready to connect'}</h2><p class="connection-subtitle">{connected ? `${locationName} · ${modeName(state.mode)}` : connecting ? 'Verifying the server and traffic.' : state.signedIn ? `${locationName} · ${modeName(mode)}` : 'Sign in with your Mozilla account to get started.'}</p></div>
          </div>
          <button class:tonal={!connected} class="connect-button" disabled={busy || scanning || !state.signedIn || !country} onclick={() => act(() => connected ? backend().Disconnect() : backend().Connect(country, mode))}>{busy ? (connecting ? 'Connecting…' : 'Please wait…') : connected ? 'Disconnect' : 'Connect'}<Icon name={connected ? 'power' : 'arrow'} size={18} /></button>
          <div class="connection-details"><div><span>Exit IP</span><strong>{connected ? state.ip : '—'}</strong></div><div><span>Time connected</span><strong class="timer">{connected ? time : '00:00:00'}</strong></div></div>
          <div class="latency-panel">
            <div class="latency-heading"><span>Server latency</span><strong title={state.latencyCheckedAt ? `Last tested ${checkedTime(state.latencyCheckedAt)}` : undefined}>{connected && state.latencyMs >= 0 ? `${state.latencyMs} ms` : '—'}</strong></div>
            <button class="text-button" disabled={busy || !connected || testingLatency || state.latencyChecking} onclick={testLatency}><Icon name="refresh" size={14}/>{testingLatency || state.latencyChecking ? 'Measuring…' : 'Test latency'}</button>
            <button class="text-button latency-interval-button" onclick={openAppearance}>Auto-refresh: {intervalLabel}<Icon name="settings" size={12}/></button>
            {#if connected && (state.latencyError || latencyActionError)}<small class="latency-error" role="status">{state.latencyError || latencyActionError}</small>{/if}
          </div>
        </section>

      </div>

      <div class="right-column">
        {#if !state.signedIn}
          <section class="panel account-panel">{@render signInForm()}</section>
        {:else}
          <section class="panel location-panel" aria-labelledby="location-title">
            <div class="section-title"><h2 id="location-title">Location</h2><span class="location-count">{state.locations.length} available</span></div>
            <button class="server-toggle" class:expanded={serversExpanded} aria-expanded={serversExpanded} aria-controls="server-browser" aria-label={`${serversExpanded ? 'Collapse' : 'Expand'} server list, ${locationName}`} onclick={() => serversExpanded = !serversExpanded}>
              <span class="server-flag" aria-hidden="true">{selectedLocation ? flag(selectedLocation.code) : '🌐'}</span>
              <span class="server-identity"><strong>{locationName}</strong><small>{serversExpanded ? 'Hide locations' : 'Browse locations'}</small></span>
              <span class="server-ping" class:measured={selectedLocation && selectedLocation.pingCheckedAt > 0 && selectedLocation.pingMs >= 0}>{selectedLocation ? locationPing(selectedLocation) : '—'}</span>
              <span class="disclosure-icon"><Icon name="chevron" size={18}/></span>
            </button>
            <div id="server-browser" class="server-browser" hidden={!serversExpanded}>
              <div class="server-browser-heading"><span id="servers-title">Choose a location</span><button class="icon-button" aria-label="Refresh locations" title="Refresh locations" disabled={busy || connected || connecting} onclick={() => act(() => backend().RefreshLocations())}><Icon name="refresh" size={16}/></button></div>
              <div class="server-list" role="group" aria-labelledby="servers-title" aria-busy={scanning}>
                {#each state.locations as location (location.code)}
                  <button class="server-row" class:chosen={country === location.code} aria-pressed={country === location.code} disabled={busy || connected || connecting} onclick={() => { country = location.code; serversExpanded = false; }}>
                    <span class="server-flag" aria-hidden="true">{flag(location.code)}</span>
                    <span class="server-identity"><strong>{location.name}</strong><small>{location.code}{country === location.code ? ' · Selected' : ''}</small></span>
                    <span class="server-ping" class:measured={location.pingCheckedAt > 0 && location.pingMs >= 0}>{locationPing(location)}</span>
                    <span class="server-choice" aria-hidden="true">{#if country === location.code}<Icon name="check" size={12}/>{/if}</span>
                  </button>
                {:else}<p class="empty-servers">No locations loaded. Use Refresh locations to retry.</p>{/each}
              </div>
              <p class="server-method">Ping measures the best server round trip in each location.</p>
            </div>
            <div class="location-actions"><span class="server-hint">{connected ? 'Disconnect to change location.' : 'Lowest ping appears first after a scan.'}</span><button class="small-button refresh-pings" disabled={busy || connected || connecting || scanning || !state.locations.length} onclick={refreshPings}><Icon name="refresh" size={14}/>{scanning ? 'Testing…' : 'Refresh pings'}</button></div>
            <div class="server-scan-status" role="status">
              {#if scanning}<span>Testing servers · {state.serverPingsCompleted || 0}/{state.serverPingsTotal || 0}</span><progress aria-label="Server ping progress" max={state.serverPingsTotal || 1} value={state.serverPingsCompleted || 0}></progress>
              {:else if state.serverPingsCheckedAt}<span>Sorted by ping · {checkedTime(state.serverPingsCheckedAt)}</span>{/if}
              {#if state.serverPingsError}<span class="ping-error">{state.serverPingsError}</span>{/if}
            </div>
          </section>

          <section class="panel settings-panel">
            <div class="section-title"><h2>Connection mode</h2><Icon name="settings" size={17}/></div>
            <div class="segmented" role="group" aria-label="Traffic mode"><button class:selected={mode === 'tun'} aria-pressed={mode === 'tun'} disabled={busy || connected} onclick={() => mode = 'tun'}><Icon name="shield" size={17}/>System-wide TUN</button><button class:selected={mode === 'steroid'} aria-pressed={mode === 'steroid'} disabled={busy || connected} onclick={() => mode = 'steroid'}><Icon name="shield" size={17}/>TUN on steroid</button><button class:selected={mode === 'proxy'} aria-pressed={mode === 'proxy'} disabled={busy || connected} onclick={() => mode = 'proxy'}><Icon name="globe" size={17}/>Local proxy</button></div>
            <p class="mode-description">{mode === 'steroid' ? 'Experimental TUN with browser domain rules. Requires administrator authorization and browser proxy setup below.' : mode === 'tun' ? 'Route supported TCP traffic from your apps. Requires administrator authorization.' : 'Connect individual apps using the local proxy addresses below.'}</p>
            {#if mode === 'proxy'}<div class="proxy-addresses"><span>SOCKS5 <code>127.0.0.1:{state.socksPort}</code></span><span>HTTP <code>127.0.0.1:{state.httpPort}</code></span></div>{/if}
            <button class="text-button" disabled={busy || connected} onclick={openPorts}>Change local proxy ports<Icon name="arrow" size={13}/></button>
          </section>
        {/if}
      </div>
      {#if state.signedIn && mode === 'steroid'}<Steroid {state} {busy} onSave={saveSteroidConfig} onClear={() => act(() => backend().ClearObservedDomains())}/>{/if}
      {#if state.signedIn}<Traffic {state} {preferences} disabled={preferenceSaving} quotaError={activeAccount?.quotaError || ''} onChange={changePreference} onAccounts={() => showAccount = true}/>{/if}
    </div>
    <div class="service-note"><Icon name="info" size={15}/><p>Supports TCP traffic. UDP, QUIC, and ICMP ping are unsupported. TUN blocks IPv6. No kill switch.</p></div>
  </main>
  <footer><span><span class="footer-dot"></span>Unofficial Firefox VPN client</span><button class="text-button" onclick={() => showAbout = true}>About NAT-on-steroids<Icon name="arrow" size={12}/></button></footer>
</div>

{#if showAbout || showAccount || showAddAccount || showPorts || showAppearance}
  <div class="modal-backdrop" role="presentation"><div class="modal" role="dialog" aria-modal="true" aria-labelledby={showAddAccount ? 'signin-title' : 'dialog-title'} tabindex="-1" use:focusDialog>
    <button class="icon-button modal-close" aria-label="Close dialog" disabled={busy || preferenceSaving} onclick={closeDialogs}><Icon name="close"/></button>
    {#if error || state.error || preferenceError}<div class="alert modal-alert" role="alert"><Icon name="info"/><span>{error || state.error || preferenceError}</span></div>{/if}
    {#if showAppearance}
      <div class="symbol"><Icon name="palette"/></div><h2 id="dialog-title">Appearance &amp; monitoring</h2>
      <p>Choose your theme. Traffic displays have their own selectors on the dashboard.</p>
      <div class="theme-grid" role="group" aria-label="App theme">
        {#each themes as theme}<button class="theme-option" class:chosen={preferences.theme===theme.id} aria-pressed={preferences.theme===theme.id} disabled={preferenceSaving} onclick={()=>changePreference({theme:theme.id})}><span class="theme-preview" style:background={theme.colors[0]} aria-hidden="true"><span style:background={theme.colors[1]}></span><span style:background={theme.colors[2]}></span></span><span>{theme.name}</span>{#if preferences.theme===theme.id}<Icon name="check" size={14}/>{/if}</button>{/each}
      </div>
      <div class="monitor-settings"><h3>Connected server latency</h3><label for="latency-refresh">Refresh interval</label><select id="latency-refresh" value={latencyChoice} disabled={preferenceSaving} onchange={event=>changeInterval(event.currentTarget.value)}>{#each latencyPresets as option}<option value={String(option.seconds)}>{option.label}</option>{/each}<option value="custom">Custom…</option></select>
        {#if latencyChoice==='custom'}<form class="custom-interval" onsubmit={saveCustomInterval}><label for="custom-latency">Seconds (1–900)</label><div><input id="custom-latency" type="number" min="1" max="900" step="1" bind:value={customInterval} required disabled={preferenceSaving}/><button class="small-button" disabled={preferenceSaving}>Apply</button></div></form>{/if}
        <p class="dialog-footnote">Applies to the active connection immediately. Each check can take up to five seconds; checks never overlap.</p>
      </div>
      <p class="preference-save-status" role="status">{preferenceSaving?'Saving…':'Preferences are saved on this device.'}</p>
    {:else if showAddAccount}
      {@render signInForm()}
    {:else if showAccount}
      <div class="symbol"><Icon name="account"/></div><h2 id="dialog-title">Your accounts</h2>
      <p class="auto-balance-note">Balances refresh automatically every 5 minutes while the app is open. No notifications.</p>
      <p>Switching or adding an account disconnects the current VPN. Each connection uses the selected account’s allowance. Check traffic for any account without switching or disconnecting.</p>
      <ul class="account-list">
        {#each state.accounts as account}
          <li><div class="account-identity"><strong>{account.email}</strong><span>{account.email === state.email ? 'Active account' : 'Signed in'}</span></div>
            <div class="account-quota">
              {#if account.quotaRemaining >= 0}
                <strong>{quotaBytes(account.quotaRemaining)} remaining{#if account.quotaLimit > 0}{' '}<span>of {quotaBytes(account.quotaLimit)}</span>{/if}</strong>
                {#if account.quotaLimit > 0}<progress aria-label={`Remaining traffic for ${account.email}`} max={account.quotaLimit} value={account.quotaRemaining}></progress>{/if}
                {#if account.quotaRemaining === 0}<small>Monthly allowance exhausted.</small>{/if}
                <small>Last checked {checkedTime(account.quotaCheckedAt)}{account.quotaError ? ' · Last known balance' : ''}</small>
              {:else}<strong>{account.quotaError ? 'Remaining traffic unavailable' : 'Remaining traffic not checked'}</strong>{/if}
              {#if account.quotaError}<small class="quota-error" role="status">{account.quotaError}</small>{/if}
              <button class="text-button" aria-label={`Refresh traffic for ${account.email}`} disabled={busy} onclick={() => refreshQuota(account.email)}><Icon name="refresh" size={14}/>{refreshingQuota === account.email ? 'Checking…' : account.quotaCheckedAt ? 'Refresh traffic' : 'Check traffic'}</button>
            </div>
            <div class="account-row-actions"><button class="small-button" aria-label={`Switch to ${account.email}`} disabled={busy || account.email === state.email} onclick={() => act(() => backend().SwitchAccount(account.email))}>{account.email === state.email ? 'Active' : 'Switch'}</button><button class="small-button remove-button" aria-label={`Remove ${account.email}`} disabled={busy} onclick={() => act(async () => { await backend().RemoveAccount(account.email); await poll(); if (!state.accounts.length) showAccount = false; })}>Remove</button></div>
          </li>
        {/each}
      </ul>
      <button class="primary-button" disabled={busy} onclick={() => { showAccount = false; showAddAccount = true; email = ''; password = ''; error = ''; }}>Add account<Icon name="account" size={18}/></button>
      <p class="dialog-footnote">Session tokens are stored in your desktop keyring. Removing an account deletes its saved sign-in. No passwords are saved.</p>
    {:else if showPorts}
      <div class="symbol"><Icon name="settings"/></div><h2 id="dialog-title">Local proxy ports</h2>
      <p>Choose separate SOCKS5 and HTTP ports from 1024 to 65535. Both proxies listen only on your computer.</p>
      <form onsubmit={savePorts}><label for="socks-port">SOCKS5 port</label><input id="socks-port" type="number" min="1024" max="65535" step="1" bind:value={socksPort} required disabled={busy || connected}/><label for="http-port">HTTP proxy port</label><input id="http-port" type="number" min="1024" max="65535" step="1" bind:value={httpPort} required disabled={busy || connected}/><button class="primary-button" disabled={busy || connected}>Save ports<Icon name="check" size={18}/></button></form>
      {#if portsSaved}<p class="save-confirmation" role="status">Ports saved. They apply to your next connection.</p>{/if}
      {#if connected}<p>Disconnect before changing ports.</p>{/if}
      <p class="dialog-footnote">TUN mode also uses the selected SOCKS5 port.</p>
    {:else}
      <img class="about-logo" src="/logo.png" width="92" height="92" alt=""/><h2 id="dialog-title">NAT-on-steroids</h2><p>Version 0.7.1 · Linux</p><p>An independent Linux client based on FoxyVPN 1.0.7. This app is not affiliated with Mozilla or Fastly. Eligibility, quotas, locations, and destination restrictions are managed by the provider.</p><p>Go · Wails · Material 3 design<br/>TUN powered by hev-socks5-tunnel</p><button class="primary-button" onclick={closeDialogs}>Got it</button>
    {/if}
  </div></div>
{/if}
