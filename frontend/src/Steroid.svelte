<script lang="ts">
  import type { State, SteroidConfig } from './api';
  import { bytes } from './format';
  import Icon from './Icon.svelte';
  export let state: State;
  export let busy = false;
  export let onSave: (config: SteroidConfig) => Promise<boolean>;
  export let onClear: () => void;
  let domain = '';
  let kind = 'suffix';
  let action = 'direct';
  let filter = '';
  let pacPort: number | undefined = 8099;
  let editingPort = false;
  $: config = state.steroidConfig || {pacPort:8099,rules:[]};
  $: active = state.status === 'connected' && state.mode === 'steroid';
  $: events = (state.observedDomains || []).filter(event=>event.domain.toLowerCase().includes(filter.toLowerCase()));
  $: pacURL = `http://127.0.0.1:${config.pacPort}/proxy.pac`;
  $: if (!editingPort) pacPort = config.pacPort;
  async function addRule(event: SubmitEvent) {
    event.preventDefault();
    if (await onSave({...config,rules:[...config.rules,{kind,domain,action}]})) domain = '';
  }
  async function setDomainRoute(host: string,route: string) {
    const rules = config.rules.filter(rule=>!(rule.kind==='exact'&&rule.domain===host));
    await onSave({...config,rules:[...rules,{kind:'exact',domain:host,action:route}]});
  }
  async function savePort(event: SubmitEvent) {
    event.preventDefault();
    if (await onSave({...config,pacPort:pacPort!})) editingPort = false;
  }
</script>

<section class="panel steroid-panel" aria-labelledby="steroid-title">
  <div class="section-title"><h2 id="steroid-title">TUN on steroid</h2><span class="experimental-badge">Experimental</span></div>
  <p class="steroid-intro">System-wide TUN stays active. Configure your browser with the PAC URL below to choose VPN or Direct for individual domains. Direct uses your normal connection; unmatched domains stay on VPN.</p>
  <div class="steroid-columns">
    <div class="steroid-rules">
      <h3>Domain rules</h3>
      <form class="domain-rule-form" onsubmit={addRule}>
        <div><label for="rule-domain">Domain or suffix</label><input id="rule-domain" placeholder=".ir or example.com" bind:value={domain} required disabled={busy}/></div>
        <div class="rule-options"><div><label for="rule-kind">Match</label><select id="rule-kind" bind:value={kind} disabled={busy}><option value="suffix">Domain suffix</option><option value="exact">Exact domain</option></select></div><div><label for="rule-action">Route</label><select id="rule-action" bind:value={action} disabled={busy}><option value="direct">Direct · real IP</option><option value="vpn">VPN</option></select></div><button class="small-button" disabled={busy}>Add rule</button></div>
      </form>
      {#if config.rules.length}<ul class="domain-rules-list">{#each config.rules as rule,index (`${rule.kind}:${rule.domain}`)}<li><div><strong>{rule.kind==='suffix'?`*.${rule.domain}`:rule.domain}</strong><small>{rule.kind==='exact'?'Exact domain':'Domain and subdomains'}</small></div><span class:direct={rule.action==='direct'} class="domain-route">{rule.action==='direct'?'Direct':'VPN'}</span><button class="icon-button" aria-label={`Remove ${rule.kind} rule for ${rule.domain}`} disabled={busy} onclick={()=>onSave({...config,rules:config.rules.filter((_,i)=>i!==index)})}><Icon name="close" size={14}/></button></li>{/each}</ul>
      {:else}<p class="metric-empty">No exceptions yet. Add <strong>.ir → Direct</strong> to bypass the VPN for .ir domains.</p>{/if}
      <p class="steroid-footnote">Exact rules override suffix rules. Longer suffixes override shorter ones. Direct supports public IPv4 web destinations on ports 80 and 443. Saving rules closes existing hostname proxy connections; reload affected pages.</p>
    </div>
    <div class="steroid-browser">
      <h3>Browser setup</h3>
      <ol><li>Add the rules you want.</li><li>Connect using TUN on steroid.</li><li>Set your browser’s automatic proxy configuration URL to:</li></ol>
      <input class="pac-url" aria-label="Browser automatic proxy URL" value={pacURL} readonly onfocus={event=>event.currentTarget.select()}/>
      <p class="steroid-footnote">Use this URL in Firefox’s Network Settings or your browser’s PAC/proxy configuration. Alternatively, use HTTP and HTTPS proxy <code>127.0.0.1:{state.httpPort}</code>. No automatic system proxy changes are made.</p>
      <div class="direct-verification"><div><span>VPN exit IP</span><strong>{active?state.ip:'—'}</strong></div><div><span>Direct path IP</span><strong>{active?state.directIp:'Connect to verify'}</strong></div></div>
      {#if active}<p class="steroid-footnote">Direct received {bytes(state.directDownload || 0)} · sent {bytes(state.directUpload || 0)}. The traffic monitor below shows VPN traffic.</p>{/if}
      <details class="pac-settings"><summary>Browser PAC port</summary><form onsubmit={savePort}><label for="pac-port">Local port (1024–65535)</label><div><input id="pac-port" type="number" min="1024" max="65535" step="1" bind:value={pacPort} required disabled={busy||active} oninput={()=>editingPort=true}/><button class="small-button" disabled={busy||active}>Save port</button></div></form><p class="steroid-footnote">Disconnect before changing this port. It must differ from both proxy ports.</p></details>
    </div>
  </div>
  <div class="observed-heading"><div><h3>Observed domains</h3><p>Last routes for connections seen by the browser proxy; IP-only TUN traffic stays on VPN. This is not a complete browser request history.</p></div><button class="text-button" disabled={busy} onclick={onClear}>Clear list</button></div>
  <input class="domain-filter" type="search" aria-label="Filter observed domains" placeholder="Filter domains…" bind:value={filter}/>
  <div class="observed-domains" aria-label="Observed domain connections">
    {#each events as event (event.domain)}<div class="observed-domain"><div><strong>{event.domain}</strong><small>{event.connections} connection{event.connections===1?'':'s'} · {new Date(event.lastSeen*1000).toLocaleTimeString()}</small>{#if event.error}<small class="quota-error">{event.error}</small>{/if}</div><span class:direct={event.action==='direct'} class="domain-route">{event.action==='direct'?'Direct':'VPN'}</span><div class="domain-row-actions"><button class="small-button" aria-label={`Use VPN for ${event.domain}`} disabled={busy} onclick={()=>setDomainRoute(event.domain,'vpn')}>VPN</button><button class="small-button" aria-label={`Use Direct for ${event.domain}`} disabled={busy} onclick={()=>setDomainRoute(event.domain,'direct')}>Direct</button></div></div>
    {:else}<p class="metric-empty">{filter?'No matching domains.':'Domains appear here after your configured browser opens connections. Up to 256 recent domains are kept in memory only.'}</p>{/each}
  </div>
</section>
