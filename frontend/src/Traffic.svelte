<script lang="ts">
  import type { State, Preferences } from './api';
  import { quotaBytes, bytes } from './format';
  import Icon from './Icon.svelte';
  export let state: State;
  export let preferences: Preferences;
  export let disabled = false;
  export let quotaError = '';
  export let onChange: (patch: Partial<Preferences>) => void;
  export let onAccounts: () => void;
  let history: { at: number; down: number; up: number }[] = [];
  let session = '';
  let lastTotal = 0;
  const blocks = Array.from({length:30}, (_,i) => i);
  $: connected = state.status === 'connected';
  $: down = connected ? Math.max(0,state.downloadSpeed || 0) : 0;
  $: up = connected ? Math.max(0,state.uploadSpeed || 0) : 0;
  $: sample(state);
  $: peak = Math.max(1,...history.flatMap(point => [point.down,point.up]));
  $: downPath = line(history, 'down', peak);
  $: upPath = line(history, 'up', peak);
  $: known = state.quotaRemaining >= 0;
  $: fraction = known && state.quotaLimit > 0 ? Math.max(0,Math.min(1,state.quotaRemaining/state.quotaLimit)) : null;
  $: percent = fraction === null ? null : Math.round(fraction*100);
  $: received = Math.max(0,state.download);
  $: sent = Math.max(0,state.upload);
  $: total = received + sent;
  $: receiveShare = total > 0 ? received/total : 0;

  function sample(s: State) {
    const key = s.status === 'connected' ? `${s.email}/${s.country}/${s.mode}/${s.since}` : '';
    if (key !== session || s.download+s.upload < lastTotal) { history=[]; session=key; }
    lastTotal=s.download+s.upload;
    if (!key) return;
    const now=Date.now();
    if (history.length && Math.floor(now/1000)===Math.floor(history[history.length-1].at/1000)) return;
    history=[...history.filter(point=>now-point.at<60000),{at:now,down:Math.max(0,s.downloadSpeed||0),up:Math.max(0,s.uploadSpeed||0)}];
  }
  function line(points: typeof history, key: 'down' | 'up', maximum: number) {
    if (!points.length) return '';
    const end=points[points.length-1].at;
    return points.map((point,i)=>`${i?'L':'M'}${((point.at-end+60000)/60000*360).toFixed(2)},${(74-point[key]/maximum*68).toFixed(2)}`).join(' ');
  }
</script>

<section class="panel usage-panel" aria-label="Traffic visualizations">
  <div class="section-title"><h2>Traffic monitor</h2><div class="monitor-title-actions"><span class="live-label"><span class="status-dot"></span>{connected ? 'Live · 1s' : 'Disconnected'}</span><button class="text-button" {disabled} onclick={onAccounts}>Manage accounts<Icon name="arrow" size={13}/></button></div></div>
  <section class="metric-section speed-section" aria-labelledby="speed-title">
    <div class="metric-heading"><h3 id="speed-title">Network speed</h3><select aria-label="Network speed visualization" value={preferences.speedVisualization} {disabled} onchange={event=>onChange({speedVisualization:event.currentTarget.value})}><option value="graph">Live graph</option><option value="bars">Terminal bars</option><option value="numbers">Numbers</option></select></div>
    <div class="speed-readings"><div class="download-reading"><Icon name="download" size={14}/><span>Down</span><strong>{quotaBytes(down)}/s</strong></div><div class="upload-reading"><Icon name="upload" size={14}/><span>Up</span><strong>{quotaBytes(up)}/s</strong></div></div>
    {#if preferences.speedVisualization === 'graph'}
      <div class="speed-chart">
        <svg class="history-graph" viewBox="0 0 360 80" preserveAspectRatio="none" role="img" aria-label="Download and upload speed over the last 60 seconds">
          <path class="chart-grid" d="M0 6H360M0 40H360M0 74H360"/>
          {#if history.length > 1}<path class="download-line" d={downPath}/><path class="upload-line" d={upPath}/>{/if}
        </svg>
        {#if history.length < 2}<span class="chart-empty">{connected ? 'Collecting live history…' : 'Connect to start the live graph'}</span>{/if}
      </div>
      <div class="chart-caption"><span>60-second history</span><span>Scale {quotaBytes(peak)}/s</span></div>
    {:else if preferences.speedVisualization === 'bars'}
      <div class="terminal-meters" aria-hidden="true">{#each [{name:'DL',value:down,kind:'download'},{name:'UL',value:up,kind:'upload'}] as meter}<div class={`terminal-row ${meter.kind}`}><span>{meter.name}</span><div class="segment-meter">{#each blocks as i}<span class:lit={i < Math.ceil(meter.value/peak*30)}></span>{/each}</div></div>{/each}</div>
      <div class="chart-caption"><span>Relative to the last 60-second peak</span><span>{quotaBytes(peak)}/s</span></div>
    {/if}
  </section>

  <section class="metric-section remaining-section" aria-labelledby="remaining-title">
    <div class="metric-heading"><h3 id="remaining-title">Remaining allowance</h3><select aria-label="Remaining allowance visualization" value={preferences.remainingVisualization} {disabled} onchange={event=>onChange({remainingVisualization:event.currentTarget.value})}><option value="ring">Ring</option><option value="blocks">Terminal blocks</option><option value="bar">Progress bar</option></select></div>
    {#if known}
      <div class:with-ring={preferences.remainingVisualization === 'ring' && fraction !== null} class="allowance-content">
        {#if preferences.remainingVisualization === 'ring' && fraction !== null}<div class="ring-chart" role="img" aria-label={`${percent}% allowance remaining`}><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="40"/><circle class="ring-value allowance-ring" cx="50" cy="50" r="40" pathLength="100" stroke-dasharray={`${fraction*100} 100`}/></svg><strong>{percent}%</strong></div>{/if}
        <div class="allowance-readings"><strong>{quotaBytes(state.quotaRemaining)}</strong><span>{state.quotaLimit > 0 ? `of ${quotaBytes(state.quotaLimit)} remaining` : 'remaining · total allowance unavailable'}</span>{#if state.quotaRemaining===0}<small class="quota-error">Allowance exhausted</small>{/if}</div>
      </div>
      {#if fraction !== null && preferences.remainingVisualization !== 'ring'}
        {#if preferences.remainingVisualization === 'blocks'}<div class="allowance-blocks" role="img" aria-label={`${percent}% allowance remaining`}>{#each blocks as i}<span class:lit={i < Math.ceil(fraction*30)}></span>{/each}</div>
        {:else}<progress aria-label="Active account remaining traffic" max={state.quotaLimit} value={state.quotaRemaining}></progress>{/if}
        <div class="chart-caption"><span>{percent}% remaining</span><span>Service-reported balance</span></div>
      {/if}
      {#if quotaError}<small class="quota-error balance-error">{quotaError} Showing last known balance.</small>{/if}
    {:else}<p class="metric-empty">Balance unavailable. Check traffic in Accounts.</p>{/if}
  </section>

  <section class="metric-section totals-section" aria-labelledby="totals-title">
    <div class="metric-heading"><h3 id="totals-title">Received &amp; sent</h3><select aria-label="Received and sent visualization" value={preferences.totalsVisualization} {disabled} onchange={event=>onChange({totalsVisualization:event.currentTarget.value})}><option value="bars">Comparison bars</option><option value="ring">Split ring</option><option value="numbers">Numbers</option></select></div>
    <div class:with-ring={preferences.totalsVisualization === 'ring'} class="totals-content">
      {#if preferences.totalsVisualization === 'ring'}<div class="ring-chart split-ring" role="img" aria-label={total>0?`${Math.round(receiveShare*100)}% received, ${Math.round((1-receiveShare)*100)}% sent`:'No traffic yet'}><svg viewBox="0 0 100 100" aria-hidden="true"><circle class="ring-track" cx="50" cy="50" r="40"/>{#if total>0}<circle class="ring-value sent-ring" cx="50" cy="50" r="40"/><circle class="ring-value received-ring" cx="50" cy="50" r="40" pathLength="100" stroke-dasharray={`${receiveShare*100} 100`}/>{/if}</svg><span>{total>0?'Session':'No data'}</span></div>{/if}
      <div class="totals-readings"><div class="total-reading"><span><i class="download-dot"></i>Received</span><strong>{bytes(received)}</strong></div>{#if preferences.totalsVisualization === 'bars'}<div class="comparison-track"><span class="download-fill" style:width={`${receiveShare*100}%`}></span></div>{/if}<div class="total-reading"><span><i class="upload-dot"></i>Sent</span><strong>{bytes(sent)}</strong></div>{#if preferences.totalsVisualization === 'bars'}<div class="comparison-track"><span class="upload-fill" style:width={`${total>0?(1-receiveShare)*100:0}%`}></span></div>{/if}</div>
    </div>
    <div class="chart-caption"><span>{total>0?'Share of this connection’s traffic':'No traffic in this connection yet'}</span></div>
  </section>
</section>
