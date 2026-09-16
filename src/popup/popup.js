const $ = id => document.getElementById(id);
let tabId, state;
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
async function send(type, payload = {}) { return chrome.runtime.sendMessage({ type, ...payload }); }
function setStatus(title, tone, summary) { $('statusTitle').textContent = title; $('statusTitle').className = `statusTitle ${tone || ''}`; $('statusSummary').textContent = summary; }
function render(s) {
  state = s; const fp = s?.fingerprint, result = s?.result || {};
  $('origin').textContent = fp?.site?.origin || 'This page cannot be monitored';
  if (s?.status === 'PAUSED') setStatus('MONITORING PAUSED', 'paused', 'Resume monitoring to compare this page with its baseline.');
  else if (s?.status === 'UNMONITORED') setStatus('NOT MONITORED', 'warning', 'Create a baseline to begin semantic change detection.');
  else if (s?.status === 'IGNORED') setStatus('CHANGE IGNORED', 'warning', 'This change is suppressed for the current session window; the baseline was not rewritten.');
  else if (s?.status === 'CHANGES_DETECTED') setStatus('CHANGES DETECTED', 'danger', 'Security-relevant page semantics differ from the saved baseline.');
  else if (s?.status === 'TRUSTED') setStatus('TRUSTED', 'trusted', 'The current page matches the active baseline.');
  else setStatus('UNAVAILABLE', '', 'Open a normal http or https page to use PageDNA.');
  if (fp) { $('scoreCard').classList.remove('hidden'); $('metrics').classList.remove('hidden'); $('match').textContent = `${result.matchPercent ?? 0}%`; $('score').textContent = `${result.score ?? 0}/100`; $('scripts').textContent = fp.metrics?.scriptCount ?? 0; $('origins').textContent = fp.metrics?.externalOriginCount ?? 0; $('frames').textContent = fp.metrics?.frameCount ?? 0; $('forms').textContent = fp.metrics?.sensitiveFormCount ?? 0; }
  const changes = result.changes || [];
  if (changes.length) { $('changesCard').classList.remove('hidden'); $('changes').innerHTML = changes.map(c => `<li class="${String(result.level || '').toLowerCase()}"><span class="changeLabel">${esc(c.label)}</span><span class="changeValue">${esc(c.oldValue)} → ${esc(c.newValue)}</span><span class="changeWhy">${esc(c.why)}</span></li>`).join(''); } else $('changesCard').classList.add('hidden');
  const actions = $('actions'); actions.innerHTML = '';
  const button = (text, cls, fn) => { const b = document.createElement('button'); b.textContent = text; b.className = `btn ${cls}`; b.onclick = fn; actions.appendChild(b); };
  if (s?.status === 'UNMONITORED' && fp) button('CREATE BASELINE', 'primary', () => act('PD_CREATE_BASELINE'));
  if (s?.status === 'CHANGES_DETECTED' || s?.status === 'IGNORED') { button('INVESTIGATE', 'secondary', () => showInvestigation()); button('TRUST THIS CHANGE', 'primary', () => act('PD_TRUST_CHANGE')); button('IGNORE ONCE', 'dangerBtn', () => act('PD_IGNORE_ONCE', { origin: fp.site.origin })); }
  if (!fp && s?.status === 'UNAVAILABLE') button('GRANT SITE ACCESS', 'primary', async () => {
    try {
      const tab = await chrome.tabs.get(tabId);
      if (tab.url?.startsWith('file://')) { alert('For local files: open chrome://extensions, find PageDNA, and turn on "Allow access to file URLs". Then reload this page.'); return; }
      const origin = new URL(tab.url).origin;
      const granted = await chrome.permissions.request({ origins: [`${origin}/*`] });
      if (granted) location.reload(); else alert('Site access was not granted.');
    } catch (error) { alert(error.message || 'Unable to request site access.'); }
  });
}
async function act(type, payload = {}) { const result = await send(type, { tabId, fingerprint: state?.fingerprint, ...payload }); if (result?.ok) { if (type === 'PD_IGNORE_ONCE') render((await send('PD_GET_TAB_STATE', { tabId })).state); else render((await send('PD_GET_TAB_STATE', { tabId })).state); } else alert(result?.error || 'Action failed'); }
function showInvestigation() { const c = state?.result?.changes || []; alert(c.map(x => `${x.label}\nOLD: ${x.oldValue}\nNEW: ${x.newValue}\nWHY: ${x.why}`).join('\n\n') || 'No changes recorded.'); }
async function init() { const tabs = await chrome.tabs.query({ active: true, currentWindow: true }); tabId = tabs[0]?.id; const result = await send('PD_GET_TAB_STATE', { tabId }); render(result.state); const settings = await send('PD_GET_SETTINGS'); $('pauseBtn').classList.toggle('active', settings.settings?.paused); $('pauseBtn').onclick = async () => { await send('PD_SET_PAUSED', { paused: !settings.settings?.paused }); location.reload(); }; }
$('historyBtn').onclick = async () => { const r = await send('PD_GET_HISTORY', { limit: 20 }); alert((r.history || []).map(x => `${new Date(x.time).toLocaleString()} — ${x.level} — ${x.event}${x.score != null ? ` (${x.score}/100)` : ''}`).join('\n') || 'No history yet.'); };
$('optionsBtn').onclick = () => chrome.runtime.openOptionsPage();
init();
