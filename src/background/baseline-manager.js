import { STORAGE_KEY, DEFAULT_SETTINGS } from '../shared/constants.js';

const emptyState = () => ({ sites: {}, history: [] });
export async function getState() { const data = await chrome.storage.local.get([STORAGE_KEY]); return data[STORAGE_KEY] || emptyState(); }
export async function saveState(state) { await chrome.storage.local.set({ [STORAGE_KEY]: state }); return state; }
export async function getSettings() { const data = await chrome.storage.local.get(['pagednaSettings']); return { ...DEFAULT_SETTINGS, ...(data.pagednaSettings || {}), thresholds: { ...DEFAULT_SETTINGS.thresholds, ...(data.pagednaSettings?.thresholds || {}) } }; }
export async function saveSettings(settings) { await chrome.storage.local.set({ pagednaSettings: settings }); return settings; }
function siteRecord(state, origin) { return state.sites[origin] || { versions: [], currentVersion: 0, lastFingerprint: null, lastResult: null, ignoredUntil: 0, observations: 0 }; }
export async function getSite(origin) { const state = await getState(); return siteRecord(state, origin); }
export async function createBaseline(fingerprint, reason = 'user-created') {
  const state = await getState(); const origin = fingerprint.site.origin; const site = siteRecord(state, origin);
  const last = site.versions.length ? site.versions[site.versions.length - 1].version : 0; const version = last + 1;
  const entry = { version, createdAt: new Date().toISOString(), reason, fingerprint };
  site.versions.push(entry); site.currentVersion = version; site.lastFingerprint = fingerprint; site.lastResult = { score: 0, level: 'LOW', changes: [], matchPercent: 100 }; site.observations = 0; state.sites[origin] = site;
  state.history.unshift({ time: entry.createdAt, origin, event: `Baseline v${version} created`, level: 'LOW', reason });
  await saveState(state); return { site, entry };
}
export async function recordScan(fingerprint, result) {
  const state = await getState(); const origin = fingerprint.site.origin; const site = siteRecord(state, origin);
  site.lastFingerprint = fingerprint; site.lastResult = result; site.observations = (site.observations || 0) + 1; state.sites[origin] = site;
  state.history.unshift({ time: new Date().toISOString(), origin, event: result.changes.length ? 'Change detected' : 'Page matched baseline', level: result.level, score: result.score, changes: result.changes });
  state.history = state.history.slice(0, 200); await saveState(state); return site;
}
export async function trustChange(fingerprint, reason = 'user-approved-change') { return createBaseline(fingerprint, reason); }
export async function ignoreOnce(origin) { const state = await getState(); const site = siteRecord(state, origin); site.ignoredUntil = Date.now() + 10 * 60 * 1000; state.sites[origin] = site; state.history.unshift({ time: new Date().toISOString(), origin, event: 'Ignored once', level: 'LOW' }); await saveState(state); return site; }
export async function history(limit = 50) { const state = await getState(); return state.history.slice(0, limit); }
export async function setPaused(paused) { const settings = await getSettings(); settings.paused = Boolean(paused); return saveSettings(settings); }
