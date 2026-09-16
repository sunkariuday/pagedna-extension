import { MESSAGE } from '../shared/constants.js';
import { diffFingerprints } from './diff-engine.js';
import { getSite, getSettings, createBaseline, recordScan, trustChange, ignoreOnce, history, setPaused, getState, saveSettings } from './baseline-manager.js';
import { notifyRisk } from './notifications.js';

const tabStates = new Map();
async function scan(tabId, fingerprint) {
  const settings = await getSettings();
  if (settings.paused) { const state = { status: 'PAUSED', fingerprint, result: { score: 0, level: 'LOW', changes: [], matchPercent: 0 } }; tabStates.set(tabId, state); return state; }
  const site = await getSite(fingerprint.site.origin);
  if (!site.versions.length) {
    const result = { score: 0, level: 'LOW', changes: [], matchPercent: 0, status: 'UNMONITORED' };
    await recordScan(fingerprint, result); const state = { status: 'UNMONITORED', fingerprint, result }; tabStates.set(tabId, state); return state;
  }
  const baseline = site.versions.find(v => v.version === site.currentVersion) || site.versions[site.versions.length - 1];
  const result = diffFingerprints(baseline.fingerprint, fingerprint);
  const ignored = site.ignoredUntil > Date.now() && result.changes.length > 0;
  const state = { status: ignored ? 'IGNORED' : (result.changes.length ? 'CHANGES_DETECTED' : 'TRUSTED'), fingerprint, baseline, result: { ...result, status: ignored ? 'IGNORED' : result.status } };
  await recordScan(fingerprint, state.result); tabStates.set(tabId, state);
  if (!ignored && result.score >= 20) await notifyRisk(fingerprint.site.origin, result);
  return state;
}
async function stateForTab(tabId) {
  if (tabStates.has(tabId)) return tabStates.get(tabId);
  try { const tab = await chrome.tabs.get(tabId); const origin = new URL(tab.url).origin; const site = await getSite(origin); if (site.lastFingerprint) { const baseline = site.versions.find(v => v.version === site.currentVersion); return { status: site.lastResult?.status || (site.lastResult?.changes?.length ? 'CHANGES_DETECTED' : 'TRUSTED'), fingerprint: site.lastFingerprint, baseline, result: site.lastResult }; } } catch {}
  return { status: 'UNAVAILABLE', fingerprint: null, result: { score: 0, level: 'LOW', changes: [], matchPercent: 0 } };
}
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    const tabId = sender.tab?.id;
    switch (message.type) {
      case MESSAGE.SCAN: return tabId == null ? { ok: false } : { ok: true, state: await scan(tabId, message.fingerprint) };
      case MESSAGE.GET_TAB_STATE: return { ok: true, state: await stateForTab(message.tabId ?? tabId) };
      case MESSAGE.CREATE_BASELINE: return { ok: true, ...(await createBaseline(message.fingerprint || tabStates.get(message.tabId)?.fingerprint, 'user-created')) };
      case MESSAGE.TRUST_CHANGE: { const current = message.fingerprint || tabStates.get(message.tabId)?.fingerprint; return { ok: true, ...(await trustChange(current)) }; }
      case MESSAGE.IGNORE_ONCE: return { ok: true, site: await ignoreOnce(message.origin || new URL((await chrome.tabs.get(message.tabId)).url).origin) };
      case MESSAGE.INVESTIGATE: return { ok: true, state: await stateForTab(message.tabId ?? tabId) };
      case MESSAGE.GET_HISTORY: return { ok: true, history: await history(message.limit || 50) };
      case MESSAGE.SET_PAUSED: return { ok: true, settings: await setPaused(message.paused) };
      case MESSAGE.GET_SETTINGS: return { ok: true, settings: await getSettings() };
      case MESSAGE.SAVE_SETTINGS: return { ok: true, settings: await saveSettings(message.settings) };
      default: return { ok: false, error: 'Unknown message' };
    }
  })().then(sendResponse).catch(error => sendResponse({ ok: false, error: String(error?.message || error) }));
  return true;
});
chrome.tabs.onRemoved.addListener(tabId => tabStates.delete(tabId));
