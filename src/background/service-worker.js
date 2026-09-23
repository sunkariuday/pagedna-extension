import { MESSAGE } from '../shared/constants.js';
import { diffFingerprints } from './diff-engine.js';
import { getSite, getSettings, createBaseline, recordScan, trustChange, ignoreOnce, history, setPaused, saveSettings } from './baseline-manager.js';
import { notifyRisk } from './notifications.js';

const tabStates = new Map();
const MAX_FINGERPRINT_BYTES = 1024 * 1024;

function siteKeyFromUrl(rawUrl) {
  const url = new URL(rawUrl);
  if (url.protocol === 'file:') { url.hash = ''; return url.toString(); }
  return url.origin;
}

function validFingerprint(fingerprint) {
  if (!fingerprint || typeof fingerprint !== 'object') return false;
  if (fingerprint.schemaVersion !== 3) return false;
  if (!fingerprint.site || typeof fingerprint.site.origin !== 'string') return false;
  try {
    const url = new URL(fingerprint.site.origin);
    const isFileKey = fingerprint.site.protocol === 'file' && url.protocol === 'file:' && url.toString() === fingerprint.site.origin;
    if (!isFileKey && (!['http:', 'https:'].includes(url.protocol) || url.origin !== fingerprint.site.origin)) return false;
  } catch { return false; }
  if (!Array.isArray(fingerprint.scripts) || !fingerprint.structure || !Array.isArray(fingerprint.structure.forms) || !Array.isArray(fingerprint.structure.frames)) return false;
  try { return JSON.stringify(fingerprint).length <= MAX_FINGERPRINT_BYTES; } catch { return false; }
}

function validOrigin(origin) {
  try {
    const url = new URL(origin);
    return (['http:', 'https:'].includes(url.protocol) && url.origin === origin) || (url.protocol === 'file:' && url.toString() === origin);
  } catch { return false; }
}

async function scan(tabId, fingerprint) {
  const settings = await getSettings();
  if (settings.paused) {
    const state = { status: 'PAUSED', fingerprint: validFingerprint(fingerprint) ? fingerprint : null, result: { score: 0, level: 'LOW', changes: [], matchPercent: 0 } };
    tabStates.set(tabId, state);
    return state;
  }
  if (!validFingerprint(fingerprint)) return { status: 'INVALID_SCAN', fingerprint: null, result: { score: 0, level: 'LOW', changes: [], matchPercent: 0 } };
  const site = await getSite(fingerprint.site.origin);
  if (!site.versions.length) {
    const result = { score: 0, level: 'LOW', changes: [], matchPercent: 0, status: 'UNMONITORED' };
    await recordScan(fingerprint, result);
    const state = { status: 'UNMONITORED', fingerprint, result };
    tabStates.set(tabId, state);
    return state;
  }
  const baseline = site.versions.find(v => v.version === site.currentVersion) || site.versions[site.versions.length - 1];
  const result = diffFingerprints(baseline.fingerprint, fingerprint, settings);
  const ignored = site.ignoredUntil > Date.now() && result.changes.length > 0;
  const state = { status: ignored ? 'IGNORED' : (result.changes.length ? 'CHANGES_DETECTED' : 'TRUSTED'), fingerprint, baseline, result: { ...result, status: ignored ? 'IGNORED' : result.status } };
  await recordScan(fingerprint, state.result);
  tabStates.set(tabId, state);
  const notifyThreshold = Math.max(0, Number(settings.thresholds?.medium) || 20);
  if (!ignored && result.score >= notifyThreshold) await notifyRisk(fingerprint.site.origin, result);
  return state;
}

async function stateForTab(tabId) {
  if (tabStates.has(tabId)) return tabStates.get(tabId);
  try {
    const tab = await chrome.tabs.get(tabId);
    const origin = siteKeyFromUrl(tab.url);
    const site = await getSite(origin);
    if (site.lastFingerprint) {
      const baseline = site.versions.find(v => v.version === site.currentVersion);
      return { status: site.lastResult?.status || (site.lastResult?.changes?.length ? 'CHANGES_DETECTED' : 'TRUSTED'), fingerprint: site.lastFingerprint, baseline, result: site.lastResult };
    }
  } catch {}
  return { status: 'UNAVAILABLE', fingerprint: null, result: { score: 0, level: 'LOW', changes: [], matchPercent: 0 } };
}

function clearTabState(tabId) {
  if (tabId != null) tabStates.delete(tabId);
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  (async () => {
    if (!message || typeof message.type !== 'string') return { ok: false, error: 'Invalid message' };
    const senderTabId = sender.tab?.id;
    const requestedTabId = message.tabId ?? senderTabId;
    switch (message.type) {
      case MESSAGE.SCAN:
        return senderTabId == null ? { ok: false, error: 'Scan must originate from a tab' } : { ok: true, state: await scan(senderTabId, message.fingerprint) };
      case MESSAGE.GET_TAB_STATE:
        return { ok: true, state: await stateForTab(requestedTabId) };
      case MESSAGE.CREATE_BASELINE: {
        if (!validFingerprint(message.fingerprint || tabStates.get(requestedTabId)?.fingerprint)) return { ok: false, error: 'Invalid fingerprint' };
        const result = await createBaseline(message.fingerprint || tabStates.get(requestedTabId)?.fingerprint, 'user-created');
        clearTabState(requestedTabId);
        return { ok: true, ...result };
      }
      case MESSAGE.TRUST_CHANGE: {
        if (!validFingerprint(message.fingerprint || tabStates.get(requestedTabId)?.fingerprint)) return { ok: false, error: 'Invalid fingerprint' };
        const result = await trustChange(message.fingerprint || tabStates.get(requestedTabId)?.fingerprint);
        clearTabState(requestedTabId);
        return { ok: true, ...result };
      }
      case MESSAGE.IGNORE_ONCE: {
        const tab = message.origin ? null : await chrome.tabs.get(requestedTabId);
        const origin = message.origin || (tab?.url ? siteKeyFromUrl(tab.url) : '');
        if (!validOrigin(origin)) return { ok: false, error: 'Invalid origin' };
        const site = await ignoreOnce(origin);
        const previous = tabStates.get(requestedTabId);
        if (previous) tabStates.set(requestedTabId, { ...previous, status: 'IGNORED', result: { ...previous.result, status: 'IGNORED' } });
        return { ok: true, site };
      }
      case MESSAGE.INVESTIGATE:
        return { ok: true, state: await stateForTab(requestedTabId) };
      case MESSAGE.GET_HISTORY:
        return { ok: true, history: await history(message.limit || 50) };
      case MESSAGE.SET_PAUSED:
        return { ok: true, settings: await setPaused(message.paused) };
      case MESSAGE.GET_SETTINGS:
        return { ok: true, settings: await getSettings() };
      case MESSAGE.SAVE_SETTINGS:
        return { ok: true, settings: await saveSettings(message.settings) };
      default:
        return { ok: false, error: 'Unknown message' };
    }
  })().then(sendResponse).catch(error => sendResponse({ ok: false, error: String(error?.message || error) }));
  return true;
});
chrome.tabs.onRemoved.addListener(tabId => tabStates.delete(tabId));
