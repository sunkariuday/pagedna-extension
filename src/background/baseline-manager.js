import { STORAGE_KEY, DEFAULT_SETTINGS } from '../shared/constants.js';

const emptyState = () => ({ sites: {}, history: [] });
let stateQueue = Promise.resolve();
let settingsQueue = Promise.resolve();

async function readState() {
  const data = await chrome.storage.local.get([STORAGE_KEY]);
  return data[STORAGE_KEY] || emptyState();
}

function enqueue(task) {
  const run = stateQueue.then(task);
  stateQueue = run.catch(() => {});
  return run;
}

export async function getState() {
  await stateQueue;
  return readState();
}

export function saveState(state) {
  return enqueue(async () => {
    await chrome.storage.local.set({ [STORAGE_KEY]: state });
    return state;
  });
}

function clampThreshold(value, fallback) {
  const number = Number(value);
  return Number.isFinite(number) ? Math.min(100, Math.max(0, number)) : fallback;
}

export function normalizeSettings(raw = {}) {
  const source = raw && typeof raw === 'object' ? raw : {};
  const rawThresholds = source.thresholds && typeof source.thresholds === 'object' ? source.thresholds : {};
  const medium = clampThreshold(rawThresholds.medium, DEFAULT_SETTINGS.thresholds.medium);
  const high = Math.max(medium, clampThreshold(rawThresholds.high, DEFAULT_SETTINGS.thresholds.high));
  const critical = Math.max(high, clampThreshold(rawThresholds.critical, DEFAULT_SETTINGS.thresholds.critical));
  return {
    paused: Boolean(source.paused),
    mediumNotifications: source.mediumNotifications !== false,
    highNotifications: source.highNotifications !== false,
    criticalNotifications: source.criticalNotifications !== false,
    thresholds: { medium, high, critical }
  };
}

function enqueueSettings(task) {
  const run = settingsQueue.then(task);
  settingsQueue = run.catch(() => {});
  return run;
}

async function readSettings() {
  const data = await chrome.storage.local.get(['pagednaSettings']);
  return normalizeSettings(data.pagednaSettings);
}

export async function getSettings() {
  await settingsQueue;
  return readSettings();
}

export function saveSettings(settings) {
  return enqueueSettings(async () => {
    const normalized = normalizeSettings(settings);
    await chrome.storage.local.set({ pagednaSettings: normalized });
    return normalized;
  });
}

function siteRecord(state, origin) {
  return state.sites[origin] || { versions: [], currentVersion: 0, lastFingerprint: null, lastResult: null, ignoredUntil: 0, observations: 0 };
}

async function mutateState(mutator) {
  return enqueue(async () => {
    const state = await readState();
    const result = await mutator(state);
    await chrome.storage.local.set({ [STORAGE_KEY]: state });
    return result;
  });
}

export async function getSite(origin) {
  const state = await getState();
  return siteRecord(state, origin);
}

export function createBaseline(fingerprint, reason = 'user-created') {
  return mutateState(state => {
    if (!fingerprint?.site?.origin) throw new Error('A valid fingerprint is required');
    const origin = fingerprint.site.origin;
    const site = siteRecord(state, origin);
    const last = site.versions.length ? site.versions[site.versions.length - 1].version : 0;
    const version = last + 1;
    const entry = { version, createdAt: new Date().toISOString(), reason, fingerprint };
    site.versions.push(entry);
    site.currentVersion = version;
    site.lastFingerprint = fingerprint;
    site.lastResult = { score: 0, level: 'LOW', changes: [], matchPercent: 100 };
    site.observations = 0;
    state.sites[origin] = site;
    state.history.unshift({ time: entry.createdAt, origin, event: `Baseline v${version} created`, level: 'LOW', reason });
    state.history = state.history.slice(0, 200);
    return { site, entry };
  });
}

export function recordScan(fingerprint, result) {
  return mutateState(state => {
    if (!fingerprint?.site?.origin) throw new Error('A valid fingerprint is required');
    const origin = fingerprint.site.origin;
    const site = siteRecord(state, origin);
    site.lastFingerprint = fingerprint;
    site.lastResult = result;
    site.observations = (site.observations || 0) + 1;
    state.sites[origin] = site;
    state.history.unshift({ time: new Date().toISOString(), origin, event: result.changes.length ? 'Change detected' : 'Page matched baseline', level: result.level, score: result.score, changes: result.changes });
    state.history = state.history.slice(0, 200);
    return site;
  });
}

export function trustChange(fingerprint, reason = 'user-approved-change') {
  return createBaseline(fingerprint, reason);
}

export function ignoreOnce(origin) {
  return mutateState(state => {
    const site = siteRecord(state, origin);
    site.ignoredUntil = Date.now() + 10 * 60 * 1000;
    state.sites[origin] = site;
    state.history.unshift({ time: new Date().toISOString(), origin, event: 'Ignored once', level: 'LOW' });
    state.history = state.history.slice(0, 200);
    return site;
  });
}

export async function history(limit = 50) {
  const state = await getState();
  const safeLimit = Math.min(200, Math.max(1, Number(limit) || 50));
  return state.history.slice(0, safeLimit);
}

export function setPaused(paused) {
  return enqueueSettings(async () => {
    const settings = await readSettings();
    settings.paused = Boolean(paused);
    const normalized = normalizeSettings(settings);
    await chrome.storage.local.set({ pagednaSettings: normalized });
    return normalized;
  });
}
