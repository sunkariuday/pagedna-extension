import { getSettings } from './baseline-manager.js';
export async function notifyRisk(origin, result) {
  const settings = await getSettings();
  if (result.level === 'MEDIUM' && !settings.mediumNotifications) return;
  if (result.level === 'HIGH' && !settings.highNotifications) return;
  if (result.level === 'CRITICAL' && !settings.criticalNotifications) return;
  if (!chrome.notifications?.create) return;
  const first = result.changes?.[0]?.label || 'Semantic page change detected';
  await chrome.notifications.create(`pagedna-${Date.now()}`, { type: 'basic', iconUrl: chrome.runtime.getURL('assets/icon.svg'), title: `PageDNA: ${result.level}`, message: `${origin}: ${first} (${result.score}/100)` });
}
