import { MESSAGE } from './constants.js';

export function sendRuntime(type, payload = {}) {
  return chrome.runtime.sendMessage({ type, ...payload });
}

export function sendTab(tabId, type, payload = {}) {
  return chrome.tabs.sendMessage(tabId, { type, ...payload });
}

export { MESSAGE };
