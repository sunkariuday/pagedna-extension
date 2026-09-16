export const VERSION = 1;
export const STORAGE_KEY = 'pagednaState';
export const SETTINGS_KEY = 'pagednaSettings';
export const MESSAGE = Object.freeze({
  SCAN: 'PD_SCAN_PAGE',
  GET_TAB_STATE: 'PD_GET_TAB_STATE',
  CREATE_BASELINE: 'PD_CREATE_BASELINE',
  TRUST_CHANGE: 'PD_TRUST_CHANGE',
  IGNORE_ONCE: 'PD_IGNORE_ONCE',
  INVESTIGATE: 'PD_INVESTIGATE',
  GET_HISTORY: 'PD_GET_HISTORY',
  SET_PAUSED: 'PD_SET_PAUSED',
  GET_SETTINGS: 'PD_GET_SETTINGS',
  SAVE_SETTINGS: 'PD_SAVE_SETTINGS'
});
export const RISK_LEVELS = Object.freeze({
  LOW: 'LOW', MEDIUM: 'MEDIUM', HIGH: 'HIGH', CRITICAL: 'CRITICAL'
});
export const DEFAULT_SETTINGS = Object.freeze({
  paused: false,
  mediumNotifications: true,
  highNotifications: true,
  criticalNotifications: true,
  thresholds: { medium: 20, high: 50, critical: 80 }
});
export const VOLATILE_QUERY_KEYS = /^(utm_|fbclid$|gclid$|mc_cid$|mc_eid$|cacheBust$|timestamp$|ts$|nonce$)/i;
