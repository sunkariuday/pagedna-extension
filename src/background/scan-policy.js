export function scanPolicyKey(settings = {}, ignored = false) {
  const thresholds = settings.thresholds || {};
  return JSON.stringify({
    thresholds: {
      medium: Number(thresholds.medium),
      high: Number(thresholds.high),
      critical: Number(thresholds.critical)
    },
    notifications: {
      medium: settings.mediumNotifications !== false,
      high: settings.highNotifications !== false,
      critical: settings.criticalNotifications !== false
    },
    ignored: Boolean(ignored)
  });
}

export function canReuseScan(site, fingerprintHash, currentPolicyKey) {
  return Boolean(
    fingerprintHash &&
    site?.lastFingerprint?.hashes?.stable === fingerprintHash &&
    site?.lastResult?.policyKey === currentPolicyKey
  );
}
