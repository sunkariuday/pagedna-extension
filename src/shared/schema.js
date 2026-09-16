export function emptyFingerprint() {
  return {
    schemaVersion: 1,
    capturedAt: new Date().toISOString(),
    site: { origin: '', hostname: '', protocol: '', port: '' },
    identity: { protocol: '', port: '' },
    structure: { forms: [], frames: [], sensitiveNodes: [] },
    scripts: [],
    origins: [],
    flows: [],
    navigation: { redirects: [], finalOrigin: '' },
    behavior: { downloads: [], popups: [] },
    metrics: { formCount: 0, frameCount: 0, scriptCount: 0, externalOriginCount: 0, sensitiveFormCount: 0 },
    hashes: { stable: '', volatileMasked: '' }
  };
}

export function isFingerprint(value) {
  return Boolean(value && value.site && Array.isArray(value.scripts) && value.structure && Array.isArray(value.structure.forms));
}

export function siteKeyFromFingerprint(fingerprint) {
  return fingerprint?.site?.origin || '';
}
