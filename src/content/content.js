(() => {
  const C = self.PageDNACanonicalizer;
  function collectFingerprint() {
    const scan = self.PageDNADomAnalyzer.analyze();
    const nav = performance.getEntriesByType('navigation')[0];
    const fingerprint = {
      schemaVersion: 1, capturedAt: new Date().toISOString(),
      site: { origin: location.origin, hostname: location.hostname, protocol: location.protocol.replace(':', ''), port: location.port || (location.protocol === 'https:' ? '443' : '80') },
      identity: { protocol: location.protocol.replace(':', ''), port: location.port || '' },
      structure: { forms: scan.forms, frames: scan.frames, sensitiveNodes: scan.sensitiveNodes },
      scripts: scan.scripts,
      origins: scan.originSet.map(origin => ({ origin, role: scan.roleForOrigin(origin) })),
      flows: scan.forms.filter(f => f.hasSensitive || f.crossOrigin).map(f => ({ source: 'form', actionOrigin: f.actionOrigin, actionPathClass: f.actionPathClass, sensitive: f.hasSensitive })),
      navigation: { redirects: nav ? [nav.name].filter(Boolean).map(C.originOf) : [], finalOrigin: location.origin },
      behavior: { downloads: [], popups: [] },
      metrics: { formCount: scan.forms.length, frameCount: scan.frames.length, scriptCount: scan.scripts.length, externalOriginCount: scan.originSet.filter(x => x !== location.origin).length, sensitiveFormCount: scan.forms.filter(f => f.hasSensitive).length },
      hashes: { stable: '', volatileMasked: '' }
    };
    const stable = C.stableStringify({ ...fingerprint, capturedAt: undefined, hashes: undefined });
    fingerprint.hashes.stable = C.hashString(stable);
    fingerprint.hashes.volatileMasked = fingerprint.hashes.stable;
    return fingerprint;
  }
  let scanned = false;
  function scanAndSend() {
    if (scanned) return; scanned = true;
    try { chrome.runtime.sendMessage({ type: 'PD_SCAN_PAGE', fingerprint: collectFingerprint() }); } catch {}
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', scanAndSend, { once: true }); else scanAndSend();
  window.addEventListener('pageshow', scanAndSend, { once: true });
})();
