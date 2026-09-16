(() => {
  const C = self.PageDNACanonicalizer;
  async function collectFingerprint() {
    const scan = await self.PageDNADomAnalyzer.analyze();
    const nav = performance.getEntriesByType('navigation')[0];
    const fingerprint = {
      schemaVersion: 3, capturedAt: new Date().toISOString(),
      site: { origin: location.origin, hostname: location.hostname, protocol: location.protocol.replace(':', ''), port: location.port || (location.protocol === 'https:' ? '443' : '80') },
      identity: { protocol: location.protocol.replace(':', ''), port: location.port || '' },
      structure: { forms: scan.forms, frames: scan.frames, sensitiveNodes: scan.sensitiveNodes },
      scripts: scan.scripts,
      origins: scan.originSet.map(origin => ({ origin, role: scan.roleForOrigin(origin) })),
      flows: scan.forms.filter(f => f.hasSensitive || f.crossOrigin).map(f => ({ source: 'form', actionOrigin: f.actionOrigin, actionPathClass: f.actionPathClass, sensitive: f.hasSensitive })),
      navigation: { redirects: nav ? [nav.name].filter(Boolean).map(C.originOf) : [], finalOrigin: location.origin },
      behavior: { downloads: [], popups: [] },
      metrics: { formCount: scan.forms.length, frameCount: scan.frames.length, scriptCount: scan.scripts.length, externalOriginCount: scan.originSet.filter(x => x !== location.origin).length, sensitiveFormCount: scan.forms.filter(f => f.hasSensitive).length },
      hashes: { algorithm: 'sha256', stable: '', volatileMasked: '' }
    };
    const stable = C.stableStringify({ ...fingerprint, capturedAt: undefined, hashes: undefined });
    fingerprint.hashes.stable = await C.hashStringSha256(stable);
    fingerprint.hashes.volatileMasked = fingerprint.hashes.stable;
    return fingerprint;
  }
  let lastSentHash = '';
  let scanTimer = null;
  let scheduled = false;
  async function scanAndSend(force = false) {
    scheduled = false;
    try {
      const fingerprint = await collectFingerprint();
      if (!force && fingerprint.hashes.stable === lastSentHash) return;
      lastSentHash = fingerprint.hashes.stable;
      chrome.runtime.sendMessage({ type: 'PD_SCAN_PAGE', fingerprint });
    } catch {}
  }
  function scheduleScan() {
    if (scheduled) return;
    scheduled = true;
    clearTimeout(scanTimer);
    scanTimer = setTimeout(() => { void scanAndSend(false); }, 350);
  }
  function startObservers() {
    if (!document.documentElement) return;
    const observer = new MutationObserver(mutations => {
      const relevant = mutations.some(m => m.type === 'childList' || m.type === 'attributes');
      if (relevant) scheduleScan();
    });
    observer.observe(document.documentElement, { subtree: true, childList: true, attributes: true, attributeFilter: ['src', 'href', 'action', 'method', 'type', 'name', 'autocomplete', 'integrity'] });
  }
  function initialScan() {
    void scanAndSend(true);
    startObservers();
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', initialScan, { once: true }); else initialScan();
  window.addEventListener('pageshow', () => { void scanAndSend(true); });
  window.addEventListener('popstate', () => { void scanAndSend(true); });
  window.addEventListener('hashchange', scheduleScan);
})();
