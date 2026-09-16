(() => {
  const VOLATILE = /^(utm_|fbclid$|gclid$|mc_cid$|mc_eid$|cacheBust$|timestamp$|ts$|nonce$)/i;
  function normalizeUrl(raw, base = location.href) {
    try {
      const url = new URL(raw || base, base);
      url.hash = '';
      const kept = [...url.searchParams.entries()]
        .filter(([key]) => !VOLATILE.test(key))
        .sort(([a], [b]) => a.localeCompare(b));
      url.search = '';
      for (const [key, value] of kept) url.searchParams.append(key, value);
      return url.toString();
    } catch { return String(raw || ''); }
  }
  function originOf(raw, base = location.href) {
    try { return new URL(raw || base, base).origin; } catch { return ''; }
  }
  function pathClass(raw, base = location.href) {
    try {
      const path = new URL(raw || base, base).pathname;
      return path.replace(/\/\d+(?=\/|$)/g, '/:id').replace(/[a-f0-9]{16,}/gi, ':token');
    } catch { return ''; }
  }
  function sortDeep(value) {
    if (Array.isArray(value)) return value.map(sortDeep);
    if (value && typeof value === 'object') return Object.keys(value).sort().reduce((o, k) => { o[k] = sortDeep(value[k]); return o; }, {});
    return value;
  }
  function stableStringify(value) { return JSON.stringify(sortDeep(value)); }
  function hashString(value) {
    let hash = 2166136261;
    for (let i = 0; i < value.length; i++) { hash ^= value.charCodeAt(i); hash = Math.imul(hash, 16777619); }
    return (hash >>> 0).toString(16).padStart(8, '0');
  }
  async function hashStringSha256(value) {
    if (!globalThis.crypto?.subtle) return hashString(value);
    const data = new TextEncoder().encode(value);
    const digest = await globalThis.crypto.subtle.digest('SHA-256', data);
    return [...new Uint8Array(digest)].map(byte => byte.toString(16).padStart(2, '0')).join('');
  }
  self.PageDNACanonicalizer = { normalizeUrl, originOf, pathClass, stableStringify, hashString, hashStringSha256 };
})();
