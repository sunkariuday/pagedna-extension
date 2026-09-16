(() => {
  const C = self.PageDNACanonicalizer;
  function roleForOrigin(origin) {
    if (!origin || origin === location.origin) return 'first-party';
    if (/google|doubleclick|analytics|facebook|sentry|cloudflare|jsdelivr|unpkg|cdnjs/i.test(origin)) return 'known-service';
    return 'external';
  }
  async function analyzeScripts() {
    return Promise.all([...document.scripts].map(async (script, index) => {
      const src = script.src ? C.normalizeUrl(script.src) : '';
      const content = script.src ? '' : (script.textContent || '');
      return {
        index, origin: src ? C.originOf(src) : location.origin, pathClass: src ? C.pathClass(src) : 'inline',
        type: script.type || 'classic', module: script.type === 'module', async: Boolean(script.async), defer: Boolean(script.defer),
        inline: !Boolean(src), inlineLength: content.length,
        inlineHash: content ? await C.hashStringSha256(content) : '',
        integrity: script.getAttribute('integrity') || ''
      };
    }));
  }
  function analyzeSensitiveNodes() {
    const selectors = ['input[type=password]', 'input[name*=card i]', 'input[name*=cvv i]', '[autocomplete=cc-number]', '[contenteditable=true]'];
    return selectors.flatMap(selector => [...document.querySelectorAll(selector)].map(node => ({ selector, tag: node.tagName.toLowerCase() })));
  }
  async function analyze() {
    const scripts = await analyzeScripts();
    const forms = self.PageDNAFormAnalyzer.analyzeForms();
    const frames = self.PageDNAFrameAnalyzer.analyzeFrames();
    const sensitiveNodes = analyzeSensitiveNodes();
    const originSet = new Set([...scripts, ...frames].map(x => x.origin).filter(Boolean));
    return { scripts, forms, frames, sensitiveNodes, originSet: [...originSet], roleForOrigin };
  }
  self.PageDNADomAnalyzer = { analyze, analyzeScripts, roleForOrigin };
})();
