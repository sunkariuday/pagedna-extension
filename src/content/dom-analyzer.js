(() => {
  const C = self.PageDNACanonicalizer;
  function roleForOrigin(origin) {
    if (!origin || origin === location.origin) return 'first-party';
    if (/google|doubleclick|analytics|facebook|sentry|cloudflare|jsdelivr|unpkg|cdnjs/i.test(origin)) return 'known-service';
    return 'external';
  }
  function analyzeScripts() {
    return [...document.scripts].map((script, index) => {
      const src = script.src ? C.normalizeUrl(script.src) : '';
      const content = script.src ? '' : (script.textContent || '').slice(0, 20000);
      return {
        index, origin: src ? C.originOf(src) : location.origin, pathClass: src ? C.pathClass(src) : 'inline',
        type: script.type || 'classic', module: script.type === 'module', async: Boolean(script.async), defer: Boolean(script.defer),
        inline: !Boolean(src), inlineLength: content.length, inlineHash: content ? C.hashString(content) : ''
      };
    });
  }
  function analyzeSensitiveNodes() {
    const selectors = ['input[type=password]', 'input[name*=card i]', 'input[name*=cvv i]', '[autocomplete=cc-number]', '[contenteditable=true]'];
    return selectors.flatMap(selector => [...document.querySelectorAll(selector)].map(node => ({ selector, tag: node.tagName.toLowerCase() })));
  }
  function analyze() {
    const scripts = analyzeScripts();
    const forms = self.PageDNAFormAnalyzer.analyzeForms();
    const frames = self.PageDNAFrameAnalyzer.analyzeFrames();
    const sensitiveNodes = analyzeSensitiveNodes();
    const originSet = new Set([...scripts, ...frames].map(x => x.origin).filter(Boolean));
    return { scripts, forms, frames, sensitiveNodes, originSet: [...originSet], roleForOrigin };
  }
  self.PageDNADomAnalyzer = { analyze, roleForOrigin };
})();
