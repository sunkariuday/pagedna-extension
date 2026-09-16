(() => {
  const C = self.PageDNACanonicalizer;
  function analyzeFrames() {
    return [...document.querySelectorAll('iframe, frame')].map((frame, index) => {
      const raw = frame.getAttribute('src') || 'about:blank';
      const src = C.normalizeUrl(raw);
      return {
        index, tag: frame.tagName.toLowerCase(), origin: C.originOf(src), pathClass: C.pathClass(src),
        sandbox: frame.getAttribute('sandbox') || '', titlePresent: Boolean(frame.getAttribute('title')),
        isCrossOrigin: C.originOf(src) !== location.origin && C.originOf(src) !== 'null'
      };
    });
  }
  self.PageDNAFrameAnalyzer = { analyzeFrames };
})();
