(() => {
  const C = self.PageDNACanonicalizer;
  const sensitiveNames = /pass(word)?|otp|one[-_ ]?time|cvv|cvc|card|credit|debit|bank|ssn|security|pin|token/i;
  function classifyField(field) {
    const text = [field.type, field.name, field.id, field.autocomplete, field.getAttribute('aria-label')].filter(Boolean).join(' ');
    if (field.type === 'password' || /pass(word)?/i.test(text)) return 'password';
    if (/cvv|cvc|card|credit|debit/i.test(text)) return 'payment';
    if (/otp|one[-_ ]?time|pin|token|ssn|security/i.test(text)) return 'credential';
    return null;
  }
  function analyzeForms() {
    return [...document.forms].map((form, index) => {
      const action = C.normalizeUrl(form.getAttribute('action') || location.href);
      const fields = [...form.elements].filter(e => e.tagName === 'INPUT' || e.tagName === 'TEXTAREA' || e.tagName === 'SELECT');
      const sensitiveFields = fields.map(classifyField).filter(Boolean);
      return {
        index, method: (form.method || 'get').toUpperCase(), actionOrigin: C.originOf(action), actionPathClass: C.pathClass(action),
        fieldTypes: fields.map(e => e.type || e.tagName.toLowerCase()).sort(),
        sensitiveFields: [...new Set(sensitiveFields)],
        hasSensitive: sensitiveFields.length > 0,
        crossOrigin: C.originOf(action) !== location.origin
      };
    });
  }
  self.PageDNAFormAnalyzer = { analyzeForms, classifyField };
})();
