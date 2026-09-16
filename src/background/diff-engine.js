function keyOf(item) { return JSON.stringify(item); }
function setDiff(oldItems = [], newItems = []) {
  const oldSet = new Set(oldItems.map(keyOf));
  const newSet = new Set(newItems.map(keyOf));
  return { added: newItems.filter(x => !oldSet.has(keyOf(x))), removed: oldItems.filter(x => !newSet.has(keyOf(x))) };
}
function scriptKey(x) {
  return {
    origin: x.origin || '', pathClass: x.pathClass || '', type: x.type || '', module: Boolean(x.module),
    inline: Boolean(x.inline), inlineHash: x.inline ? (x.inlineHash || '') : ''
  };
}
function byOrigin(items = []) { return items.map(x => ({ origin: x.origin || x.actionOrigin, pathClass: x.pathClass || x.actionPathClass || '', type: x.type || '', module: Boolean(x.module) })); }
function formKey(x) {
  return [x.method || 'GET', x.actionOrigin || '', x.actionPathClass || '', Boolean(x.hasSensitive), ...(x.sensitiveFields || [])].join('|');
}
function thresholdLevel(score, thresholds = {}) {
  const medium = Number.isFinite(Number(thresholds.medium)) ? Number(thresholds.medium) : 20;
  const high = Number.isFinite(Number(thresholds.high)) ? Number(thresholds.high) : 50;
  const critical = Number.isFinite(Number(thresholds.critical)) ? Number(thresholds.critical) : 80;
  if (score >= critical) return 'CRITICAL';
  if (score >= high) return 'HIGH';
  if (score >= medium) return 'MEDIUM';
  return 'LOW';
}
export function diffFingerprints(baseline, current, settings = {}) {
  const changes = [];
  if (!baseline || !current) return { changes, counts: {}, score: 0, level: 'LOW', matchPercent: 0 };
  if (baseline.site.origin !== current.site.origin) changes.push({ code: 'BOUNDARY_CHANGE', category: 'boundary', severity: 'high', label: 'Page origin changed', oldValue: baseline.site.origin, newValue: current.site.origin, why: 'The monitored security boundary is different.' });

  const oldScripts = baseline.scripts || [], newScripts = current.scripts || [];
  const oldExternalScripts = oldScripts.filter(x => !x.inline).map(scriptKey);
  const newExternalScripts = newScripts.filter(x => !x.inline).map(scriptKey);
  const scripts = setDiff(oldExternalScripts, newExternalScripts);
  scripts.added.forEach(x => changes.push({ code: 'NEW_SCRIPT_ORIGIN', category: 'resource', severity: 'medium', label: 'New script resource', oldValue: 'not present', newValue: `${x.origin}${x.pathClass}`, why: 'New executable code can change page behavior.' }));
  scripts.removed.forEach(x => changes.push({ code: 'SCRIPT_REMOVED', category: 'resource', severity: 'low', label: 'Script removed', oldValue: `${x.origin}${x.pathClass}`, newValue: 'not present', why: 'A page dependency changed.' }));

  const oldInline = oldScripts.filter(x => x.inline).map(scriptKey);
  const newInline = newScripts.filter(x => x.inline).map(scriptKey);
  const inline = setDiff(oldInline, newInline);
  inline.added.forEach(x => changes.push({ code: 'INLINE_SCRIPT_CHANGED', category: 'resource', severity: 'high', label: 'Inline script changed or added', oldValue: 'not present', newValue: `inline:${x.inlineHash || 'empty'}`, why: 'Inline executable content differs from the trusted baseline.' }));
  inline.removed.forEach(x => changes.push({ code: 'INLINE_SCRIPT_REMOVED', category: 'resource', severity: 'low', label: 'Inline script removed', oldValue: `inline:${x.inlineHash || 'empty'}`, newValue: 'not present', why: 'Inline executable content was removed.' }));

  const frames = setDiff(byOrigin(baseline.structure?.frames), byOrigin(current.structure?.frames));
  frames.added.forEach(x => changes.push({ code: 'NEW_FRAME_ORIGIN', category: 'resource', severity: 'medium', label: 'New iframe origin', oldValue: 'not present', newValue: x.origin, why: 'Embedded content can receive data or alter the user flow.' }));
  frames.removed.forEach(x => changes.push({ code: 'FRAME_REMOVED', category: 'resource', severity: 'low', label: 'Iframe removed', oldValue: x.origin, newValue: 'not present', why: 'Embedded page structure changed.' }));

  const oldForms = baseline.structure?.forms || [], newForms = current.structure?.forms || [];
  const oldFormMap = new Map(oldForms.map(x => [formKey(x), x]));
  const newFormMap = new Map(newForms.map(x => [formKey(x), x]));
  const unmatchedOld = oldForms.filter(x => !newFormMap.has(formKey(x)));
  const unmatchedNew = newForms.filter(x => !oldFormMap.has(formKey(x)));
  unmatchedNew.forEach(form => changes.push({ code: 'NEW_FORM', category: 'boundary', severity: form.hasSensitive ? 'high' : 'medium', label: 'New form', oldValue: 'not present', newValue: `${form.method} ${form.actionOrigin}${form.actionPathClass}`, why: 'A new submission flow appeared.' }));
  unmatchedOld.forEach(form => changes.push({ code: 'FORM_REMOVED', category: 'boundary', severity: 'low', label: 'Form removed', oldValue: `${form.method} ${form.actionOrigin}${form.actionPathClass}`, newValue: 'not present', why: 'A submission flow was removed.' }));

  const oldRedirects = baseline.navigation?.redirects || [], newRedirects = current.navigation?.redirects || [];
  if (keyOf(oldRedirects) !== keyOf(newRedirects) || baseline.navigation?.finalOrigin !== current.navigation?.finalOrigin) changes.push({ code: 'NAVIGATION_CHANGE', category: 'navigation', severity: 'high', label: 'Navigation destination changed', oldValue: baseline.navigation?.finalOrigin || oldRedirects.join(' → '), newValue: current.navigation?.finalOrigin || newRedirects.join(' → '), why: 'The page may be redirecting to a different origin.' });
  const oldOrigins = new Set((baseline.origins || []).map(x => x.origin)), newOrigins = new Set((current.origins || []).map(x => x.origin));
  const unfamiliar = [...newOrigins].filter(x => !oldOrigins.has(x) && x !== current.site.origin && !/google|doubleclick|analytics|facebook|sentry|cloudflare|jsdelivr|unpkg|cdnjs/i.test(x));
  unfamiliar.forEach(origin => changes.push({ code: 'UNFAMILIAR_ORIGIN', category: 'boundary', severity: 'medium', label: 'Unfamiliar external origin', oldValue: 'not present', newValue: origin, why: 'A new third-party boundary was introduced.' }));

  const counts = {
    boundaryChange: changes.filter(c => c.category === 'boundary').length,
    sensitiveFlowChange: changes.filter(c => c.category === 'sensitive-flow').length,
    newScriptOrigin: changes.filter(c => c.code === 'NEW_SCRIPT_ORIGIN').length,
    newFrameOrigin: changes.filter(c => c.code === 'NEW_FRAME_ORIGIN').length,
    inlineScriptChange: changes.filter(c => ['INLINE_SCRIPT_CHANGED', 'INLINE_SCRIPT_REMOVED'].includes(c.code)).length,
    redirectChange: changes.filter(c => c.code === 'NAVIGATION_CHANGE').length,
    unfamiliarity: unfamiliar.length,
    compoundBonus: changes.filter(c => ['sensitive-flow', 'navigation', 'boundary'].includes(c.category)).length >= 2 ? 1 : 0
  };
  const score = Math.min(100, counts.boundaryChange * 25 + counts.sensitiveFlowChange * 40 + counts.newScriptOrigin * 15 + counts.newFrameOrigin * 10 + counts.inlineScriptChange * 25 + counts.redirectChange * 20 + counts.unfamiliarity * 10 + counts.compoundBonus * 40);
  const level = thresholdLevel(score, settings.thresholds);
  const total = Math.max(1, oldScripts.length + (baseline.structure?.frames?.length || 0) + oldForms.length);
  const matchPercent = Math.max(0, Math.round(100 - (changes.length / total) * 100));
  return { changes, counts, score, level, matchPercent };
}
