function keyOf(item) { return JSON.stringify(item); }
function setDiff(oldItems = [], newItems = []) {
  const oldSet = new Set(oldItems.map(keyOf));
  const newSet = new Set(newItems.map(keyOf));
  return { added: newItems.filter(x => !oldSet.has(keyOf(x))), removed: oldItems.filter(x => !newSet.has(keyOf(x))) };
}
function byOrigin(items = []) { return items.map(x => ({ origin: x.origin || x.actionOrigin, pathClass: x.pathClass || x.actionPathClass || '', type: x.type || '', module: Boolean(x.module) })); }
export function diffFingerprints(baseline, current) {
  const changes = [];
  if (!baseline || !current) return { changes, counts: {}, score: 0, level: 'LOW', matchPercent: 0 };
  if (baseline.site.origin !== current.site.origin) changes.push({ code: 'BOUNDARY_CHANGE', category: 'boundary', severity: 'high', label: 'Page origin changed', oldValue: baseline.site.origin, newValue: current.site.origin, why: 'The monitored security boundary is different.' });
  const scripts = setDiff(byOrigin(baseline.scripts), byOrigin(current.scripts));
  scripts.added.forEach(x => changes.push({ code: 'NEW_SCRIPT_ORIGIN', category: 'resource', severity: 'medium', label: 'New script resource', oldValue: 'not present', newValue: `${x.origin}${x.pathClass}`, why: 'New executable code can change page behavior.' }));
  scripts.removed.forEach(x => changes.push({ code: 'SCRIPT_REMOVED', category: 'resource', severity: 'low', label: 'Script removed', oldValue: `${x.origin}${x.pathClass}`, newValue: 'not present', why: 'A page dependency changed.' }));
  const frames = setDiff(byOrigin(baseline.structure.frames), byOrigin(current.structure.frames));
  frames.added.forEach(x => changes.push({ code: 'NEW_FRAME_ORIGIN', category: 'resource', severity: 'medium', label: 'New iframe origin', oldValue: 'not present', newValue: x.origin, why: 'Embedded content can receive data or alter the user flow.' }));
  frames.removed.forEach(x => changes.push({ code: 'FRAME_REMOVED', category: 'resource', severity: 'low', label: 'Iframe removed', oldValue: x.origin, newValue: 'not present', why: 'Embedded page structure changed.' }));
  const oldForms = new Map((baseline.structure.forms || []).map(x => [x.index, x]));
  const newForms = new Map((current.structure.forms || []).map(x => [x.index, x]));
  for (const [index, form] of newForms) {
    const old = oldForms.get(index);
    if (!old) { changes.push({ code: 'NEW_FORM', category: 'boundary', severity: form.hasSensitive ? 'high' : 'medium', label: 'New form', oldValue: 'not present', newValue: `${form.method} ${form.actionOrigin}${form.actionPathClass}`, why: 'A new submission flow appeared.' }); continue; }
    if (old.actionOrigin !== form.actionOrigin || old.actionPathClass !== form.actionPathClass) changes.push({ code: 'SENSITIVE_FLOW_CHANGED', category: 'sensitive-flow', severity: form.hasSensitive || old.hasSensitive ? 'critical' : 'high', label: 'Form destination changed', oldValue: `${old.actionOrigin}${old.actionPathClass}`, newValue: `${form.actionOrigin}${form.actionPathClass}`, why: 'Submitted data may now go to a different destination.' });
    if (old.hasSensitive !== form.hasSensitive || keyOf(old.sensitiveFields) !== keyOf(form.sensitiveFields)) changes.push({ code: 'SENSITIVE_FIELD_CHANGED', category: 'sensitive-flow', severity: 'high', label: 'Sensitive field profile changed', oldValue: old.sensitiveFields.join(', ') || 'none', newValue: form.sensitiveFields.join(', ') || 'none', why: 'The data requested by this flow changed.' });
  }
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
    redirectChange: changes.filter(c => c.code === 'NAVIGATION_CHANGE').length,
    unfamiliarity: unfamiliar.length,
    compoundBonus: changes.filter(c => ['sensitive-flow', 'navigation', 'boundary'].includes(c.category)).length >= 2 ? 1 : 0
  };
  const score = Math.min(100, counts.boundaryChange * 25 + counts.sensitiveFlowChange * 40 + counts.newScriptOrigin * 15 + counts.newFrameOrigin * 10 + counts.redirectChange * 20 + counts.unfamiliarity * 10 + counts.compoundBonus * 40);
  const level = score >= 80 ? 'CRITICAL' : score >= 50 ? 'HIGH' : score >= 20 ? 'MEDIUM' : 'LOW';
  const total = Math.max(1, (baseline.scripts?.length || 0) + (baseline.structure?.frames?.length || 0) + (baseline.structure?.forms?.length || 0));
  const matchPercent = Math.max(0, Math.round(100 - (changes.length / total) * 100));
  return { changes, counts, score, level, matchPercent };
}
