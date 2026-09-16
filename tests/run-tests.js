import assert from 'node:assert/strict';
import { diffFingerprints } from '../src/background/diff-engine.js';
import { base, withNewFrameAndScript, changedForm } from './fixtures.js';
const t = (name, fn) => { fn(); console.log(`✓ ${name}`); };
t('clean page has no changes', () => { const r = diffFingerprints(base, base); assert.equal(r.score, 0); assert.equal(r.changes.length, 0); assert.equal(r.level, 'LOW'); });
t('new script and iframe are explained', () => { const r = diffFingerprints(base, withNewFrameAndScript); assert.ok(r.changes.some(x => x.code === 'NEW_SCRIPT_ORIGIN')); assert.ok(r.changes.some(x => x.code === 'NEW_FRAME_ORIGIN')); assert.ok(r.score >= 20); });
t('changed sensitive form destination is high risk', () => { const r = diffFingerprints(base, changedForm); assert.ok(r.changes.some(x => x.code === 'SENSITIVE_FLOW_CHANGED')); assert.ok(r.score >= 40); assert.ok(['HIGH','CRITICAL'].includes(r.level)); });
t('risk score is bounded', () => { const noisy = {...withNewFrameAndScript, structure:{...withNewFrameAndScript.structure,forms:Array.from({length:20},(_,i)=>({...base.structure.forms[0],index:i,actionOrigin:'https://evil.example',actionPathClass:'/collect'}))}, scripts:Array.from({length:30},(_,i)=>({origin:`https://evil${i}.example`,pathClass:'/x.js'}))}; const r = diffFingerprints(base,noisy); assert.ok(r.score >= 0 && r.score <= 100); assert.equal(r.level,'CRITICAL'); });
console.log('All PageDNA tests passed.');
