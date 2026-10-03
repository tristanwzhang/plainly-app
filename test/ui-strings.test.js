// The shipped interface translations. The point of these tests is coverage and
// safety, not quality — only a native speaker can judge the wording.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { UI_STRINGS, hasStatic, staticStrings } from '../data/ui-strings.js';

/** The language codes the UI actually offers, read from the page itself. */
function uiLanguages() {
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const block = html.match(/var LANGS\s*=\s*\[[\s\S]*?\];/)[0];
  return [...block.matchAll(/code:\s*'([a-z]{2,3})'/g)].map((m) => m[1]);
}

/**
 * The English keys the UI sends for translation.
 *
 * String values are blanked first. Without that, a value ending in a colon
 * ("This looks like:", "Time frame:") is read as a key named `like` or `frame`.
 */
function uiKeys() {
  const html = fs.readFileSync(new URL('../public/index.html', import.meta.url), 'utf8');
  const block = html.match(/var STR\s*=\s*\{[\s\S]*?\n\s{2}\};/)[0];
  const blanked = block.replace(/"(?:\\.|[^"\\])*"/g, '""');
  return [...blanked.matchAll(/([a-zA-Z_][\w]*)\s*:\s*""/g)].map((m) => m[1]);
}

test('every language the UI offers has a translation (English aside)', () => {
  const missing = uiLanguages().filter((c) => c !== 'en' && !UI_STRINGS[c]);
  assert.deepEqual(missing, [], `no static strings for: ${missing.join(', ')}`);
});

test('every language covers every key the UI sends', () => {
  const keys = uiKeys();
  assert.ok(keys.length > 50, `expected the full string table, found ${keys.length} keys`);
  for (const [code, table] of Object.entries(UI_STRINGS)) {
    const missing = keys.filter((k) => typeof table[k] !== 'string' || !table[k].length);
    assert.deepEqual(missing, [], `${code} is missing: ${missing.join(', ')}`);
  }
});

test('no language has stray keys the UI never asks for', () => {
  const keys = new Set(uiKeys());
  for (const [code, table] of Object.entries(UI_STRINGS)) {
    const extra = Object.keys(table).filter((k) => !keys.has(k));
    assert.deepEqual(extra, [], `${code} has keys the UI does not use: ${extra.join(', ')}`);
  }
});

test('the {n} placeholder survives in every language', () => {
  for (const [code, table] of Object.entries(UI_STRINGS)) {
    assert.ok(table.nExamples.includes('{n}'), `${code} lost the {n} placeholder`);
  }
});

test('no translation was left as the English original', () => {
  // Catches a half-finished language that was copied and not translated.
  // Short labels can legitimately coincide, so only longer text is checked.
  const english = { lead: true, pasteHelp: true, retakeTip: true, lowConf: true, fine: true };
  for (const [code, table] of Object.entries(UI_STRINGS)) {
    for (const k of Object.keys(english)) {
      assert.ok(!/^Got a letter|^Copy a text|^Try again in good light|^I'm not sure about this one|^Prototype for a hackathon/.test(table[k]),
        `${code}.${k} is still the English text`);
    }
  }
});

test('hasStatic is true for a covered language and false otherwise', () => {
  const keys = uiKeys();
  assert.equal(hasStatic('es', keys), true);
  assert.equal(hasStatic('xx', keys), false);
  assert.equal(hasStatic('es', [...keys, 'aKeyThatDoesNotExist']), false);
});

test('staticStrings falls back to English per missing key', () => {
  const out = staticStrings('es', { check: 'Check it', madeUpKey: 'Only in English' });
  assert.equal(out.check, 'Revisarlo');
  assert.equal(out.madeUpKey, 'Only in English', 'an unknown key must keep its English text');
});

test('an unknown language returns English rather than blanks', () => {
  const out = staticStrings('xx', { check: 'Check it', back: 'Back' });
  assert.deepEqual(out, { check: 'Check it', back: 'Back' });
});

// --------------------------------------------------- the endpoint's caching

/** Minimal fake req/res so the handler can be driven without a server. */
function call(handler, body) {
  return new Promise((resolve) => {
    const res = {
      setHeader() {},
      status(code) { this.code = code; return this; },
      json(payload) { resolve({ code: this.code, body: payload }); return this; },
    };
    handler({ method: 'POST', headers: {}, socket: {}, body }, res);
  });
}

test('a cached language is not served to a request wanting more keys', async () => {
  // Regression: the cache was keyed on language alone, so an early request for
  // two keys left every later caller falling back to English for the rest.
  // In the browser that looked like a half-translated page.
  process.env.MOCK = '1';
  const { default: handler } = await import('../api/translate-ui.js?cachebust=' + Date.now());
  const lang = { code: 'es', en: 'Spanish', native: 'Espanol' };

  const few = await call(handler, { lang, strings: { check: 'Check it', back: 'Back' } });
  assert.equal(Object.keys(few.body).length, 2);

  const many = await call(handler, {
    lang,
    strings: { check: 'Check it', back: 'Back', paste: 'Paste a text', whatIs: 'What this is', copy: 'Copy' },
  });
  assert.equal(Object.keys(many.body).length, 5, 'every requested key must come back');
  assert.equal(many.body.whatIs, 'Qué es esto', 'the extra keys must be translated, not English');
  assert.equal(many.body.copy, 'Copiar');
});

test('English is returned untouched without consulting the cache', async () => {
  process.env.MOCK = '1';
  const { default: handler } = await import('../api/translate-ui.js?cachebust=' + Date.now());
  const out = await call(handler, { lang: { code: 'en', en: 'English', native: 'English' }, strings: { check: 'Check it' } });
  assert.deepEqual(out.body, { check: 'Check it' });
});
