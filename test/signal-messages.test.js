// The translated scam explanations. As with the interface strings, these tests
// check coverage and safety, not whether the wording is any good — only a
// native speaker can judge that.

import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { MESSAGES, KINDS, fill, message, kindLabel } from '../data/signal-messages.js';
import { analyzeSignals, toSchema } from '../lib/signals.js';

const LANGS = Object.keys(MESSAGES).filter((c) => c !== 'en');

/** Every signal id the engine can actually emit, read from the source. */
function engineIds() {
  const src = fs.readFileSync(new URL('../lib/signals.js', import.meta.url), 'utf8');
  return [...new Set([...src.matchAll(/id: '([a-z_]+)'/g)].map((m) => m[1]))];
}

test('every language covers every key English has', () => {
  const keys = Object.keys(MESSAGES.en);
  for (const code of LANGS) {
    const missing = keys.filter((k) => typeof MESSAGES[code][k] !== 'string' || !MESSAGES[code][k].length);
    assert.deepEqual(missing, [], `${code} is missing: ${missing.join(', ')}`);
  }
});

test('every signal the engine can emit has a message', () => {
  const missing = engineIds().filter((id) => !(id in MESSAGES.en));
  assert.deepEqual(missing, [], `no message for: ${missing.join(', ')}`);
});

test('no language has keys English does not', () => {
  const keys = new Set(Object.keys(MESSAGES.en));
  for (const code of LANGS) {
    const extra = Object.keys(MESSAGES[code]).filter((k) => !keys.has(k));
    assert.deepEqual(extra, [], `${code} has extra keys: ${extra.join(', ')}`);
  }
});

test('placeholders survive translation', () => {
  // A dropped {org} or {domain} turns a specific, checkable finding into a
  // vague one, which is most of its value gone.
  const placeholders = (s) => (String(s).match(/\{\w+\}/g) || []).sort().join(',');
  for (const [key, en] of Object.entries(MESSAGES.en)) {
    for (const code of LANGS) {
      assert.equal(placeholders(MESSAGES[code][key]), placeholders(en),
        `${code}.${key} placeholders differ from English`);
    }
  }
});

test('every language names every kind of item', () => {
  const keys = Object.keys(KINDS.en);
  for (const code of Object.keys(KINDS)) {
    const missing = keys.filter((k) => !KINDS[code][k]);
    assert.deepEqual(missing, [], `${code} is missing kinds: ${missing.join(', ')}`);
  }
});

test('no message was left as the English original', () => {
  // Catches a language that was copied and not translated. Checked on the long
  // sentences only, since short ones can legitimately coincide.
  for (const key of ['pay_gift_card', 'secrecy', 'what_tail', 'safe_generic', 'reason_none']) {
    for (const code of LANGS) {
      assert.notEqual(MESSAGES[code][key], MESSAGES.en[key], `${code}.${key} is still English`);
    }
  }
});

test('an unknown language falls back to English instead of blanking', () => {
  assert.equal(message('xx', 'pay_crypto'), MESSAGES.en.pay_crypto);
  assert.equal(kindLabel('xx', 'bill'), 'a bill');
  assert.equal(message('es', 'a_key_that_does_not_exist'), '');
});

test('fill leaves an unknown placeholder visible rather than blank', () => {
  assert.equal(fill('from {org} to {nope}', { org: 'IRS' }), 'from IRS to {nope}');
});

// ------------------------------------------- end to end through the engine

test('a Spanish reader gets Spanish reasons, with the domain intact', () => {
  const r = analyzeSignals('Internal Revenue Service: pague en https://irs-falso.com ahora.', { lang: 'es' });
  assert.equal(r.verdict, 'scam');
  assert.ok(r.reasons.some((x) => /Dice que es de/.test(x)), JSON.stringify(r.reasons));
  assert.ok(r.reasons.some((x) => /irs-falso\.com/.test(x)), 'the domain must survive translation');
  assert.ok(!r.reasons.some((x) => /Says it is from/.test(x)));
});

test('the whole summary is translated, not just the reasons', () => {
  const s = toSchema(analyzeSignals('Compre una tarjeta de regalo para pagar su deuda.', { lang: 'es' }));
  assert.match(s.headline, /estafa|cerca/i);
  assert.match(s.what_it_is, /señales conocidas de estafa/);
  assert.match(s.safe_step, /No use el teléfono/);
  assert.match(s.family_message, /no estoy seguro/i);
});

test('every language produces a complete answer with no leftover placeholders', () => {
  const text = 'Internal Revenue Service: pay at https://irs-fake.com or call 888-555-0142.';
  for (const code of ['en', ...LANGS]) {
    const s = toSchema(analyzeSignals(text, { lang: code }));
    for (const field of ['headline', 'what_it_is', 'action_summary', 'safe_step', 'family_message']) {
      assert.ok(s[field] && s[field].length > 0, `${code}.${field} is empty`);
      assert.ok(!/\{\w+\}/.test(s[field]), `${code}.${field} has an unfilled placeholder: ${s[field]}`);
    }
    assert.ok(s.reasons.length > 0, `${code} produced no reasons`);
    assert.ok(!s.reasons.some((r) => /\{\w+\}/.test(r)), `${code} reason has an unfilled placeholder`);
  }
});

test('a clean result carries its caution in every language', () => {
  for (const code of ['en', ...LANGS]) {
    const r = analyzeSignals('Hola, la cena es a las seis.', { lang: code });
    assert.equal(r.verdict, 'real', `${code} needlessly flagged ordinary mail`);
    assert.equal(r.noScamSignsFound, true);
    const s = toSchema(r);
    // Reassurance is fine; claiming it was verified is not. Every language must
    // keep the "this does not mean it is real" half of the sentence.
    assert.ok(s.reasons[0].length > 20, `${code} lost the no-signs caution`);
    assert.ok(s.what_it_is.length > 40, `${code} summary is too thin to carry the caveat`);
  }
});
