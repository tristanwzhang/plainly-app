// How the offline rules combine with the model's reading.
// The rule that matters: rules may make a verdict more cautious, never less.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSignals, mergeResults } from '../lib/signals.js';

const modelSaid = (over = {}) => ({
  readable: true, kind_label: 'Letter', verdict: 'real', headline: 'A routine notice',
  what_it_is: 'A letter about your account.', action_needed: false,
  action_summary: 'Nothing to do.', deadline: null, reasons: ['It reads like normal mail.'],
  safe_step: 'Call the number on your statement.', family_message: 'Can you look at this?',
  confidence: 'high', full_translation: null, ...over,
});

test('rules override a model that misses a gift-card demand', () => {
  const rules = analyzeSignals('Pay your overdue balance with a $500 Google Play card today.');
  const out = mergeResults(modelSaid({ verdict: 'real' }), rules, { english: true });
  assert.equal(out.verdict, 'scam', 'a conclusive structural finding must win');
  assert.equal(out.confidence, 'high');
});

test('rules do not downgrade a model that found a scam', () => {
  const rules = analyzeSignals('Hi Grandma, dinner is at six.');
  const out = mergeResults(modelSaid({ verdict: 'scam' }), rules, { english: true });
  assert.equal(out.verdict, 'scam', 'clean rules must not argue the model down');
});

test('clean rules leave a model "real" verdict alone', () => {
  const rules = analyzeSignals('Your library books are due next Tuesday.');
  const out = mergeResults(modelSaid({ verdict: 'real' }), rules, { english: true });
  assert.equal(out.verdict, 'real');
});

test('medium risk stops something being called real', () => {
  // Claimed sender plus a link that is not theirs: 3 + 2 points.
  const rules = analyzeSignals('USPS: reschedule your delivery at https://parcel-fee.top/pay');
  assert.equal(rules.risk, 'medium');
  const out = mergeResults(modelSaid({ verdict: 'real' }), rules, { english: true });
  assert.equal(out.verdict, 'careful');
});

test('a single weak signal does not override the model', () => {
  // A .top link on its own is worth 2 points. The model read the whole letter;
  // one weak structural hint should not be allowed to contradict it.
  const rules = analyzeSignals('Reschedule your delivery at https://parcel-fee.top/pay');
  assert.equal(rules.risk, 'low');
  assert.equal(mergeResults(modelSaid({ verdict: 'real' }), rules, { english: true }).verdict, 'real');
});

test('rule findings appear in reasons for English readers', () => {
  const rules = analyzeSignals('IRS: pay at https://irs-fake-portal.com now.');
  const out = mergeResults(modelSaid(), rules, { english: true });
  assert.ok(out.reasons.some((r) => /\.gov/.test(r)), `expected a .gov reason, got ${JSON.stringify(out.reasons)}`);
  assert.ok(out.reasons.length <= 4);
});

test('non-English readers get the model reasons, not English rule text', () => {
  const rules = analyzeSignals('IRS: pay at https://irs-fake-portal.com now.');
  const out = mergeResults(modelSaid({ reasons: ['Parece un fraude.'] }), rules, { english: false });
  assert.deepEqual(out.reasons, ['Parece un fraude.']);
  // The structured signals still travel, so the UI can use them later.
  assert.ok(out.signals.length > 0);
});

test('with no model reply the rules carry the answer', () => {
  const rules = analyzeSignals('Buy a gift card to clear your IRS debt.');
  const out = mergeResults(null, rules, { english: true });
  assert.equal(out.verdict, 'scam');
  assert.ok(out.headline.length > 0, 'the rules supply a headline when no model does');
  assert.equal(out.checked_offline, true);
  assert.ok(out.reasons.length > 0);
});

test('photo input reports that no offline check happened', () => {
  const out = mergeResults(modelSaid(), null);
  assert.equal(out.checked_offline, false);
  assert.deepEqual(out.signals, []);
  assert.equal(out.verdict, 'real', 'the model stands alone when rules cannot run');
});

test('positives are passed through as checks_out', () => {
  const rules = analyzeSignals('Internal Revenue Service. Pay at irs.gov/payments or call 800-829-1040.');
  const out = mergeResults(modelSaid(), rules, { english: true });
  assert.ok(out.checks_out.length > 0);
});

test('a deadline from the rules fills in when the model missed it', () => {
  const rules = analyzeSignals('Respond within 48 hours or your account closes.');
  const out = mergeResults(modelSaid({ deadline: null }), rules, { english: true });
  assert.match(out.deadline, /48 hours/);
});
