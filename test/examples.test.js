// The examples built into the app are what a judge or a first-time user will
// click, so they are the cases that must not embarrass us. Each scam example
// here is checked twice: as written, and as the browser actually sends it after
// client-side redaction — because redaction can erase the very wording a rule
// depends on.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSignals } from '../lib/signals.js';

/** Approximate what public/index.html's redaction does before sending. */
function redact(text) {
  return text
    .replace(/(\bDear\s+)((?:Mr\.|Mrs\.|Ms\.|Dr\.)?\s*[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)(?=[,:\n])/g, '$1[HIDDEN NAME]')
    .replace(/^((?:Patient|Member|Name|Account holder|Customer)\s*:\s*)(.+)$/gim, '$1[HIDDEN NAME]')
    .replace(/\b(?:\d[ -]?){13,16}\b/g, '[HIDDEN NUMBER]')
    .replace(/\b\d{3}-\d{2}-\d{4}\b/g, '[HIDDEN NUMBER]');
}

const BANK_PHISH = `Heartland Community Bank. SECURITY DEPARTMENT
Dear Valued Customer,

We have detected unusual sign-ins on your checking account. Your account will be CLOSED in 48 hours unless you verify your details.

Call our Security Team at 1-844-555-0167 or visit www.heartland-secure-verify.example and enter your online banking password and the 6-digit code we text you.

Failure to act will result in permanent loss of funds.

Account: 4400-2287-1130`;

const SSA_PHISH = `SOCIAL SECURITY ADMINISTRATION. FINAL NOTICE
Dear Margaret Ellis,

Your Social Security number ending in 4821 has been linked to suspicious activity. Your benefits will be SUSPENDED within 24 hours and a warrant may be issued.

You must call Officer Dale Brooks immediately at 1-800-555-0142 to avoid arrest. Do not discuss this letter with your family or your bank.

To resolve the case, a refund deposit of $850 must be paid today using gift cards or a wire transfer.

Case ID: SSA-77-90312`;

const REAL_STATEMENT = `Heartland Community Bank
Monthly statement: September 2026

Account holder: Margaret Ellis
Starting balance ....... $3,412.55
Ending balance ......... $4,136.15

Questions about a charge? Call the number on the back of your debit card.`;

test('the built-in bank phishing letter is caught, redacted or not', () => {
  for (const [label, text] of [['as written', BANK_PHISH], ['as sent', redact(BANK_PHISH)]]) {
    const r = analyzeSignals(text);
    assert.equal(r.verdict, 'scam', `${label}: got ${r.verdict} (score ${r.score}, ${r.signals.map((s) => s.id).join(', ') || 'nothing'})`);
  }
});

test('the bank letter is caught on several independent grounds', () => {
  // Not resting on one rule: any single pattern can be dodged by rewording.
  const ids = analyzeSignals(BANK_PHISH).signals.map((s) => s.id);
  for (const id of ['ask_password', 'ask_digit_code', 'threat']) {
    assert.ok(ids.includes(id), `expected ${id}, got ${ids.join(', ')}`);
  }
});

test('the built-in Social Security scam is caught, redacted or not', () => {
  for (const [label, text] of [['as written', SSA_PHISH], ['as sent', redact(SSA_PHISH)]]) {
    const r = analyzeSignals(text);
    assert.equal(r.verdict, 'scam', `${label}: got ${r.verdict} (score ${r.score})`);
  }
});

test('the built-in real bank statement is not called a scam', () => {
  const r = analyzeSignals(REAL_STATEMENT);
  assert.notEqual(r.verdict, 'scam', `signals: ${r.signals.map((s) => s.id).join(', ')}`);
});

test('redaction is noted as able to hide a signal', () => {
  // "Dear Valued Customer" is a scam sign; redaction turns it into a name and
  // the signal is lost. The letter must still be caught on other grounds, which
  // is exactly why no single rule is allowed to carry a verdict.
  const asWritten = analyzeSignals(BANK_PHISH).signals.map((s) => s.id);
  const asSent = analyzeSignals(redact(BANK_PHISH)).signals.map((s) => s.id);
  assert.ok(asWritten.includes('generic_greeting'));
  assert.ok(!asSent.includes('generic_greeting'), 'redaction is expected to hide this one');
  assert.equal(analyzeSignals(redact(BANK_PHISH)).verdict, 'scam');
});

test('an "in N hours" deadline counts the same as "within N hours"', () => {
  assert.ok(analyzeSignals('Your account will be closed in 48 hours.').signals.some((s) => s.id === 'urgency'));
  assert.ok(analyzeSignals('Your account will be closed within 48 hours.').signals.some((s) => s.id === 'urgency'));
});

test('advice to change your password is not treated as a request for it', () => {
  // A real bank says this. Convicting on it would be a costly false positive.
  for (const line of ['We recommend you change your password regularly.', 'You can update your password in settings.', 'Reset your password if you suspect a problem.']) {
    const ids = analyzeSignals(line).signals.map((s) => s.id);
    assert.ok(!ids.includes('ask_password'), `wrongly flagged: ${line}`);
  }
});
