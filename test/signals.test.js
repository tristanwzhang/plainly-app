// Run with: npm test
//
// These examples are written the way the real things read. The most important
// tests here are the ones that assert something is NOT called a scam: a tool
// that cries wolf on genuine government mail teaches people to ignore it.

import test from 'node:test';
import assert from 'node:assert/strict';
import { analyzeSignals, toSchema, registrable, editDistance, findDeadline, guessKind } from '../lib/signals.js';

// ----------------------------------------------------------------- real scams

test('gift card demand is called a scam', () => {
  const r = analyzeSignals('FINAL NOTICE: Your utility account is past due. To avoid shut-off today, purchase a $500 Google Play card and call us back with the code.');
  assert.equal(r.verdict, 'scam');
  assert.equal(r.risk, 'high');
  assert.ok(r.signals.some((s) => s.id === 'pay_gift_card'));
});

test('IRS claim with a non-gov link is called a scam', () => {
  const r = analyzeSignals('Internal Revenue Service: you have an unpaid balance. Settle at https://irs-payment-portal.com/settle within 24 hours to avoid arrest.');
  assert.equal(r.verdict, 'scam');
  assert.ok(r.signals.some((s) => s.id === 'gov_mismatch'), 'should notice the .com link');
});

test('lookalike domain is caught by character swaps', () => {
  const r = analyzeSignals('Your PayPal account is limited. Log in at http://paypa1.com/resolve to restore access.');
  assert.equal(r.verdict, 'scam');
  assert.ok(r.signals.some((s) => s.id === 'lookalike_exact'));
});

test('brand name in front of an unrelated domain is caught', () => {
  const r = analyzeSignals('Amazon security alert. Verify your account at https://amazon.account-verify.xyz/login');
  assert.ok(['scam', 'careful'].includes(r.verdict));
  assert.ok(r.signals.some((s) => s.id === 'brand_subdomain' || s.id === 'org_domain_mismatch'));
});

test('plural gift cards are caught, not just the singular', () => {
  // Regression: a word-boundary after "card" missed "cards", which is how
  // people actually get asked ("buy three Google Play cards").
  for (const phrase of ['a gift card', 'two gift cards', 'three Google Play cards', 'iTunes cards']) {
    const r = analyzeSignals(`To settle this, buy ${phrase} and call us with the numbers.`);
    assert.ok(r.signals.some((s) => s.id === 'pay_gift_card'), `missed: ${phrase}`);
  }
});

test('the grandparent scam is caught', () => {
  const r = analyzeSignals('Grandma it is me, I am in jail and need bail money. Please do not tell mom. Buy three $500 Google Play cards and read me the codes.');
  assert.equal(r.verdict, 'scam');
  assert.ok(r.signals.some((s) => s.id === 'pay_gift_card'));
  assert.ok(r.signals.some((s) => s.id === 'secrecy'));
});

test('a lookalike is not also reported as a subdomain trick', () => {
  // "paypa1.com puts PayPal's name in front of paypa1.com" is nonsense wording.
  const r = analyzeSignals('Sign in at http://paypa1.com/resolve');
  assert.ok(!r.signals.some((s) => s.id === 'brand_subdomain'));
  assert.ok(r.signals.some((s) => s.id === 'lookalike_exact'));
});

test('request for a one-time code is conclusive', () => {
  const r = analyzeSignals('This is your bank. To cancel the pending charge, reply with the 6-digit verification code we just texted you.');
  assert.equal(r.verdict, 'scam');
  assert.ok(r.signals.some((s) => s.id === 'ask_otp'));
});

test('punycode address is caught', () => {
  const r = analyzeSignals('Account notice: sign in at https://xn--pypal-4ve.com/verify to continue.');
  assert.equal(r.verdict, 'scam');
  assert.ok(r.signals.some((s) => s.id === 'punycode'));
});

test('a link that hides its real destination is caught', () => {
  const r = analyzeSignals('Delivery held. Reschedule here: https://www.usps.com@track-parcel.top/fee');
  assert.ok(r.signals.some((s) => s.id === 'at_in_url'));
  assert.equal(r.verdict, 'scam');
});

test('wrong callback number for a known agency is flagged', () => {
  const r = analyzeSignals('Social Security Administration: your benefits are suspended. Call 888-555-0142 to reactivate.');
  assert.ok(r.signals.some((s) => s.id === 'phone_mismatch'));
});

test('secrecy instruction is flagged', () => {
  const r = analyzeSignals('We are investigating fraud on your account. Do not tell anyone about this call, including bank staff.');
  assert.ok(r.signals.some((s) => s.id === 'secrecy'));
});

// ------------------------------------- genuine mail must NOT be called a scam

test('a real IRS notice is not called a scam', () => {
  const r = analyzeSignals([
    'Internal Revenue Service',
    'Notice CP14. Amount due: $1,247.18. Pay by April 15, 2026.',
    'Pay online at irs.gov/payments or call 800-829-1040 with questions.',
    'If you do not pay, you may be subject to penalties and interest.',
  ].join('\n'));
  assert.notEqual(r.verdict, 'scam');
  assert.ok(r.positives.length > 0, 'should notice the real irs.gov address and real phone number');
  assert.ok(!r.signals.some((s) => s.id === 'gov_mismatch'));
  assert.ok(!r.signals.some((s) => s.id === 'phone_mismatch'));
});

test('urgent tone alone is not enough to call something a scam', () => {
  const r = analyzeSignals('URGENT: Final notice. Your payment is due immediately. Please respond right away.');
  assert.notEqual(r.verdict, 'scam');
  assert.ok(r.score < 6, `tone-only score should stay low, got ${r.score}`);
});

test('a legitimate link in a letter claiming that company is not a mismatch', () => {
  const r = analyzeSignals('Chase: your statement is ready. View it at https://www.chase.com/statements');
  assert.notEqual(r.verdict, 'scam');
  assert.ok(!r.signals.some((s) => s.id === 'org_domain_mismatch'));
  assert.ok(!r.signals.some((s) => s.id === 'brand_subdomain'), 'chase.com must not be read as faking Chase');
});

test("a company's own domain is never reported as faking itself", () => {
  for (const url of ['https://www.google.com/account', 'https://icloud.com/find', 'https://usps.com/track']) {
    const r = analyzeSignals(`Please visit ${url} for details.`);
    const brandish = r.signals.filter((s) => ['lookalike_exact', 'lookalike_near', 'brand_subdomain'].includes(s.id));
    assert.deepEqual(brandish, [], `${url} wrongly flagged: ${JSON.stringify(brandish)}`);
  }
});

test('an unrelated domain in agency mail does not get reported as faking that domain', () => {
  // The IRS would not link to a Google form, so a mismatch is right. But the
  // finding must be about the IRS, not about google.com impersonating Google.
  const r = analyzeSignals('IRS: complete the form at https://docs.google.com/forms/d/e/abc/viewform');
  assert.ok(!r.signals.some((s) => s.id === 'brand_subdomain'));
  assert.ok(r.signals.some((s) => s.id === 'gov_mismatch' || s.id === 'open_host'));
});

// --------------------------------------------------- the never-say-real rule

test('never returns a "real" verdict, whatever the input', () => {
  const samples = [
    '', 'Hello, how are you?', 'Your package arrived.',
    'Chase: statement ready at chase.com',
    'IRS notice, pay at irs.gov, call 800-829-1040',
    'Buy a gift card now',
  ];
  for (const s of samples) {
    assert.notEqual(analyzeSignals(s).verdict, 'real', `"${s}" produced a real verdict`);
  }
});

test('nothing found is reported as ignorance, not safety', () => {
  const r = analyzeSignals('Hi Grandma, dinner is at six on Sunday. Love, Ana.');
  assert.equal(r.noScamSignsFound, true);
  assert.equal(r.verdict, 'careful');
  assert.equal(r.confidence, 'low', 'no signals must not read as high confidence');
  assert.match(toSchema(r).reasons[0], /does not mean it is real/i);
});

test('empty input does not throw', () => {
  for (const v of [undefined, null, '', '   ']) {
    assert.doesNotThrow(() => analyzeSignals(v));
  }
});

// ----------------------------------------------------------- helper behaviour

test('registrable reduces hosts correctly', () => {
  assert.equal(registrable('www.chase.com'), 'chase.com');
  assert.equal(registrable('login.secure.evil.co.uk'), 'evil.co.uk');
  assert.equal(registrable('irs.gov'), 'irs.gov');
  assert.equal(registrable('a.b.c.example.com'), 'example.com');
});

test('editDistance gives up past the cap', () => {
  assert.equal(editDistance('paypal', 'paypal'), 0);
  assert.equal(editDistance('paypal', 'paypai', 1), 1);
  assert.ok(editDistance('paypal', 'completelyother', 2) > 2);
});

test('deadlines are pulled out of ordinary wording', () => {
  assert.match(findDeadline('Pay by April 15, 2026 to avoid penalties.'), /April 15, 2026/);
  assert.match(findDeadline('You have 48 hours to pay.'), /48 hours/);
  assert.match(findDeadline('Respond within 10 business days.'), /within 10 business days/);
  assert.equal(findDeadline('No dates here at all.'), null);
});

test('kind labels follow the obvious cues', () => {
  // guessKind returns a stable key; the wording lives in the message table so
  // it can be said in any language.
  assert.equal(guessKind('Amount due: $42.10. Statement date: March 1.'), 'bill');
  assert.equal(guessKind('Short note about your package.'), 'text');
  assert.equal(guessKind('anything', 'voicemail transcript'), 'voicemail');
  assert.equal(guessKind('Dear Mr. Smith,\n\nlong body text here.\n\nSincerely,\nThe Office'), 'letter');
  assert.equal(analyzeSignals('Amount due: $42.10.').kindLabel, 'Bill');
  assert.equal(analyzeSignals('Amount due: $42.10.', { lang: 'es' }).kindLabel, 'una factura');
});

test('toSchema writes an honest headline and summary without a model', () => {
  // These used to be null, which rendered as a blank line and a missing card.
  const s = toSchema(analyzeSignals('Buy a gift card to settle your IRS debt.'));
  assert.ok(s.headline.length > 0);
  assert.ok(s.what_it_is.length > 0);
  assert.equal(s.verdict, 'scam');
  assert.ok(s.safe_step.length > 0);
  // Translating the letter genuinely needs a model, so this one stays null.
  assert.equal(s.full_translation, null);
});

test('the summary never claims to have understood the letter', () => {
  for (const text of ['Buy a gift card to settle your IRS debt.', 'Hi Grandma, dinner is at six.']) {
    const s = toSchema(analyzeSignals(text));
    assert.match(s.what_it_is, /did not read what it says/i);
  }
});

test('a clean check is not reported as proof the item is genuine', () => {
  const s = toSchema(analyzeSignals('Hi Grandma, dinner is at six on Sunday.'));
  assert.match(s.what_it_is, /does not mean it is real/i);
  assert.ok(!/looks real|is real\b|safe/i.test(s.headline), `headline overclaims: ${s.headline}`);
});

// ---------------------------------------- false positives found in real use

test('a genuine PayPal card-update email is not called a scam', () => {
  // Reported by a user. "card security code (CSC)" is the number printed on a
  // card, not a one-time code texted to you, and updating it on a company's own
  // site is routine. The old rule matched the bare phrase "security code" and
  // convicted on it alone.
  const r = analyzeSignals([
    'Update your expired card information for PayPal',
    'service@paypal.com',
    'Hello, Tristan Zhang',
    "We noticed your card ending in 5840 has expired. Please update your card's expiration date",
    'and card security code (CSC) as soon as possible so you can continue using it with PayPal.',
    'If you have already updated your PayPal account with your new card information, please disregard this email.',
  ].join('\n'));
  assert.notEqual(r.verdict, 'scam', `signals: ${r.signals.map((s) => s.id).join(', ')}`);
  assert.ok(!r.signals.some((s) => s.id === 'ask_otp'), 'a card security code is not a one-time code');
  assert.ok(r.positives.length > 0, "should notice the message really is from PayPal's domain");
});

test('asking you to send card details back is still caught', () => {
  // The fix above must not blunt the real version of this scam.
  for (const line of [
    'Reply with your card number and the security code on the back to restore access.',
    'Please confirm your CVV and routing number so we can release the refund.',
  ]) {
    assert.equal(analyzeSignals(line).verdict, 'scam', `missed: ${line}`);
  }
});

test('ordinary mentions of a card are not treated as a request for one', () => {
  for (const line of [
    'Questions about a charge? Call the number on the back of your debit card.',
    'Your card ending in 5840 was charged $24.10 on Sept 28.',
    'You can update your card details in your account settings.',
  ]) {
    const ids = analyzeSignals(line).signals.map((s) => s.id);
    assert.ok(!ids.includes('ask_card'), `wrongly flagged: ${line}`);
  }
});
