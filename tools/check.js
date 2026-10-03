#!/usr/bin/env node
// Run the offline scam checks against text, with no API key and no network.
//
//   npm run check -- "Your package is held. Pay at https://usps-fee.xyz/pay"
//   pbpaste | npm run check
//   npm run check -- --examples

import { analyzeSignals } from '../lib/signals.js';

const EXAMPLES = [
  ['Parcel fee text', 'USPS: your package is on hold due to an unpaid fee of $2.80. Pay now at https://usps-redelivery.top/fee or it will be returned.'],
  ['IRS impersonation', 'Internal Revenue Service FINAL NOTICE: you owe $4,312. Pay within 24 hours at irs-settlement-portal.com to avoid a warrant for your arrest.'],
  ['Grandparent scam', 'Grandma it is me, I am in jail and need bail money. Please do not tell mom. Buy three $500 Google Play cards and read me the codes.'],
  ['PayPal lookalike', 'Your PayPal account has been limited. Confirm your identity at http://paypa1.com/resolve within 48 hours.'],
  ['Real IRS notice', 'Internal Revenue Service\nNotice CP14. Amount due: $1,247.18. Pay by April 15, 2026.\nPay online at irs.gov/payments or call 800-829-1040.'],
  ['Ordinary message', 'Hi Grandma, dinner is at six on Sunday. Love, Ana.'],
];

const BAR = { high: '\x1b[41m\x1b[97m', medium: '\x1b[43m\x1b[30m', low: '\x1b[46m\x1b[30m', none: '\x1b[47m\x1b[30m' };
const RESET = '\x1b[0m';
const DIM = '\x1b[2m';

function show(label, text) {
  const r = analyzeSignals(text);
  const tag = { high: ' LIKELY SCAM ', medium: ' BE CAREFUL ', low: ' BE CAREFUL ', none: ' NO SIGNS FOUND ' }[r.risk];

  if (label) console.log(`\n${DIM}${'─'.repeat(72)}${RESET}\n${label}`);
  console.log(`${DIM}${text.replace(/\n/g, ' ').slice(0, 150)}${text.length > 150 ? '…' : ''}${RESET}\n`);
  console.log(`${BAR[r.risk]}${tag}${RESET}  ${r.kindLabel}  ${DIM}score ${r.score} · confidence ${r.confidence}${RESET}`);

  if (r.claimed.length) console.log(`\n  Says it is from: ${r.claimed.join(', ')}`);
  if (r.deadline) console.log(`  Deadline given:  ${r.deadline}`);

  if (r.signals.length) {
    console.log('\n  Why:');
    for (const s of r.signals) console.log(`    • ${s.why} ${DIM}[${s.id} +${s.weight}]${RESET}`);
  } else {
    console.log(`\n  ${DIM}No known scam signs. This does NOT mean it is genuine.${RESET}`);
  }
  if (r.positives.length) {
    console.log('\n  Checks out:');
    for (const p of r.positives) console.log(`    • ${p}`);
  }
  console.log();
}

const args = process.argv.slice(2);

if (args[0] === '--examples') {
  for (const [label, text] of EXAMPLES) show(label, text);
} else if (args.length) {
  show('', args.join(' '));
} else if (!process.stdin.isTTY) {
  let buf = '';
  process.stdin.setEncoding('utf8');
  for await (const chunk of process.stdin) buf += chunk;
  show('', buf.trim());
} else {
  console.log('Usage:\n  npm run check -- "text to check"\n  npm run check -- --examples\n  pbpaste | npm run check');
  process.exit(1);
}
