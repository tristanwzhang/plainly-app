// Offline scam-signal detection. No network, no API key, no dependencies, so
// this runs instantly and keeps working when the wifi at the demo table dies.
//
// TWO MISTAKES TO AVOID, PULLING IN OPPOSITE DIRECTIONS.
//
// Calling a scam genuine costs someone money. But warning about everything is
// not the safe alternative: a tool that says "be careful" about every letter is
// one people stop reading, and then it protects nobody. This file used to never
// return a "real" verdict at all, which made every ordinary letter look
// suspicious and the warnings worthless.
//
// So: say plainly when nothing was found, and never dress that up as proof the
// item is genuine. The wording carries the caution — "no scam signs found", not
// "this is safe" — and `positives` records the cases where there really is
// confirming evidence, such as a link that matches the real organization.

import { ORGS, OPEN_HOSTS, SHORTENERS, RISKY_TLDS, MULTI_SUFFIXES } from '../data/known-orgs.js';
import { message, kindLabel } from '../data/signal-messages.js';

// A single CONCLUSIVE finding is enough to call something a scam. Tone-based
// findings score 1 on purpose: real government and utility mail is genuinely
// urgent and really does demand money, so weighting tone highly would flag
// legitimate mail and teach people to ignore the warnings that matter.
const CONCLUSIVE = 6;
const STRONG = 3;
const MODERATE = 2;
const TONE = 1;

const COMMON_TLDS = new Set([
  'com', 'net', 'org', 'gov', 'edu', 'mil', 'int', 'io', 'co', 'us', 'ca',
  'uk', 'de', 'fr', 'ru', 'cn', 'jp', 'br', 'in', 'mx', 'au', 'info', 'biz',
  'me', 'tv', 'cc', 'app', 'dev', 'site', 'online', 'store', 'pro', 'name',
  ...RISKY_TLDS,
]);

const URL_RE = /(?:https?:\/\/|www\.)[^\s<>"')\]}]+/gi;
const BARE_HOST_RE = /\b(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+([a-z]{2,24})\b(?:\/[^\s<>"')\]}]*)?/gi;
const EMAIL_RE = /\b[\w.+-]+@([a-z0-9][a-z0-9.-]*\.[a-z]{2,24})\b/gi;
const PHONE_RE = /(?:\+?1[\s.-]?)?\(?\b\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b/g;
const IPV4_HOST_RE = /^\d{1,3}(?:\.\d{1,3}){3}$/;

// ---------------------------------------------------------------- small helpers

/** Reduce a hostname to the part a registrar actually sells. */
export function registrable(host) {
  const h = String(host || '').toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  const parts = h.split('.');
  if (parts.length <= 2) return h;
  const lastTwo = parts.slice(-2).join('.');
  return MULTI_SUFFIXES.has(lastTwo) ? parts.slice(-3).join('.') : lastTwo;
}

function tldOf(host) {
  const parts = registrable(host).split('.');
  return parts[parts.length - 1] || '';
}

/** Strip the public suffix, leaving the brand-ish part we compare for lookalikes. */
function stem(host) {
  const r = registrable(host);
  const parts = r.split('.');
  const suffixLen = MULTI_SUFFIXES.has(parts.slice(-2).join('.')) ? 2 : 1;
  return parts.slice(0, Math.max(1, parts.length - suffixLen)).join('.');
}

/** Collapse the character swaps used to fake a brand: paypa1, g00gle, arnazon. */
function deconfuse(s) {
  return String(s)
    .replace(/0/g, 'o').replace(/1/g, 'l').replace(/3/g, 'e')
    .replace(/4/g, 'a').replace(/5/g, 's').replace(/7/g, 't')
    .replace(/\$/g, 's').replace(/vv/g, 'w').replace(/rn/g, 'm')
    .replace(/[^a-z]/g, '');
}

/** Levenshtein distance, abandoned once it exceeds `cap`. */
export function editDistance(a, b, cap = 3) {
  if (a === b) return 0;
  if (Math.abs(a.length - b.length) > cap) return cap + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let best = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(
        prev[j] + 1,
        cur[j - 1] + 1,
        prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1),
      );
      if (cur[j] < best) best = cur[j];
    }
    if (best > cap) return cap + 1;
    prev = cur;
  }
  return prev[b.length];
}

// ------------------------------------------------------------------- extraction

export function extractHosts(text) {
  const t = String(text || '');
  const hosts = new Set();
  const raw = [];

  for (const m of t.match(URL_RE) || []) {
    raw.push(m);
    const afterScheme = m.replace(/^https?:\/\//i, '');
    // Everything before the first /, ?, or # is the authority section.
    const authority = afterScheme.split(/[/?#]/)[0];
    // A "user@host" authority hides the real host behind a trusted-looking name.
    const host = authority.includes('@') ? authority.slice(authority.lastIndexOf('@') + 1) : authority;
    if (host) hosts.add(host.replace(/:\d+$/, '').toLowerCase());
  }

  // Bare domains ("paypa1.com/verify") only count when the suffix is a TLD we
  // recognise, so ordinary sentences like "etc.Please" are not read as links.
  // Email addresses are stripped first: the domain in "you@gmail.com" is a
  // mailbox, not somewhere this message is pointing you.
  for (const m of t.replace(EMAIL_RE, ' ').match(BARE_HOST_RE) || []) {
    const host = m.split(/[/?#]/)[0].replace(/[.,;:)]+$/, '').toLowerCase();
    if (COMMON_TLDS.has(tldOf(host))) hosts.add(host);
  }

  return { hosts: [...hosts], rawUrls: raw };
}

export function extractEmailDomains(text) {
  const out = new Set();
  for (const m of String(text || '').matchAll(EMAIL_RE)) out.add(m[1].toLowerCase());
  return [...out];
}

export function extractPhones(text) {
  const out = new Set();
  for (const m of String(text || '').match(PHONE_RE) || []) {
    const digits = m.replace(/\D/g, '').replace(/^1(?=\d{10}$)/, '');
    if (digits.length === 10) out.add(digits);
  }
  return [...out];
}

// Built once. Letters and digits may not sit next to an alias, so "IRS:" and
// "Internal Revenue Service," match but "first" does not contain "irs".
const ALIAS_RES = new WeakMap();
function aliasPatterns(org) {
  let res = ALIAS_RES.get(org);
  if (!res) {
    res = org.aliases.map((a) => new RegExp(`(?:^|[^a-z0-9])${a.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}(?:[^a-z0-9]|$)`, 'i'));
    ALIAS_RES.set(org, res);
  }
  return res;
}

/**
 * Which known organizations does this item claim to be from?
 *
 * Links and email addresses are removed first. A claim is something the prose
 * asserts ("Internal Revenue Service"), not something the link contains — and
 * reading brands out of URLs would let a scammer defeat the mismatch checks
 * below just by linking to a domain whose brand is in our list.
 */
export function claimedOrgs(text) {
  const prose = String(text || '').replace(URL_RE, ' ').replace(BARE_HOST_RE, ' ').replace(EMAIL_RE, ' ');
  return ORGS.filter((o) => aliasPatterns(o).some((re) => re.test(prose)));
}

// ------------------------------------------------------------------------ rules

const PHRASE_RULES = [
  // Payment methods that legitimate agencies, banks and utilities never demand.
  // Note the `s?` on every card: "three Google Play cards" is the usual wording
  // and a plural-blind pattern misses the most common version of this scam.
  { id: 'pay_gift_card', weight: CONCLUSIVE,
    re: /\b(gift\s?cards?|itunes\s?cards?|google\s?play\s?cards?|steam\s?cards?|apple\s?cards?|prepaid\s?cards?|vanilla\s?cards?)\b/i },
  { id: 'pay_crypto', weight: CONCLUSIVE,
    re: /\b(bitcoin|btc\b|ethereum|crypto(?:currency)?|usdt|wallet\s?address|coinbase)\b/i },
  { id: 'pay_wire', weight: CONCLUSIVE,
    re: /\b(wire\s?transfer|western\s?union|moneygram|money\s?gram)\b/i },
  { id: 'pay_p2p', weight: STRONG,
    re: /\b(zelle|venmo|cash\s?app|apple\s?pay)\b.{0,60}\b(pay|send|transfer|settle|clear)\b|\b(pay|send|transfer)\b.{0,40}\b(zelle|venmo|cash\s?app)\b/i },

  // Anything that hands an attacker direct account access.
  { id: 'ask_otp', weight: CONCLUSIVE,
    re: /\b(?:reply\s?with|send\s?(?:us|me)|tell\s?(?:us|me)|give\s?(?:us|me)|read\s?(?:us|me)|text\s?us|provide|confirm|verify\s?with|enter)\b[^.!?]{0,40}\b(?:one[-\s]?time\s?(?:code|password|pin)|otp\b|verification\s?code|2fa|authentication\s?code|passcode|code\s?we\s?(?:just\s?)?(?:sent|texted))\b/i },
  // "enter your online banking password" — words sit between "your" and
  // "password", so the two cannot be required to be adjacent. Note that
  // update/change/reset are deliberately absent: "change your password" is
  // advice a real bank gives, and convicting on it would be a bad miss.
  { id: 'ask_password', weight: CONCLUSIVE,
    re: /\b(?:enter|confirm|provide|send|reply\s?with|share|give|tell\s?us|verify)\b[^.!?]{0,40}\bpasswords?\b/i },
  { id: 'ask_ssn', weight: CONCLUSIVE,
    re: /\b(full\s)?(social\s?security\s?(?:number|#)|ssn)\b.{0,50}\b(confirm|verify|provide|send|reply|enter|need)\b|\b(confirm|verify|provide|send|reply|enter)\b.{0,40}\b(social\s?security\s?(?:number|#)|ssn)\b/i },
  { id: 'ask_digit_code', weight: STRONG,
    re: /\b\d\s?-?\s?digit\s?(?:code|pin|number)\b|\bcodes?\s?(?:we|they)\s?(?:just\s?)?(?:text|texted|send|sent)\b/i },
  // Conclusive only because a sharing verb is required: no real company asks
  // you to send a card number back to it. Merely mentioning a card number, or
  // asking you to update one on the company's own site, is ordinary.
  { id: 'ask_card', weight: CONCLUSIVE,
    re: /\b(?:send|reply\s?with|tell\s?us|give\s?us|share|confirm|provide|text\s?us|email\s?us)\b[^.!?]{0,40}\b(?:card\s?numbers?|cvv|csc\b|security\s?code|routing\s?number|account\s?and\s?routing)\b/i },
  // Scored STRONG rather than conclusive: "read the code" also appears in
  // innocent sentences, so this should not convict on its own.
  { id: 'ask_code_share', weight: STRONG,
    re: /(?<!\b(?:never|not|n[o']t|nobody|no\s?one)\s)\b(?:read|give|send|tell|text|repeat)\s(?:me|us)\b[^.!?]{0,25}\bcodes?\b/i },

  // Pressure tactics that are strong but not conclusive on their own.
  { id: 'secrecy', weight: STRONG,
    re: /\bdo\s?n[o']?t\s(?:tell|discuss|mention)\b[^.!?]{0,30}\b(?:anyone|anybody|family|mom|mum|mother|dad|father|wife|husband|son|daughter|kids|children|grandson|granddaughter|bank|police|teller|lawyer)\b|\bkeep\s?this\s?(?:confidential|between\s?us|a\s?secret|quiet)\b|\bdon'?t\s?let\s?anyone\s?know\b/i },
  { id: 'prize', weight: STRONG,
    re: /\b(you(?:'ve|\s?have)?\s?won|claim\s?your\s?(?:prize|reward|winnings)|lottery|sweepstakes|jackpot)\b/i },
  { id: 'press_number', weight: MODERATE,
    re: /\bpress\s?(?:one|two|1|2)\b/i },
  { id: 'threat', weight: MODERATE,
    re: /\b(?:arrest(?:ed)?|warrant|deport(?:ation|ed)?|lawsuit|legal\s?action|seize|suspend(?:ed)?\s?your\s?(?:benefits|account|license)|revoke|account\s?will\s?be\s?(?:closed|frozen|locked|terminated)|permanent(?:ly)?\s?(?:loss|lose)|loss\s?of\s?funds|lose\s?access)\b/i },
  { id: 'refund_bait', weight: MODERATE,
    re: /\b(refund\s?(?:is\s?)?(?:due|pending|waiting|available)|overpay(?:ment|ment\s?of)?|you\s?are\s?owed|eligible\s?for\s?a\s?refund)\b/i },

  // Tone only. Deliberately scored 1 — see the note at the top of the file.
  { id: 'urgency', weight: TONE,
    re: /\b(?:within\s?\d+\s?(?:hours?|minutes?|days?)|in\s?\d+\s?(?:hours?|minutes?)|immediately|right\s?away|final\s?notice|last\s?warning|act\s?now|expires?\s?(?:today|tonight)|before\s?midnight|urgent(?:ly)?)\b/i },
  { id: 'generic_greeting', weight: TONE,
    re: /\bdear\s?(?:customer|valued\s?customer|user|account\s?holder|sir\s?or\s?madam|madam\s?or\s?sir)\b/i },
];

/** Signals that come from links, email domains and phone numbers. */
function technicalSignals(text, orgs) {
  const found = [];
  const { hosts, rawUrls } = extractHosts(text);
  const emailDomains = extractEmailDomains(text);
  const phones = extractPhones(text);
  const allDomains = [...new Set([...hosts, ...emailDomains])];
  const regs = [...new Set(allDomains.map(registrable))];
  // Mismatch checks look at links only. An address in the body is usually the
  // reader's own, and "Apple ID: you@gmail.com" is not Apple linking to Gmail.
  const linkRegs = [...new Set(hosts.map(registrable))];

  // A message whose sender address really is at the organization's own domain
  // is almost certainly from them, and big companies routinely send mail that
  // links to tracking and marketing hosts rather than their main site. Without
  // this, every genuine Chase or PayPal email trips the brand checks below.
  //
  // A From address can be forged, and nothing here proves otherwise — real
  // proof is SPF and DKIM, which are not visible in pasted text. So this only
  // ever suppresses a weaker signal; it never clears a conclusive one.
  const senderDomains = extractEmailDomains(text).map(registrable);
  const senderIsOrg = (org) => org.domains.some((od) => senderDomains.some((d) => d === registrable(od)));

  const orgDomains = new Set(orgs.flatMap((o) => o.domains));
  const matchesClaimed = (d) => [...orgDomains].some((od) => d === od || d.endsWith(`.${od}`) || registrable(od) === registrable(d));
  // Whether a domain genuinely belongs to one specific organization. The brand
  // checks below must use this and not `matchesClaimed`: a link to google.com in
  // a letter claiming to be the IRS is a mismatch for the IRS, but it is still
  // Google's own domain and must not be reported as faking Google.
  const ownedBy = (org, d) => org.domains.some((od) => d === od || d.endsWith(`.${od}`));

  for (const host of allDomains) {
    const reg = registrable(host);

    if (host.includes('xn--')) {
      found.push({ id: 'punycode', weight: CONCLUSIVE, vars: { host } });
    }
    if (IPV4_HOST_RE.test(host)) {
      found.push({ id: 'ip_url', weight: CONCLUSIVE });
    }
    if (SHORTENERS.has(reg)) {
      found.push({ id: 'shortener', weight: MODERATE });
    }
    if (RISKY_TLDS.has(tldOf(host)) && !matchesClaimed(reg)) {
      found.push({ id: 'risky_tld', weight: MODERATE, vars: { tld: tldOf(host) } });
    }
    // Some OPEN_HOSTS entries are full hostnames (docs.google.com) and some are
    // registrable domains (notion.site), so both have to be checked.
    const openHost = OPEN_HOSTS.has(host) || OPEN_HOSTS.has(reg);
    if (openHost && orgs.length > 0 && !orgs.some(senderIsOrg)) {
      found.push({ id: 'open_host', weight: STRONG, vars: { org: orgs[0].name, host } });
    }

    // Lookalike of a brand we know, e.g. paypa1.com or arnazon-billing.com.
    {
      const mine = deconfuse(stem(reg));
      for (const org of ORGS) {
        if (ownedBy(org, reg)) continue;
        for (const od of org.domains) {
          const theirs = deconfuse(stem(od));
          if (!theirs || theirs.length < 4) continue;
          if (mine === theirs) {
            // Same name once character swaps are undone. If the raw spelling
            // matches too then only the ending differs, which a legitimate
            // country site would also do — suspicious, but not conclusive.
            found.push(stem(reg) === stem(od)
              ? { id: 'brand_other_tld', weight: STRONG, vars: { domain: reg, org: org.name, real: od } }
              : { id: 'lookalike_exact', weight: CONCLUSIVE, vars: { domain: reg, org: org.name, real: od } });
          } else if (theirs.length >= 5 && editDistance(mine, theirs, 1) <= 1) {
            found.push({ id: 'lookalike_near', weight: STRONG, vars: { domain: reg, org: org.name, real: od } });
          }
        }
      }
      // Brand name placed in front of someone else's domain, e.g.
      // amazon.account-verify.xyz. Skipped when the brand IS the registrable
      // name (paypa1.com), because the lookalike rules above already cover that
      // and the wording here would make no sense.
      for (const org of ORGS) {
        if (ownedBy(org, reg) || senderIsOrg(org)) continue;
        const brand = deconfuse(stem(org.domains[0] || ''));
        if (brand.length < 5 || deconfuse(stem(reg)) === brand) continue;
        if (deconfuse(host).includes(brand)) {
          found.push({
            id: 'brand_subdomain',
            weight: RISKY_TLDS.has(tldOf(host)) ? CONCLUSIVE : STRONG,
            vars: { host, org: org.name, domain: reg },
          });
          break;
        }
      }
    }
  }

  // Money asked for, and the link to pay it goes somewhere that is not the
  // sender's own domain. This is the shape of most payment fraud and needs no
  // list of known brands, which is why it catches senders we have never heard
  // of. A real landlord using a real payment vendor looks exactly like this
  // too — hence "be careful" rather than "scam". The reader should check
  // before sending money, which is the right advice either way.
  //
  // Requires an actual request ("pay your", "submit your payment"), not any
  // mention of money: a receipt saying a payment "was received" is not this.
  const asksForMoney = /\b(?:pay\s+(?:your|now|today|the|online|here|this)|make\s+a\s+payment|submit\s+(?:your\s+)?payment|complete\s+(?:your\s+)?payment|send\s+(?:your\s+)?payment|remit|amount\s+due|balance\s+due|first\s+(?:rent\s+)?installment)\b/i.test(text);
  if (asksForMoney && senderDomains.length) {
    const offsite = linkRegs.filter((d) => !senderDomains.includes(d) && !SHORTENERS.has(d));
    if (offsite.length) {
      found.push({ id: 'pay_offsite_link', weight: STRONG, vars: { domain: offsite[0], sender: senderDomains[0] } });
    }
  }

  // A link with "user@host" in the authority hides the real destination.
  if (rawUrls.some((u) => /^https?:\/\/[^/?#]*@/i.test(u))) {
    found.push({ id: 'at_in_url', weight: CONCLUSIVE });
  }

  // Claims to be an agency that only ever uses .gov, but links somewhere else.
  for (const org of orgs.filter((o) => o.gov)) {
    const offsite = linkRegs.filter((d) => !d.endsWith('.gov') && !matchesClaimed(d) && !SHORTENERS.has(d));
    if (offsite.length) {
      found.push({ id: 'gov_mismatch', weight: CONCLUSIVE, vars: { org: org.name, domain: offsite[0] } });
    }
  }

  // Claims a company we know, but every link belongs to someone else.
  for (const org of orgs.filter((o) => !o.gov && o.domains.length && !senderIsOrg(o))) {
    const theirs = linkRegs.filter((d) => org.domains.some((od) => d === od || d.endsWith(`.${od}`)));
    const others = linkRegs.filter((d) => !theirs.includes(d) && !SHORTENERS.has(d));
    if (linkRegs.length && !theirs.length && others.length) {
      found.push({ id: 'org_domain_mismatch', weight: MODERATE, vars: { org: org.name, domain: others[0], real: org.domains[0] } });
    }
  }

  // Claims an organization whose real number we know, and gives a different one.
  for (const org of orgs.filter((o) => o.phones.length)) {
    if (phones.length && !phones.some((p) => org.phones.includes(p))) {
      const real = org.phones[0].replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
      found.push({ id: 'phone_mismatch', weight: STRONG, vars: { org: org.name, phone: real } });
    }
  }

  const deduped = found.some((f) => f.id === 'brand_subdomain')
    ? found.filter((f) => f.id !== 'org_domain_mismatch')
    : found;
  return { found: deduped, hosts: allDomains, phones, registrables: regs };
}

/** Contact details that do match the claimed sender. Recorded, never scored. */
function positiveNotes(text, orgs) {
  const notes = [];
  const { hosts } = extractHosts(text);
  const regs = [...new Set([...hosts, ...extractEmailDomains(text)].map(registrable))];
  const phones = extractPhones(text);
  const senders = extractEmailDomains(text).map(registrable);
  // An organization whose own domain sent the mail counts even when the prose
  // never names it: "service@paypal.com" is the claim, in effect.
  const bySender = ORGS.filter((o) => o.domains.some((od) => senders.includes(registrable(od))));
  for (const org of [...new Set([...orgs, ...bySender])]) {
    if (org.domains.some((od) => senders.includes(registrable(od)))) notes.push({ id: 'ok_sender', vars: { org: org.name } });
    if (org.domains.some((od) => regs.includes(od))) notes.push({ id: 'ok_domain', vars: { org: org.name } });
    if (org.phones.some((p) => phones.includes(p))) notes.push({ id: 'ok_phone', vars: { org: org.name } });
  }
  return notes;
}

// -------------------------------------------------------------------- deadlines

const MONTHS = 'january|february|march|april|may|june|july|august|september|october|november|december|jan|feb|mar|apr|jun|jul|aug|sep|sept|oct|nov|dec';

export function findDeadline(text) {
  const t = String(text || '');
  const patterns = [
    new RegExp(`\\b(?:by|before|due|no later than|on or before)\\s+(?:${MONTHS})\\.?\\s+\\d{1,2}(?:,?\\s*\\d{4})?`, 'i'),
    new RegExp(`\\b(?:${MONTHS})\\.?\\s+\\d{1,2}(?:,?\\s*\\d{4})?`, 'i'),
    /\b(?:by|before|due|no later than)\s+\d{1,2}\/\d{1,2}(?:\/\d{2,4})?/i,
    /\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/,
    /\bwithin\s+\d+\s+(?:business\s+)?(?:hours?|days?|weeks?)/i,
    /\b\d+\s+(?:hours?|days?)\s+to\s+(?:pay|respond|reply|act|call)/i,
    /\b(?:by|before)\s+(?:today|tonight|tomorrow|monday|tuesday|wednesday|thursday|friday|saturday|sunday)\b/i,
  ];
  for (const re of patterns) {
    const m = t.match(re);
    if (m) return m[0].replace(/\s+/g, ' ').trim();
  }
  return null;
}

// ------------------------------------------------------------------ kind labels

export function guessKind(text, hint) {
  if (hint) {
    const h = hint.toLowerCase();
    if (h.includes('voicemail')) return 'voicemail';
    if (h.includes('text')) return 'text';
    if (h.includes('email')) return 'email';
    if (h.includes('letter')) return 'letter';
    if (h.includes('bill')) return 'bill';
  }
  const t = String(text || '');
  if (/^\s*(?:from|to|subject|sent):/im.test(t) || /\b[\w.+-]+@[a-z0-9][a-z0-9.-]*\.[a-z]{2,24}\b/i.test(t)) return 'email';
  if (/\bpress\s?(?:one|1)\b|\bthis\s(?:is|message)\b.{0,40}\bcall(?:ing)?\s?back\b/i.test(t)) return 'voicemail';
  if (/\b(amount\s?due|balance\s?due|total\s?due|statement\s?(?:date|period)|invoice|account\s?summary)\b/i.test(t)) return 'bill';
  if (/\bdear\b/i.test(t) && /\b(sincerely|regards|yours\s?truly)\b/i.test(t)) return 'letter';
  if (t.length < 320) return 'text';
  return 'letter';
}

// ------------------------------------------------------------------- main entry

/**
 * Score an item for scam signals, using no network and no model.
 *
 * Returns `verdict` in the same vocabulary as the model path ('scam' |
 * 'careful'), but never 'real' — see the note at the top of this file.
 */
export function analyzeSignals(text = '', { hint = '', lang = 'en' } = {}) {
  const t = String(text || '');
  const orgs = claimedOrgs(t);

  const signals = [];
  for (const rule of PHRASE_RULES) {
    if (rule.re.test(t)) signals.push({ id: rule.id, weight: rule.weight, why: rule.why });
  }

  const tech = technicalSignals(t, orgs);
  signals.push(...tech.found);

  // One finding per id, keeping the highest-weighted wording for each.
  const byId = new Map();
  for (const s of signals.sort((a, b) => b.weight - a.weight)) {
    if (!byId.has(s.id)) byId.set(s.id, s);
  }
  // Wording is attached last, from the message table, so the rules above stay
  // language-neutral and the same finding can be said in any language.
  const unique = [...byId.values()].map((s) => ({ ...s, why: message(lang, s.id, s.vars) }));
  const score = unique.reduce((n, s) => n + s.weight, 0);

  // Tone-only findings (urgency, a missing name) do not make something
  // suspicious: real agency and bank mail is urgent and often unaddressed. They
  // are still listed, but they no longer colour the whole verdict.
  const heaviest = unique.reduce((m, s) => Math.max(m, s.weight), 0);
  const risk = score >= CONCLUSIVE ? 'high'
    : score >= STRONG && heaviest >= MODERATE ? 'medium'
    : unique.length ? 'low'
    : 'none';

  return {
    risk,
    score,
    // 'real' here means "nothing we check for turned up", not "verified
    // genuine". The wording the UI shows must say so.
    verdict: risk === 'high' ? 'scam' : risk === 'medium' ? 'careful' : 'real',
    // Confirming evidence — a link or number that really is the organization's
    // — is the one thing that earns more than low confidence in a clean result.
    confidence: risk === 'high' ? 'high'
      : risk === 'medium' ? 'medium'
      : positiveNotes(t, orgs).length ? 'medium' : 'low',
    noScamSignsFound: unique.length === 0,
    signals: unique,
    reasons: unique.slice(0, 4).map((s) => s.why),
    positives: positiveNotes(t, orgs).map((n) => message(lang, n.id, n.vars)),
    deadline: findDeadline(t),
    actionNeeded: risk === 'high' || risk === 'medium' || Boolean(findDeadline(t)),
    lang,
    kindKey: guessKind(t, hint),
    kindLabel: kindLabel(lang, guessKind(t, hint)),
    claimed: orgs.map((o) => o.name),
    hosts: tech.hosts,
    phones: tech.phones,
  };
}

const SEVERITY = { real: 0, careful: 1, scam: 2 };

/**
 * Combine the model's reading with the offline rules.
 *
 * The rules may only ever make a verdict more cautious, never less: a model
 * should not be able to talk us out of a gift-card demand. They escalate only
 * when something actually fired (medium or high risk), so a clean run leaves
 * the model's own judgment — including "real" — untouched.
 *
 * `rules` is null when the rules could not run at all, which happens for photo
 * input because the images are not read as text. In that case nothing here may
 * claim an offline check was done.
 */
export function mergeResults(model, rules, { english = true } = {}) {
  // `english` is kept for callers that still pass it, but rule reasons are now
  // written in the reader's own language, so they are merged in either way.
  if (!rules) return { ...model, signals: [], checks_out: [], checked_offline: false };

  const ruleShape = toSchema(rules);
  const base = model || ruleShape;
  const extras = {
    signals: rules.signals.map((s) => ({ id: s.id, why: s.why })),
    checks_out: rules.positives,
    checked_offline: true,
  };

  if (!model) {
    // No model reply: rules are all we have, so use their wording whatever the
    // reader's language. English reasons beat an empty "why" card.
    return { ...ruleShape, ...extras };
  }

  const escalates = rules.risk === 'high' || rules.risk === 'medium';
  const verdict = escalates && SEVERITY[rules.verdict] > SEVERITY[base.verdict ?? 'careful']
    ? rules.verdict
    : base.verdict;

  // Rule findings come first: they name a specific, checkable fact.
  const modelReasons = Array.isArray(base.reasons) ? base.reasons.map(String) : [];
  const reasons = [...new Set([...rules.reasons, ...modelReasons])].slice(0, 4);

  return {
    ...base,
    ...extras,
    verdict,
    reasons,
    // A conclusive structural finding is firmer than a model's impression.
    confidence: rules.risk === 'high' ? 'high' : base.confidence,
    deadline: base.deadline || rules.deadline,
    action_needed: Boolean(base.action_needed || rules.actionNeeded),
  };
}

/**
 * Shape the result into the fields the UI already renders, filling only what
 * rules can honestly answer. `headline`, `what_it_is` and `full_translation`
 * are left null because they need a model to read the letter.
 */
export function toSchema(result) {
  const r = result;
  const lang = r.lang || 'en';
  const say = (id, vars) => message(lang, id, vars);

  // Without a model there is no one to read the letter, so these fields used to
  // come back null and the page showed a blank line and no "what this is" card
  // at all — which reads as broken rather than as a feature that is switched
  // off. What the rules can honestly say is what they checked and what they
  // found, never what the letter means.
  const n = r.signals.length;
  const headline = r.risk === 'none' ? say('head_none')
    : r.risk === 'low' ? say('head_minor')
    : say(n === 1 ? 'head_one' : 'head_many');
  const whatItIs = say('what_kind', { kind: r.kindLabel })
    + (r.claimed.length ? say('what_from', { org: r.claimed[0] }) : '')
    + say(n === 0 ? 'what_none' : n === 1 ? 'what_one' : 'what_many', { n })
    + say('what_tail');

  return {
    readable: true,
    kind_label: r.kindLabel,
    verdict: r.verdict,
    headline,
    what_it_is: whatItIs,
    action_needed: r.actionNeeded,
    action_summary: say(r.risk === 'high' ? 'action_scam' : 'action_careful'),
    deadline: r.deadline,
    reasons: r.noScamSignsFound ? [say('reason_none')] : r.reasons,
    safe_step: r.claimed.length ? say('safe_org', { org: r.claimed[0] }) : say('safe_generic'),
    family_message: say('family'),
    confidence: r.confidence,
    full_translation: null,
  };
}
