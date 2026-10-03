// Offline scam-signal detection. No network, no API key, no dependencies, so
// this runs instantly and keeps working when the wifi at the demo table dies.
//
// THE ONE RULE THAT SHAPES THIS WHOLE FILE: these checks can only ever raise
// suspicion. A message with no signals is not thereby genuine — a careful scam
// on a clean domain passes every rule below. So this module never returns a
// "real" verdict, and callers must not render "nothing found" as "this is safe".
// Telling someone their letter is legitimate when it is not is the one mistake
// here that costs a person money.

import { ORGS, OPEN_HOSTS, SHORTENERS, RISKY_TLDS, MULTI_SUFFIXES } from '../data/known-orgs.js';

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
  for (const m of t.match(BARE_HOST_RE) || []) {
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
  { id: 'pay_gift_card', weight: CONCLUSIVE, why: 'Asks for payment by gift card. No real agency or company does this.',
    re: /\b(gift\s?cards?|itunes\s?cards?|google\s?play\s?cards?|steam\s?cards?|apple\s?cards?|prepaid\s?cards?|vanilla\s?cards?)\b/i },
  { id: 'pay_crypto', weight: CONCLUSIVE, why: 'Asks for payment in cryptocurrency.',
    re: /\b(bitcoin|btc\b|ethereum|crypto(?:currency)?|usdt|wallet\s?address|coinbase)\b/i },
  { id: 'pay_wire', weight: CONCLUSIVE, why: 'Asks for a wire transfer or money transfer service.',
    re: /\b(wire\s?transfer|western\s?union|moneygram|money\s?gram)\b/i },
  { id: 'pay_p2p', weight: STRONG, why: 'Asks to be paid through a person-to-person app.',
    re: /\b(zelle|venmo|cash\s?app|apple\s?pay)\b.{0,60}\b(pay|send|transfer|settle|clear)\b|\b(pay|send|transfer)\b.{0,40}\b(zelle|venmo|cash\s?app)\b/i },

  // Anything that hands an attacker direct account access.
  { id: 'ask_otp', weight: CONCLUSIVE, why: 'Asks for a one-time code. Real companies never ask you to share one.',
    re: /\b(one[-\s]?time\s?(?:code|password|pin)|otp\b|verification\s?code|security\s?code|2fa|authentication\s?code)\b/i },
  // "enter your online banking password" — words sit between "your" and
  // "password", so the two cannot be required to be adjacent. Note that
  // update/change/reset are deliberately absent: "change your password" is
  // advice a real bank gives, and convicting on it would be a bad miss.
  { id: 'ask_password', weight: CONCLUSIVE, why: 'Asks for your password. No real company asks you to send one.',
    re: /\b(?:enter|confirm|provide|send|reply\s?with|share|give|tell\s?us|verify)\b[^.!?]{0,40}\bpasswords?\b/i },
  { id: 'ask_ssn', weight: CONCLUSIVE, why: 'Asks for your full Social Security number.',
    re: /\b(full\s)?(social\s?security\s?(?:number|#)|ssn)\b.{0,50}\b(confirm|verify|provide|send|reply|enter|need)\b|\b(confirm|verify|provide|send|reply|enter)\b.{0,40}\b(social\s?security\s?(?:number|#)|ssn)\b/i },
  { id: 'ask_digit_code', weight: STRONG, why: 'Asks for a numbered code that was sent to you. Real companies never ask you to pass one on.',
    re: /\b\d\s?-?\s?digit\s?(?:code|pin|number)\b|\bcodes?\s?(?:we|they)\s?(?:just\s?)?(?:text|texted|send|sent)\b/i },
  { id: 'ask_card', weight: STRONG, why: 'Asks for full card or bank account numbers.',
    re: /\b(card\s?numbers?|cvv|security\s?code\s?on\s?the\s?back|routing\s?number|account\s?and\s?routing)\b/i },
  // Scored STRONG rather than conclusive: "read the code" also appears in
  // innocent sentences, so this should not convict on its own.
  { id: 'ask_code_share', weight: STRONG, why: 'Asks you to read out or send a code.',
    re: /\b(read|give|send|tell|share|text|repeat)\b[^.!?]{0,25}\b(?:the\s|me\s|us\s)?codes?\b/i },

  // Pressure tactics that are strong but not conclusive on their own.
  { id: 'secrecy', weight: STRONG, why: 'Tells you to keep it secret. Real organizations never do.',
    re: /\b(do\s?n[o']?t\s(?:tell|discuss|share|mention)|keep\s?this\s?(?:confidential|between|secret|quiet)|don'?t\s?let\s?anyone)\b/i },
  { id: 'prize', weight: STRONG, why: 'Says you won a prize or lottery you did not enter.',
    re: /\b(you(?:'ve|\s?have)?\s?won|claim\s?your\s?(?:prize|reward|winnings)|lottery|sweepstakes|jackpot)\b/i },
  { id: 'press_number', weight: MODERATE, why: 'Tells you to press a number to be connected.',
    re: /\bpress\s?(?:one|two|1|2)\b/i },
  { id: 'threat', weight: MODERATE, why: 'Threatens arrest, legal action, or losing your benefits.',
    re: /\b(?:arrest(?:ed)?|warrant|deport(?:ation|ed)?|lawsuit|legal\s?action|seize|suspend(?:ed)?\s?your\s?(?:benefits|account|license)|revoke|account\s?will\s?be\s?(?:closed|frozen|locked|terminated)|permanent(?:ly)?\s?(?:loss|lose)|loss\s?of\s?funds|lose\s?access)\b/i },
  { id: 'refund_bait', weight: MODERATE, why: 'Offers a refund or says you were overpaid.',
    re: /\b(refund\s?(?:is\s?)?(?:due|pending|waiting|available)|overpay(?:ment|ment\s?of)?|you\s?are\s?owed|eligible\s?for\s?a\s?refund)\b/i },

  // Tone only. Deliberately scored 1 — see the note at the top of the file.
  { id: 'urgency', weight: TONE, why: 'Pushes you to act within a very short time.',
    re: /\b(?:within\s?\d+\s?(?:hours?|minutes?|days?)|in\s?\d+\s?(?:hours?|minutes?)|immediately|right\s?away|final\s?notice|last\s?warning|act\s?now|expires?\s?(?:today|tonight)|before\s?midnight|urgent(?:ly)?)\b/i },
  { id: 'generic_greeting', weight: TONE, why: 'Does not use your name.',
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
      found.push({ id: 'punycode', weight: CONCLUSIVE, why: `The web address "${host}" uses hidden characters to look like a real one.` });
    }
    if (IPV4_HOST_RE.test(host)) {
      found.push({ id: 'ip_url', weight: CONCLUSIVE, why: 'A link points at a bare numeric address instead of a company name.' });
    }
    if (SHORTENERS.has(reg)) {
      found.push({ id: 'shortener', weight: MODERATE, why: 'Uses a shortened link, so you cannot see where it really goes.' });
    }
    if (RISKY_TLDS.has(tldOf(host)) && !matchesClaimed(reg)) {
      found.push({ id: 'risky_tld', weight: MODERATE, why: `The web address ends in ".${tldOf(host)}", which real companies rarely use.` });
    }
    // Some OPEN_HOSTS entries are full hostnames (docs.google.com) and some are
    // registrable domains (notion.site), so both have to be checked.
    const openHost = OPEN_HOSTS.has(host) || OPEN_HOSTS.has(reg);
    if (openHost && orgs.length > 0) {
      found.push({ id: 'open_host', weight: STRONG, why: `${orgs[0].name} would not ask you to use a page hosted on ${host}.` });
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
              ? { id: 'brand_other_tld', weight: STRONG, why: `"${reg}" uses ${org.name}'s name but is not their usual address, ${od}.` }
              : { id: 'lookalike_exact', weight: CONCLUSIVE, why: `"${reg}" is spelled to look like ${org.name}'s real address, ${od}.` });
          } else if (theirs.length >= 5 && editDistance(mine, theirs, 1) <= 1) {
            found.push({ id: 'lookalike_near', weight: STRONG, why: `"${reg}" is one character away from ${org.name}'s real address, ${od}.` });
          }
        }
      }
      // Brand name placed in front of someone else's domain, e.g.
      // amazon.account-verify.xyz. Skipped when the brand IS the registrable
      // name (paypa1.com), because the lookalike rules above already cover that
      // and the wording here would make no sense.
      for (const org of ORGS) {
        if (ownedBy(org, reg)) continue;
        const brand = deconfuse(stem(org.domains[0] || ''));
        if (brand.length < 5 || deconfuse(stem(reg)) === brand) continue;
        if (deconfuse(host).includes(brand)) {
          found.push({ id: 'brand_subdomain', weight: STRONG, why: `"${host}" puts ${org.name}'s name in front of an unrelated address, ${reg}.` });
          break;
        }
      }
    }
  }

  // A link with "user@host" in the authority hides the real destination.
  if (rawUrls.some((u) => /^https?:\/\/[^/?#]*@/i.test(u))) {
    found.push({ id: 'at_in_url', weight: CONCLUSIVE, why: 'A link is built to show one address but open a different one.' });
  }

  // Claims to be an agency that only ever uses .gov, but links somewhere else.
  for (const org of orgs.filter((o) => o.gov)) {
    const offsite = regs.filter((d) => !d.endsWith('.gov') && !matchesClaimed(d) && !SHORTENERS.has(d));
    if (offsite.length) {
      found.push({ id: 'gov_mismatch', weight: CONCLUSIVE, why: `Says it is from ${org.name}, but the link goes to ${offsite[0]} instead of a .gov address.` });
    }
  }

  // Claims a company we know, but every link belongs to someone else.
  for (const org of orgs.filter((o) => !o.gov && o.domains.length)) {
    const theirs = regs.filter((d) => org.domains.some((od) => d === od || d.endsWith(`.${od}`)));
    const others = regs.filter((d) => !theirs.includes(d) && !SHORTENERS.has(d));
    if (regs.length && !theirs.length && others.length) {
      found.push({ id: 'org_domain_mismatch', weight: STRONG, why: `Says it is from ${org.name}, but the link goes to ${others[0]}, not ${org.domains[0]}.` });
    }
  }

  // Claims an organization whose real number we know, and gives a different one.
  for (const org of orgs.filter((o) => o.phones.length)) {
    if (phones.length && !phones.some((p) => org.phones.includes(p))) {
      const real = org.phones[0].replace(/(\d{3})(\d{3})(\d{4})/, '$1-$2-$3');
      found.push({ id: 'phone_mismatch', weight: STRONG, why: `Says it is from ${org.name}, but the number given is not theirs. ${org.name}'s real number is ${real}.` });
    }
  }

  return { found, hosts: allDomains, phones, registrables: regs };
}

/** Contact details that do match the claimed sender. Recorded, never scored. */
function positiveNotes(text, orgs) {
  const notes = [];
  const { hosts } = extractHosts(text);
  const regs = [...new Set([...hosts, ...extractEmailDomains(text)].map(registrable))];
  const phones = extractPhones(text);
  for (const org of orgs) {
    if (org.domains.some((od) => regs.includes(od))) notes.push(`The link matches ${org.name}'s real web address.`);
    if (org.phones.some((p) => phones.includes(p))) notes.push(`The phone number is ${org.name}'s real number.`);
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
    if (h.includes('voicemail')) return 'Voicemail';
    if (h.includes('text')) return 'Text message';
    if (h.includes('email')) return 'Email';
    if (h.includes('letter')) return 'Letter';
    if (h.includes('bill')) return 'Bill';
  }
  const t = String(text || '');
  if (/^\s*(?:from|to|subject|sent):/im.test(t) || EMAIL_RE.test(t)) return 'Email';
  if (/\bpress\s?(?:one|1)\b|\bthis\s(?:is|message)\b.{0,40}\bcall(?:ing)?\s?back\b/i.test(t)) return 'Voicemail';
  if (/\b(amount\s?due|balance\s?due|total\s?due|statement\s?(?:date|period)|invoice|account\s?summary)\b/i.test(t)) return 'Bill';
  if (/\bdear\b/i.test(t) && /\b(sincerely|regards|yours\s?truly)\b/i.test(t)) return 'Letter';
  if (t.length < 320) return 'Text message';
  return 'Letter';
}

// ------------------------------------------------------------------- main entry

/**
 * Score an item for scam signals, using no network and no model.
 *
 * Returns `verdict` in the same vocabulary as the model path ('scam' |
 * 'careful'), but never 'real' — see the note at the top of this file.
 */
export function analyzeSignals(text = '', { hint = '' } = {}) {
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
  const unique = [...byId.values()];
  const score = unique.reduce((n, s) => n + s.weight, 0);

  const risk = score >= CONCLUSIVE ? 'high' : score >= STRONG ? 'medium' : score >= 1 ? 'low' : 'none';

  return {
    risk,
    score,
    // 'careful' for everything short of high risk. This function never says 'real'.
    verdict: risk === 'high' ? 'scam' : 'careful',
    // Low confidence when nothing fired: that is ignorance, not reassurance.
    confidence: risk === 'high' ? 'high' : risk === 'medium' ? 'medium' : 'low',
    noScamSignsFound: unique.length === 0,
    signals: unique,
    reasons: unique.slice(0, 4).map((s) => s.why),
    positives: positiveNotes(t, orgs),
    deadline: findDeadline(t),
    actionNeeded: risk === 'high' || risk === 'medium' || Boolean(findDeadline(t)),
    kindLabel: guessKind(t, hint),
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

  // Rule reasons are generated in English. Only merge them in for English
  // readers; otherwise the model's reasons, which are written in the reader's
  // language, stand on their own.
  const modelReasons = Array.isArray(base.reasons) ? base.reasons.map(String) : [];
  const reasons = english
    ? [...new Set([...rules.reasons, ...modelReasons])].slice(0, 4)
    : modelReasons.slice(0, 4);

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
  const safeStep = r.claimed.length
    ? `Do not use the phone number or link in this message. Look up ${r.claimed[0]} yourself, or call the number on a bill or card you already have.`
    : 'Do not use the phone number or link in this message. Call the number on a bill, card, or statement you already have, or ask someone you trust.';

  return {
    readable: true,
    kind_label: r.kindLabel,
    verdict: r.verdict,
    headline: null,
    what_it_is: null,
    action_needed: r.actionNeeded,
    action_summary: r.risk === 'high'
      ? 'Do not pay, call, or click anything in this message.'
      : 'Check this with someone you trust before you do anything.',
    deadline: r.deadline,
    reasons: r.noScamSignsFound
      ? ['We did not find any known scam signs. That does not mean it is real.']
      : r.reasons,
    safe_step: safeStep,
    family_message: 'Hi, I got this and I am not sure it is real. Can you look at it with me before I do anything?',
    confidence: r.confidence,
    full_translation: null,
  };
}
