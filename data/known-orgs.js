// Organizations scammers impersonate most often, with the contact details that
// are actually theirs. Used to catch "claims to be X but points somewhere else".
//
// A .js module rather than .json so this loads unchanged in Node and in the
// browser, with no import-attribute or fs-path differences between them.
//
// Rules for editing this file:
//   - `aliases` are matched case-insensitively against the item's text.
//   - `domains` must be domains the organization really uses. A domain missing
//     here will make a genuine message look suspicious, so add rather than guess.
//   - `phones` are digits only, no formatting. LEAVE THE ARRAY EMPTY unless the
//     number is confirmed from the organization's own site. A wrong number here
//     tells a user that a real letter is fake, which is the costlier mistake.
//   - `gov: true` means the organization only ever uses a .gov domain.

export const ORGS = [
  // ---- Federal agencies: these never contact people from a .com ----
  { id: 'irs', name: 'Internal Revenue Service', gov: true,
    aliases: ['irs', 'internal revenue service'],
    domains: ['irs.gov'], phones: ['8008291040'] },
  { id: 'ssa', name: 'Social Security Administration', gov: true,
    aliases: ['social security administration', 'social security office', 'ssa'],
    domains: ['ssa.gov'], phones: ['8007721213'] },
  { id: 'medicare', name: 'Medicare', gov: true,
    aliases: ['medicare'],
    domains: ['medicare.gov'], phones: ['8006334227'] },
  { id: 'medicaid', name: 'Medicaid', gov: true,
    aliases: ['medicaid'],
    domains: ['medicaid.gov'], phones: [] },
  { id: 'usps', name: 'United States Postal Service',
    aliases: ['usps', 'postal service', 'post office'],
    domains: ['usps.com', 'usps.gov'], phones: ['8002758777'] },
  { id: 'ftc', name: 'Federal Trade Commission', gov: true,
    aliases: ['ftc', 'federal trade commission'],
    domains: ['ftc.gov', 'reportfraud.ftc.gov', 'consumer.ftc.gov'], phones: ['8773824357'] },
  { id: 'dmv', name: 'Department of Motor Vehicles', gov: true,
    aliases: ['dmv', 'department of motor vehicles', 'secretary of state'],
    domains: [], phones: [] },
  { id: 'uscis', name: 'U.S. Citizenship and Immigration Services', gov: true,
    aliases: ['uscis', 'immigration services', 'citizenship and immigration'],
    domains: ['uscis.gov'], phones: [] },
  { id: 'ssa_oig', name: 'Social Security Office of the Inspector General', gov: true,
    aliases: ['office of the inspector general', 'inspector general'],
    domains: ['oig.ssa.gov'], phones: [] },

  // ---- Banks and card issuers ----
  { id: 'chase', name: 'Chase', aliases: ['chase', 'jpmorgan chase'], domains: ['chase.com'], phones: [] },
  { id: 'bofa', name: 'Bank of America', aliases: ['bank of america', 'bofa'], domains: ['bankofamerica.com'], phones: [] },
  { id: 'wellsfargo', name: 'Wells Fargo', aliases: ['wells fargo'], domains: ['wellsfargo.com'], phones: [] },
  { id: 'citi', name: 'Citibank', aliases: ['citibank', 'citi'], domains: ['citi.com', 'citibank.com'], phones: [] },
  { id: 'capitalone', name: 'Capital One', aliases: ['capital one'], domains: ['capitalone.com'], phones: [] },
  { id: 'usbank', name: 'U.S. Bank', aliases: ['u.s. bank', 'us bank', 'usbank'], domains: ['usbank.com'], phones: [] },
  { id: 'pnc', name: 'PNC Bank', aliases: ['pnc'], domains: ['pnc.com'], phones: [] },
  { id: 'discover', name: 'Discover', aliases: ['discover card', 'discover'], domains: ['discover.com'], phones: [] },
  { id: 'amex', name: 'American Express', aliases: ['american express', 'amex'], domains: ['americanexpress.com', 'aexp.com'], phones: [] },
  { id: 'navyfederal', name: 'Navy Federal Credit Union', aliases: ['navy federal'], domains: ['navyfederal.org'], phones: [] },

  // ---- Payment apps: heavily impersonated ----
  { id: 'paypal', name: 'PayPal', aliases: ['paypal'], domains: ['paypal.com'], phones: [] },
  { id: 'venmo', name: 'Venmo', aliases: ['venmo'], domains: ['venmo.com'], phones: [] },
  { id: 'cashapp', name: 'Cash App', aliases: ['cash app', 'cashapp'], domains: ['cash.app', 'cash.me'], phones: [] },
  { id: 'zelle', name: 'Zelle', aliases: ['zelle'], domains: ['zellepay.com'], phones: [] },

  // ---- Big tech: "your account has been suspended" lures ----
  { id: 'apple', name: 'Apple', aliases: ['apple', 'icloud', 'apple id'], domains: ['apple.com', 'icloud.com'], phones: [] },
  { id: 'google', name: 'Google', aliases: ['google', 'gmail'], domains: ['google.com', 'gmail.com', 'accounts.google.com'], phones: [] },
  { id: 'microsoft', name: 'Microsoft', aliases: ['microsoft', 'outlook', 'windows support'], domains: ['microsoft.com', 'outlook.com', 'live.com'], phones: [] },
  { id: 'amazon', name: 'Amazon', aliases: ['amazon'], domains: ['amazon.com'], phones: [] },
  { id: 'netflix', name: 'Netflix', aliases: ['netflix'], domains: ['netflix.com'], phones: [] },
  { id: 'facebook', name: 'Facebook', aliases: ['facebook', 'meta'], domains: ['facebook.com', 'meta.com'], phones: [] },

  // ---- Parcel delivery: "redelivery fee" texts ----
  { id: 'ups', name: 'UPS', aliases: ['ups'], domains: ['ups.com'], phones: [] },
  { id: 'fedex', name: 'FedEx', aliases: ['fedex'], domains: ['fedex.com'], phones: [] },
  { id: 'dhl', name: 'DHL', aliases: ['dhl'], domains: ['dhl.com'], phones: [] },

  // ---- Local to Champaign-Urbana. Add your own utilities and clinics here. ----
  { id: 'uiuc', name: 'University of Illinois Urbana-Champaign',
    aliases: ['university of illinois', 'uiuc', 'u of i'],
    domains: ['illinois.edu', 'uillinois.edu'], phones: [] },
  { id: 'ameren', name: 'Ameren Illinois', aliases: ['ameren'], domains: ['ameren.com'], phones: [] },
  { id: 'nicor', name: 'Nicor Gas', aliases: ['nicor'], domains: ['nicorgas.com'], phones: [] },
  { id: 'comed', name: 'ComEd', aliases: ['comed'], domains: ['comed.com'], phones: [] },
];

// Registrable domains that are legitimate but commonly used to *host* a phishing
// page, so a link here is not evidence the sender is who they claim to be.
export const OPEN_HOSTS = new Set([
  'docs.google.com', 'forms.gle', 'sites.google.com', 'drive.google.com',
  'notion.site', 'weebly.com', 'wixsite.com', 'godaddysites.com',
  'firebaseapp.com', 'web.app', 'pages.dev', 'netlify.app', 'vercel.app',
  'blogspot.com', 'sharepoint.com', 'onedrive.live.com',
]);

// Link shorteners hide the real destination, so the reader cannot check it.
export const SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'buff.ly', 'is.gd',
  'rb.gy', 'cutt.ly', 'shorturl.at', 'rebrand.ly', 'tiny.cc', 'lnkd.in',
  't.ly', 'bl.ink', 'short.io', 'v.gd', 'qr.ae',
]);

// TLDs that are cheap, bulk-registered, and wildly over-represented in abuse
// data. Not proof of anything on its own, which is why it scores low.
export const RISKY_TLDS = new Set([
  'xyz', 'top', 'tk', 'ml', 'ga', 'cf', 'gq', 'buzz', 'click', 'link',
  'work', 'rest', 'country', 'kim', 'loan', 'men', 'date', 'racing',
  'win', 'bid', 'stream', 'download', 'zip', 'mov', 'cam', 'quest',
  'sbs', 'cfd', 'icu', 'live', 'shop', '店', 'autos', 'bond',
]);

// Multi-label public suffixes we need so that "foo.co.uk" reduces to "foo.co.uk"
// and not "co.uk". Far from the full Public Suffix List, but covers what shows
// up in US consumer mail.
export const MULTI_SUFFIXES = new Set([
  'co.uk', 'org.uk', 'ac.uk', 'gov.uk', 'co.jp', 'com.au', 'com.br',
  'com.mx', 'co.in', 'com.cn', 'co.kr', 'com.tr', 'co.za', 'com.sg',
]);
