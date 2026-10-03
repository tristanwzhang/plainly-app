import { getClient, MODEL, parseJson, rateLimited, safeLang } from '../lib/claude.js';
import { buildPrompt } from '../lib/prompt.js';
import { analyzeSignals, mergeResults } from '../lib/signals.js';

const MEDIA = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const MAX_IMAGES = 3;
const MAX_B64 = 3_000_000; // about 2.2 MB of image per photo
const MAX_TEXT = 20_000;

// Stand-in wording for the two fields only a model can write. Chosen to match
// whatever the offline rules concluded, so mock mode never contradicts itself.
const MOCK_TEXT = {
  scam: {
    headline: 'This looks like a scam',
    what_it_is: 'A message with clear warning signs. (Mock mode: no model was called, so this sentence is canned.)',
  },
  careful: {
    headline: 'Check this before you do anything',
    what_it_is: 'Mock mode: no model was called, so this sentence is canned. The warning signs below are real.',
  },
};

const MOCK_IMAGE_ONLY = {
  readable: true, kind_label: 'Text message', verdict: 'scam', headline: 'This looks like a scam',
  what_it_is: 'A message that says you owe a small fee.', action_needed: false,
  action_summary: 'Do not click the link or pay.', deadline: null,
  reasons: ['It rushes you with a short deadline.', 'It asks you to pay through a link.'],
  safe_step: 'Check on your package using the official website you already know.',
  family_message: 'Hi, I got this text and I am not sure it is real. Can you look at it with me?',
  family_message_en: 'Hi, I got this text and I am not sure it is real. Can you look at it with me?',
  confidence: 'high', full_translation: 'Mock translation of the full message.',
};

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
  if (rateLimited(req)) return res.status(429).json({ error: 'rate_limited' });

  const body = req.body || {};
  const lang = safeLang(body.lang);
  const text = typeof body.text === 'string' ? body.text.slice(0, MAX_TEXT) : '';
  const hint = typeof body.hint === 'string' ? body.hint.slice(0, 80) : '';
  const images = Array.isArray(body.images) ? body.images.slice(0, MAX_IMAGES) : [];

  for (const im of images) {
    if (!im || !MEDIA.has(im.media_type) || typeof im.data !== 'string' || im.data.length > MAX_B64) {
      return res.status(400).json({ error: 'bad_image' });
    }
  }
  if (!text.trim() && images.length === 0) return res.status(400).json({ error: 'empty' });

  // Offline rules first: no network, no key, no cost. They only run on text —
  // photos are not read as characters, so there is nothing to match against and
  // we must not imply an offline check happened.
  const rules = text.trim() ? analyzeSignals(text, { hint }) : null;
  const english = lang.code === 'en';

  if (process.env.MOCK === '1') {
    if (!rules) return res.status(200).json(MOCK_IMAGE_ONLY);
    const merged = mergeResults(null, rules, { english });
    return res.status(200).json({ ...merged, ...MOCK_TEXT[merged.verdict === 'scam' ? 'scam' : 'careful'] });
  }

  // No key configured: still answer with what the rules found rather than
  // failing. Half an answer beats an error message in front of a user.
  if (!process.env.ANTHROPIC_API_KEY) {
    if (!rules) return res.status(503).json({ error: 'no_key_images' });
    return res.status(200).json({ ...mergeResults(null, rules, { english }), degraded: 'no_key' });
  }

  try {
    const content = images.map((im) => ({
      type: 'image',
      source: { type: 'base64', media_type: im.media_type, data: im.data },
    }));
    content.push({ type: 'text', text: buildPrompt({ text, hasImages: images.length > 0, hint }, lang) });

    const msg = await getClient().messages.create({
      model: MODEL,
      max_tokens: 2000,
      messages: [{ role: 'user', content }],
    });
    const out = msg.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
    const data = parseJson(out);
    if (!data) {
      // The model replied with something unparseable. Rules alone still beat 502.
      if (rules) return res.status(200).json({ ...mergeResults(null, rules, { english }), degraded: 'bad_model_json' });
      return res.status(502).json({ error: 'invalid_json' });
    }
    return res.status(200).json(mergeResults(data, rules, { english }));
  } catch (e) {
    // Never log letter content. Log only the error status.
    console.error('analyze failed', e?.status || e?.name);
    // The model is down or rate limited, but the rules never were.
    if (rules) return res.status(200).json({ ...mergeResults(null, rules, { english }), degraded: 'upstream' });
    return res.status(e?.status === 429 ? 429 : 502).json({ error: 'upstream' });
  }
}
