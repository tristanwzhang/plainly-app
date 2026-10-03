import { getClient, MODEL, parseJson, rateLimited, safeLang } from '../lib/claude.js';
import { buildPrompt } from '../lib/prompt.js';

const MEDIA = new Set(['image/jpeg', 'image/png', 'image/webp', 'image/gif']);
const MAX_IMAGES = 3;
const MAX_B64 = 3_000_000; // about 2.2 MB of image per photo
const MAX_TEXT = 20_000;

const MOCK = {
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

  if (process.env.MOCK === '1') return res.status(200).json(MOCK);

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
    if (!data) return res.status(502).json({ error: 'invalid_json' });
    return res.status(200).json(data);
  } catch (e) {
    // Never log letter content. Log only the error status.
    console.error('analyze failed', e?.status || e?.name);
    return res.status(e?.status === 429 ? 429 : 502).json({ error: 'upstream' });
  }
}
