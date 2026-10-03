import { getClient, FAST_MODEL, parseJson, rateLimited, safeLang } from '../lib/claude.js';
import { hasStatic, staticStrings } from '../data/ui-strings.js';

const cache = new Map(); // language code -> translated strings (best effort, per instance)

export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  if (req.method !== 'POST') return res.status(405).json({ error: 'method' });
  if (rateLimited(req, 20)) return res.status(429).json({ error: 'rate_limited' });

  const body = req.body || {};
  const lang = safeLang(body.lang);
  const strings = body.strings;
  const keys = strings && typeof strings === 'object' ? Object.keys(strings) : [];
  if (keys.length === 0 || keys.length > 120 || keys.some((k) => typeof strings[k] !== 'string' || strings[k].length > 800)) {
    return res.status(400).json({ error: 'bad_strings' });
  }
  if (lang.code === 'en') return res.status(200).json(strings);
  if (cache.has(lang.code)) return res.status(200).json(cache.get(lang.code));

  // Shipped translations win: instant, free, and they work with no key, in mock
  // mode and offline. The model is only for a language we have not covered yet.
  if (hasStatic(lang.code, keys)) {
    const out = staticStrings(lang.code, strings);
    cache.set(lang.code, out);
    return res.status(200).json(out);
  }

  // Without a model the best we can do is per-key static text, falling back to
  // English for anything missing. A half-English screen beats a blank one.
  if (process.env.MOCK === '1' || !process.env.ANTHROPIC_API_KEY) {
    return res.status(200).json(staticStrings(lang.code, strings));
  }

  try {
    const prompt = `Translate the values of this JSON object from English into ${lang.en} (${lang.native}). Keep every key exactly as it is. Keep placeholders such as {n} unchanged. The words are for an app used by older adults, so use short, friendly, everyday words. Reply with ONLY the JSON object.\n\n${JSON.stringify(strings)}`;
    const msg = await getClient().messages.create({
      model: FAST_MODEL,
      max_tokens: 4000,
      messages: [{ role: 'user', content: prompt }],
    });
    const out = msg.content.filter((b) => b.type === 'text').map((b) => b.text).join('');
    const data = parseJson(out);
    if (!data) return res.status(200).json(staticStrings(lang.code, strings));
    cache.set(lang.code, data);
    return res.status(200).json(data);
  } catch (e) {
    console.error('translate-ui failed', e?.status || e?.name);
    // Falling back keeps the language switch working when the model is down.
    return res.status(200).json(staticStrings(lang.code, strings));
  }
}
