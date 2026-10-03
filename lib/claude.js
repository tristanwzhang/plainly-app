import Anthropic from '@anthropic-ai/sdk';

export const MODEL = process.env.CLAUDE_MODEL || 'claude-sonnet-5';
export const FAST_MODEL = process.env.CLAUDE_FAST_MODEL || 'claude-haiku-4-5-20251001';

let client = null;
export function getClient() {
  if (!client) client = new Anthropic(); // reads ANTHROPIC_API_KEY from the environment
  return client;
}

// Pull one JSON object out of a model reply, tolerating code fences or a stray sentence.
export function parseJson(text) {
  const t = String(text || '').trim();
  try { return JSON.parse(t); } catch {}
  const fence = t.match(/```(?:json)?\s*([\s\S]*?)```/);
  if (fence) { try { return JSON.parse(fence[1]); } catch {} }
  const a = t.indexOf('{'), b = t.lastIndexOf('}');
  if (a >= 0 && b > a) { try { return JSON.parse(t.slice(a, b + 1)); } catch {} }
  return null;
}

// Best-effort rate limit per IP. On serverless this resets between cold starts,
// so treat it as a speed bump, not real protection. Use a shared store for production.
const hits = new Map();
export function rateLimited(req, max = 12, windowMs = 60_000) {
  const ip = (req.headers['x-forwarded-for'] || req.socket?.remoteAddress || 'unknown').toString().split(',')[0].trim();
  const now = Date.now();
  const list = (hits.get(ip) || []).filter((t) => now - t < windowMs);
  list.push(now);
  hits.set(ip, list);
  if (hits.size > 5000) hits.clear();
  return list.length > max;
}

export function safeLang(l = {}) {
  const ok = (s) => typeof s === 'string' && s.length > 0 && s.length < 40 && /^[\p{L}\p{M}\s().-]+$/u.test(s);
  return {
    code: typeof l.code === 'string' && /^[a-z]{2,3}$/.test(l.code) ? l.code : 'en',
    en: ok(l.en) ? l.en : 'English',
    native: ok(l.native) ? l.native : 'English',
  };
}
