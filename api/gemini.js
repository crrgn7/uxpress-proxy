import { createHmac, timingSafeEqual } from 'crypto';

function isValidToken(token) {
  const secret = process.env.PROXY_SHARED_SECRET;
  if (!secret || !token) return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;

  let canonical;
  try {
    const siteUrl = Buffer.from(parts[0], 'base64url').toString('utf8');
    const parsed = new URL(siteUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    canonical = parsed.origin;
  } catch {
    return false;
  }

  const expected = createHmac('sha256', secret).update(canonical).digest('hex');

  if (parts[1].length !== 64) return false;
  const a = Buffer.from(parts[1], 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const raw = req.headers['authorization'] ?? '';
  if (!raw.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  const token = raw.slice(7);

  if (!isValidToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'Proxy not configured' });

  const { model, payload } = req.body ?? {};
  if (!model || typeof model !== 'string' || !payload || typeof payload !== 'object' || Array.isArray(payload)) {
    return res.status(400).json({ error: 'model (string) and payload (object) required' });
  }

  const ALLOWED_MODELS = [
    'gemini-2.5-flash',
    'gemini-2.5-pro',
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-1.5-pro',
  ];
  if (!ALLOWED_MODELS.includes(model)) {
    return res.status(400).json({ error: 'Unsupported model.' });
  }

  let geminiRes;
  try {
    geminiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/${encodeURIComponent(model)}:generateContent`,
      {
        method: 'POST',
        headers: {
          'x-goog-api-key': apiKey,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      }
    );
  } catch (err) {
    return res.status(502).json({ error: 'Upstream fetch failed' });
  }

  let data;
  try {
    data = await geminiRes.json();
  } catch {
    return res.status(502).json({ error: 'Gemini returned non-JSON', status: geminiRes.status });
  }

  // Remap Gemini's 401 to 502 so the plugin doesn't misinterpret an expired proxy API key
  // as a rejected site token and wipe its registration.
  if (geminiRes.status === 401) {
    return res.status(502).json({ error: 'Upstream authentication failed — check proxy API key', upstream_status: 401 });
  }

  res.status(geminiRes.status).json(data);
}
