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

  const a = Buffer.from(parts[1].padEnd(64, '0'), 'hex');
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
  if (!model || typeof model !== 'string' || !payload || typeof payload !== 'object') {
    return res.status(400).json({ error: 'model (string) and payload (object) required' });
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

  res.status(geminiRes.status).json(data);
}
