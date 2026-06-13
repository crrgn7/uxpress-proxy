import { createHmac, timingSafeEqual } from 'crypto';

function isValidToken(token) {
  const secret = process.env.PROXY_SHARED_SECRET;
  if (!secret || !token) return false;

  const parts = token.split('.');
  if (parts.length !== 2) return false;

  let siteUrl;
  try {
    siteUrl = Buffer.from(parts[0], 'base64url').toString('utf8');
  } catch {
    return false;
  }

  if (!siteUrl) return false;

  // Normalize to origin — must match what register.js signed
  let canonical;
  try {
    const parsed = new URL(siteUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) return false;
    canonical = parsed.origin;
  } catch {
    return false;
  }

  const expected = createHmac('sha256', secret).update(canonical).digest('hex');

  // Both buffers must be the same length for timingSafeEqual
  if (parts[1].length !== expected.length) return false;
  const a = Buffer.from(parts[1], 'hex');
  const b = Buffer.from(expected, 'hex');
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export default async function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const raw = (req.headers['authorization'] ?? '');
  const token = raw.startsWith('Bearer ') ? raw.slice(7) : raw;

  if (!isValidToken(token)) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const apiKey = process.env.GEMINI_API_KEY;
  if (!apiKey) return res.status(500).json({ error: 'Proxy not configured' });

  const { model, payload } = req.body ?? {};
  if (!model || !payload) {
    return res.status(400).json({ error: 'model and payload required' });
  }

  const geminiRes = await fetch(
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

  const data = await geminiRes.json();
  res.status(geminiRes.status).json(data);
}
