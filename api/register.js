import { createHmac } from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { siteUrl } = req.body ?? {};
  if (!siteUrl || typeof siteUrl !== 'string') {
    return res.status(400).json({ error: 'siteUrl required' });
  }

  // Normalize to origin only — strips path, query, trailing slash.
  // gemini.js must apply the same normalization when validating.
  let canonical;
  try {
    const parsed = new URL(siteUrl);
    if (!['http:', 'https:'].includes(parsed.protocol)) throw new Error();
    canonical = parsed.origin;
  } catch {
    return res.status(400).json({ error: 'siteUrl must be a valid http/https URL' });
  }

  const secret = process.env.PROXY_SHARED_SECRET;
  if (!secret) return res.status(500).json({ error: 'Proxy not configured' });

  const encoded = Buffer.from(canonical).toString('base64url');
  const hmac = createHmac('sha256', secret).update(canonical).digest('hex');
  const token = `${encoded}.${hmac}`;

  res.status(200).json({ token });
}
