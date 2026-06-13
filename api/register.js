import { createHmac } from 'crypto';

export default function handler(req, res) {
  if (req.method !== 'POST') return res.status(405).end();

  const { siteUrl } = req.body ?? {};
  if (!siteUrl || typeof siteUrl !== 'string') {
    return res.status(400).json({ error: 'siteUrl required' });
  }

  const secret = process.env.PROXY_SHARED_SECRET;
  if (!secret) return res.status(500).json({ error: 'Proxy not configured' });

  const encoded = Buffer.from(siteUrl).toString('base64url');
  const hmac = createHmac('sha256', secret).update(siteUrl).digest('hex');
  const token = `${encoded}.${hmac}`;

  res.status(200).json({ token });
}
