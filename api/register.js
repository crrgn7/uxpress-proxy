import { createHmac } from 'crypto';

function buildFreemiusAuth(installId, publicKey, secretKey, resourceUrl) {
    const date = new Date().toUTCString();
    // Freemius signs: METHOD\ncontent_md5\ncontent_type\ndate\nfull_url
    // For GET: content_md5 and content_type are empty strings.
    const stringToSign = ['GET', '', '', date, resourceUrl].join('\n');
    // Freemius Base64UrlEncode(hash_hmac('sha256', ..., ...)) where hash_hmac returns a hex string.
    // The hex string is then base64url-encoded (not the raw binary digest).
    const hexSig = createHmac('sha256', secretKey).update(stringToSign).digest('hex');
    const sig = Buffer.from(hexSig).toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    return { authorization: `FS ${installId}:${publicKey}:${sig}`, date };
}

export default async function handler(req, res) {
    if (req.method !== 'POST') return res.status(405).end();

    const { siteUrl, fsInstallId } = req.body ?? {};

    if (!siteUrl || typeof siteUrl !== 'string') {
        return res.status(400).json({ error: 'siteUrl required' });
    }
    if (!fsInstallId) {
        return res.status(401).json({ error: 'UXPress installation credentials required.' });
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

    const proxySecret = process.env.PROXY_SHARED_SECRET;
    const pluginId = process.env.FREEMIUS_PLUGIN_ID ?? '32000';
    const devId = process.env.FREEMIUS_DEV_ID;
    const devPublicKey = process.env.FREEMIUS_DEV_PUBLIC_KEY;
    const devSecretKey = process.env.FREEMIUS_DEV_SECRET_KEY;
    if (!proxySecret) return res.status(500).json({ error: 'Proxy not configured' });
    if (!devId || !devPublicKey || !devSecretKey) return res.status(500).json({ error: 'Proxy not configured' });

    // Verify against Freemius API using developer-level credentials stored in Vercel env vars.
    // This confirms fsInstallId is a real UXPress install without the install secret ever leaving WordPress.
    const fsUrl = `https://api.freemius.com/v1/plugins/${pluginId}/installs/${encodeURIComponent(fsInstallId)}.json`;
    const { authorization, date } = buildFreemiusAuth(devId, devPublicKey, devSecretKey, fsUrl);

    try {
        const fsRes = await fetch(fsUrl, {
            headers: { Authorization: authorization, Date: date },
        });
        if (!fsRes.ok) {
            return res.status(401).json({ error: 'Not a valid UXPress installation.' });
        }
    } catch {
        return res.status(502).json({ error: 'Could not verify installation — please try again.' });
    }

    const encoded = Buffer.from(canonical).toString('base64url');
    const hmac = createHmac('sha256', proxySecret).update(canonical).digest('hex');
    res.status(200).json({ token: `${encoded}.${hmac}` });
}
