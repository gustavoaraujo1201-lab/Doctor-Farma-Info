// api/login.js — Vercel Serverless Function
// Login direto por e-mail — 1 requisição só, sem busca extra

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || '';

// ─── Rate Limiting em memória ────────────────────────────────
const attempts = new Map();
function isRateLimited(ip) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const max = 10;
    const data = attempts.get(ip) || { count: 0, start: now };
    if (now - data.start > windowMs) { attempts.set(ip, { count: 1, start: now }); return false; }
    if (data.count >= max) return true;
    data.count++;
    attempts.set(ip, data);
    return false;
}

function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
}

export default async function handler(req, res) {
    setSecurityHeaders(res);

    if (req.method !== 'POST') return res.status(405).json({ erro: 'Método não permitido.' });

    const ip = req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
    if (isRateLimited(ip)) return res.status(429).json({ erro: 'Muitas tentativas. Aguarde 15 minutos.' });

    const { email, password } = req.body || {};

    if (!email || !password) return res.status(400).json({ erro: 'Preencha o e-mail e a senha.' });

    const emailClean  = String(email).trim().toLowerCase().slice(0, 254);
    const passwordRaw = String(password).slice(0, 72);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean))
        return res.status(400).json({ erro: 'E-mail inválido.' });

    try {
        // ─── Uma única requisição ao Supabase Auth ───────────
        const authRes = await fetch(`${SUPABASE_URL}/auth/v1/token?grant_type=password`, {
            method: 'POST',
            headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: emailClean, password: passwordRaw })
        });

        const authData = await authRes.json();

        if (!authRes.ok) {
            return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
        }

        // Username vem do user_metadata salvo no registro
        const username = authData?.user?.user_metadata?.username || emailClean.split('@')[0];

        return res.json({
            sucesso: true,
            usuario: username,
            access_token: authData.access_token,
            expires_in: authData.expires_in
        });

    } catch (err) {
        console.error('Erro no login:', err);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
