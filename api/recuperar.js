// api/recuperar.js — Vercel Serverless Function
// Dispara e-mail de recuperação de senha via Supabase Auth

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || '';

// ─── Rate Limiting ────────────────────────────────────────────
const attempts = new Map();
function isRateLimited(ip) {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000;
    const max = 5; // máx 5 pedidos de recuperação por IP
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
}

export default async function handler(req, res) {
    setSecurityHeaders(res);

    if (req.method !== 'POST') return res.status(405).json({ erro: 'Método não permitido.' });

    const ip = req.headers['x-forwarded-for']?.split(',')[0] || 'unknown';
    if (isRateLimited(ip)) return res.status(429).json({ erro: 'Muitas tentativas. Aguarde 15 minutos.' });

    const { email } = req.body || {};
    if (!email) return res.status(400).json({ erro: 'E-mail obrigatório.' });

    const emailClean = String(email).trim().toLowerCase().slice(0, 254);
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean))
        return res.status(400).json({ erro: 'E-mail inválido.' });

    try {
        // Dispara o e-mail de recuperação via Supabase Auth
        // Por segurança, sempre retorna sucesso (evita enumeração de e-mails)
        await fetch(`${SUPABASE_URL}/auth/v1/recover`, {
            method: 'POST',
            headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: emailClean,
                redirect_to: 'https://infofarma.vercel.app/dashboard'
            })
        });

        // Sempre retorna sucesso — não revela se o e-mail existe ou não
        return res.json({ sucesso: true });

    } catch (err) {
        console.error('Erro na recuperação:', err);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
