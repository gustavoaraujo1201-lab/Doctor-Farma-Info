// api/login.js — Vercel Serverless Function
// Login via Firebase Authentication (Identity Toolkit REST API)

import { requireApiKey } from './_lib/firebase-admin.js';
import { mensagemAmigavel } from './_lib/firebase-errors.js';

// ─── Rate Limiting em memória (preservado — ver observação no relatório) ───
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
        const apiKey = requireApiKey();

        const authRes = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailClean, password: passwordRaw, returnSecureToken: true })
            }
        );
        const authData = await authRes.json();

        if (!authRes.ok) {
            return res.status(401).json({ erro: mensagemAmigavel(authData?.error?.message) });
        }

        // O displayName foi salvo no registro (accounts:update) — é o username.
        const username = authData.displayName || emailClean.split('@')[0];

        return res.json({
            sucesso: true,
            usuario: username,
            access_token: authData.idToken,
            expires_in: Number(authData.expiresIn) // Identity Toolkit retorna em segundos, como string
        });

    } catch (err) {
        console.error('Erro no login:', err.message);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
