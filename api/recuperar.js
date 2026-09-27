// api/recuperar.js — Vercel Serverless Function
// Dispara e-mail de recuperação de senha via Firebase Authentication

import { requireApiKey } from './_lib/firebase-admin.js';

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
        const apiKey = requireApiKey();

        await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:sendOobCode?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ requestType: 'PASSWORD_RESET', email: emailClean })
            }
        );

        // Sempre retorna sucesso — mesmo se a Identity Toolkit responder
        // EMAIL_NOT_FOUND. Isso evita enumeração de e-mails, exatamente
        // como o comportamento anterior com o Supabase.
        return res.json({ sucesso: true });

    } catch (err) {
        console.error('Erro na recuperação:', err.message);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
