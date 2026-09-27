// api/verify-session.js — Vercel Serverless Function
// Valida o ID token do Firebase no backend, para que a proteção do
// /dashboard deixe de depender só de um valor gravável no sessionStorage.

import { adminAuth } from './_lib/firebase-admin.js';

function setSecurityHeaders(res) {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
}

export default async function handler(req, res) {
    setSecurityHeaders(res);

    if (req.method !== 'GET' && req.method !== 'POST')
        return res.status(405).json({ erro: 'Método não permitido.' });

    const authHeader = req.headers['authorization'] || '';
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : (req.body?.idToken || '');

    if (!token) return res.status(401).json({ valido: false, erro: 'Token ausente.' });

    try {
        const decoded = await adminAuth.verifyIdToken(token);
        return res.json({ valido: true, uid: decoded.uid, usuario: decoded.name || decoded.email });
    } catch (err) {
        // Token expirado, revogado ou forjado — não é erro interno, é sessão inválida.
        return res.status(401).json({ valido: false, erro: 'Sessão expirada ou inválida.' });
    }
}
