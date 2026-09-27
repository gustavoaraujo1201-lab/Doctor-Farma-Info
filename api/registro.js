// api/registro.js — Vercel Serverless Function
// Cadastro via Firebase Authentication. O Firebase não tem conceito nativo
// de "username único", então usamos uma única coleção Firestore mínima
// (usernames/{usernameLower} -> uid) só para essa checagem — nada além disso
// foi movido para o Firestore.

import { requireApiKey, db, adminAuth } from './_lib/firebase-admin.js';
import { mensagemAmigavel } from './_lib/firebase-errors.js';

const PALAVRAS_PROIBIDAS = [
    'puta','puto','merda','bosta','corno','corna','viado','viadão',
    'buceta','boceta','xoxota','xereca','piroca','pau','rola','pinto',
    'cu','cú','cuzão','cuzao','fdp','filhadaputa','filhodaputa',
    'porra','caralho','cacete','desgraça','desgraca','safado','safada',
    'vagabundo','vagabunda','prostituta','prostituída','traveco',
    'otario','otário','imbecil','idiota','cretino','babaca',
    'arrombado','arrombada','fudido','fudida','foda','fodase',
    'fuck','shit','bitch','asshole','bastard','cunt','dick',
    'cock','pussy','nigger','nigga','faggot','whore','slut',
    'damn','crap','prick','twat',
];

function contemPalavraProibida(texto) {
    const t = texto.toLowerCase().replace(/\s+/g, '');
    return PALAVRAS_PROIBIDAS.some(p => t.includes(p));
}

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

    const { email, username, password } = req.body || {};
    if (!email || !username || !password)
        return res.status(400).json({ erro: 'Preencha todos os campos.' });

    const emailClean    = String(email).trim().toLowerCase().slice(0, 254);
    const usernameClean = String(username).trim().slice(0, 30);
    const usernameKey    = usernameClean.toLowerCase();
    const passwordRaw   = String(password);

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(emailClean))
        return res.status(400).json({ erro: 'E-mail inválido.' });
    if (usernameClean.length < 3)
        return res.status(400).json({ erro: 'Usuário deve ter pelo menos 3 caracteres.' });
    if (usernameClean.length > 30)
        return res.status(400).json({ erro: 'Usuário deve ter no máximo 30 caracteres.' });
    if (contemPalavraProibida(usernameClean))
        return res.status(400).json({ erro: 'Nome de usuário contém palavras não permitidas.' });
    if (passwordRaw.length < 8)
        return res.status(400).json({ erro: 'A senha deve ter pelo menos 8 caracteres.' });
    if (passwordRaw.length > 72)
        return res.status(400).json({ erro: 'Senha muito longa.' });

    try {
        const apiKey = requireApiKey();

        // ─── Verifica se o username já existe (Firestore) ────────────
        const usernameDoc = await db.collection('usernames').doc(usernameKey).get();
        if (usernameDoc.exists)
            return res.status(409).json({ erro: 'Este nome de usuário já está em uso.' });

        // ─── Cria a conta no Firebase Auth ───────────────────────────
        const signUpRes = await fetch(
            `https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=${apiKey}`,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: emailClean, password: passwordRaw, returnSecureToken: true })
            }
        );
        const signUpData = await signUpRes.json();

        if (!signUpRes.ok) {
            return res.status(signUpData?.error?.message === 'EMAIL_EXISTS' ? 409 : 400)
                .json({ erro: mensagemAmigavel(signUpData?.error?.message) });
        }

        const uid = signUpData.localId;

        // ─── Salva o displayName (username) na conta ─────────────────
        await adminAuth.updateUser(uid, { displayName: usernameClean });

        // ─── Reserva o username no Firestore (fire-and-forget, como antes) ───
        db.collection('usernames').doc(usernameKey).set({ uid, email: emailClean })
            .catch(e => console.error('Erro ao reservar username:', e.message));

        return res.json({ sucesso: true, usuario: usernameClean });

    } catch (err) {
        console.error('Erro no registro:', err.message);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
