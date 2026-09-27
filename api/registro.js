// api/registro.js — Vercel Serverless Function
// Usa Supabase Auth: senhas criptografadas com bcrypt, sessão JWT segura

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || '';

// ─── Palavras proibidas no nome de usuário ───────────────────
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

// ─── Headers de segurança HTTP ───────────────────────────────
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
    const passwordRaw   = String(password);

    // ─── Validações rápidas (sem rede) ───────────────────────
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
        // ✅ Verifica username e cria conta em paralelo não é possível pois precisamos
        // do resultado do check antes — mas fazemos signup e insert de perfil em paralelo
        // ─── Verifica se username já existe ──────────────────
        const checkRes = await fetch(
            `${SUPABASE_URL}/rest/v1/perfis?username=ilike.${encodeURIComponent(usernameClean)}&select=id`,
            { headers: { 'apikey': SUPABASE_KEY, 'Authorization': `Bearer ${SUPABASE_KEY}` } }
        );
        const userData = await checkRes.json();
        if (Array.isArray(userData) && userData.length > 0)
            return res.status(409).json({ erro: 'Este nome de usuário já está em uso.' });

        // ─── Cria no Supabase Auth ────────────────────────────
        const signUpRes = await fetch(`${SUPABASE_URL}/auth/v1/signup`, {
            method: 'POST',
            headers: { 'apikey': SUPABASE_KEY, 'Content-Type': 'application/json' },
            body: JSON.stringify({
                email: emailClean,
                password: passwordRaw,
                data: { username: usernameClean, full_name: usernameClean }
            })
        });

        const signUpData = await signUpRes.json();

        if (!signUpRes.ok) {
            if (signUpData?.code === 'user_already_exists' || signUpData?.message?.toLowerCase().includes('already registered'))
                return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
            return res.status(400).json({ erro: 'Erro ao criar conta. Tente novamente.' });
        }

        // ✅ Salva perfil sem aguardar (fire-and-forget) — não bloqueia a resposta
        if (signUpData?.user?.id) {
            fetch(`${SUPABASE_URL}/rest/v1/perfis`, {
                method: 'POST',
                headers: {
                    'apikey': SUPABASE_KEY,
                    'Authorization': `Bearer ${SUPABASE_KEY}`,
                    'Content-Type': 'application/json',
                    'Prefer': 'return=minimal'
                },
                body: JSON.stringify({ id: signUpData.user.id, username: usernameClean, email: emailClean })
            }); // ← sem await: responde ao usuário imediatamente
        }

        return res.json({ sucesso: true, usuario: usernameClean });

    } catch (err) {
        console.error('Erro no registro:', err);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
}
