const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_ANON_KEY || '';

app.use(express.static(path.join(__dirname, '..')));
app.use(express.json());

// ─── ROTA DE LOGIN ───────────────────────────────────────────
app.post('/api/login', async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ erro: 'Preencha usuário e senha.' });
    }

    try {
        const response = await fetch(
            `${SUPABASE_URL}/rest/v1/usuarios?username=eq.${encodeURIComponent(username)}&password=eq.${encodeURIComponent(password)}&select=id,username`,
            {
                headers: {
                    'apikey': SUPABASE_KEY,
                    'Authorization': `Bearer ${SUPABASE_KEY}`,
                    'Content-Type': 'application/json'
                }
            }
        );

        const data = await response.json();

        if (data && data.length > 0) {
            return res.json({ sucesso: true, usuario: data[0].username });
        } else {
            return res.status(401).json({ erro: 'Usuário ou senha incorretos.' });
        }
    } catch (err) {
        console.error('Erro ao autenticar:', err);
        return res.status(500).json({ erro: 'Erro interno do servidor.' });
    }
});

// ─── ROTA MEDICAMENTOS ───────────────────────────────────────
app.get('/api/medicamentos', (req, res) => {
    const medicamentos = require('../data/medicamentos.json');
    const { q, tarja, classe } = req.query;

    let result = medicamentos;

    if (q) {
        const search = q.toLowerCase();
        result = result.filter(m =>
            m.nome.toLowerCase().includes(search) ||
            m.ativo.toLowerCase().includes(search) ||
            (m.obs && m.obs.toLowerCase().includes(search))
        );
    }
    if (tarja) result = result.filter(m => m.tarja === tarja);
    if (classe) result = result.filter(m => m.classe === classe);

    res.json(result);
});

// ─── ROTAS DE PÁGINAS ────────────────────────────────────────
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, '../pages/login.html'));
});

app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, '../pages/login.html'));
});

app.get('/dashboard', (req, res) => {
    res.sendFile(path.join(__dirname, '../index.html'));
});

app.listen(PORT, () => {
    console.log(`\n🚀 Info-Farma rodando em: http://localhost:${PORT}\n`);
});
