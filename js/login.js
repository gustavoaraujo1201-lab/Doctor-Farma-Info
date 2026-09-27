// ─── LOGIN PAGE ──────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
    const btn  = document.getElementById('btnEntrar');
    const user = document.getElementById('inputUser');
    const pass = document.getElementById('inputPass');

    // Toggle mostrar/ocultar senha
    document.querySelectorAll('.toggle-pass').forEach(icon => {
        icon.addEventListener('click', () => {
            const input = document.getElementById(icon.dataset.target);
            if (input.type === 'password') {
                input.type = 'text';
                icon.classList.replace('bx-hide', 'bx-show');
            } else {
                input.type = 'password';
                icon.classList.replace('bx-show', 'bx-hide');
            }
        });
    });

    btn?.addEventListener('click', async () => {
        const u = user?.value.trim();
        const p = pass?.value.trim();

        if (!u || !p) { showError('Preencha o e-mail e a senha.'); return; }
        if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(u)) { showError('Digite um e-mail válido.'); return; }

        btn.disabled = true;
        btn.textContent = 'Entrando...';

        try {
            const res = await fetch('/api/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email: u, password: p })
            });

            const data = await res.json();

            if (res.ok && data.sucesso) {
                const expiresAt = Date.now() + (data.expires_in * 1000);
                sessionStorage.setItem('infofarma_user', data.usuario);
                sessionStorage.setItem('infofarma_token', data.access_token);
                sessionStorage.setItem('infofarma_expires', expiresAt);
                window.location.href = '/home';
            } else {
                showError(data.erro || 'E-mail ou senha incorretos.');
                btn.disabled = false;
                btn.textContent = 'Entrar';
            }
        } catch {
            showError('Erro de conexão. Tente novamente.');
            btn.disabled = false;
            btn.textContent = 'Entrar';
        }
    });

    [user, pass].forEach(input => {
        input?.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') btn?.click();
        });
    });
});

function showError(msg) {
    let err = document.getElementById('login-error');
    if (!err) {
        err = document.createElement('p');
        err.id = 'login-error';
        err.style.cssText = 'color:#ef4444;font-size:13px;text-align:center;margin-top:-10px;margin-bottom:10px;';
        document.getElementById('btnEntrar').before(err);
    }
    err.textContent = msg;
}
