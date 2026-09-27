// api/_lib/firebase-errors.js — traduz erros da Identity Toolkit (Firebase Auth
// REST API) para as mesmas mensagens amigáveis que o app já usava com o Supabase.
// Nunca deixe o erro técnico bruto vazar para o usuário.

const MAP = {
    EMAIL_EXISTS: 'Este e-mail já está cadastrado.',
    EMAIL_NOT_FOUND: 'E-mail ou senha incorretos.',
    INVALID_PASSWORD: 'E-mail ou senha incorretos.',
    INVALID_LOGIN_CREDENTIALS: 'E-mail ou senha incorretos.',
    INVALID_EMAIL: 'E-mail inválido.',
    USER_DISABLED: 'Esta conta foi desativada.',
    TOO_MANY_ATTEMPTS_TRY_LATER: 'Muitas tentativas. Aguarde alguns minutos e tente novamente.',
};

export function mensagemAmigavel(identityToolkitMessage) {
    if (!identityToolkitMessage) return 'Erro ao processar a solicitação.';
    // Mensagens de senha fraca vêm como "WEAK_PASSWORD : Password should be at least 6 characters"
    const code = String(identityToolkitMessage).split(':')[0].trim();
    return MAP[code] || 'Erro ao processar a solicitação. Tente novamente.';
}
