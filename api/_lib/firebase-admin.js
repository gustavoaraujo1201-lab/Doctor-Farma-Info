// api/_lib/firebase-admin.js — inicialização única do Firebase Admin SDK
// Usado por qualquer função serverless que precise falar com Firestore
// ou validar um ID token. NUNCA coloque as credenciais aqui — elas vêm
// das variáveis de ambiente da Vercel.

import { initializeApp, getApps, cert } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';
import { getFirestore } from 'firebase-admin/firestore';

function getServiceAccount() {
    const projectId = process.env.FIREBASE_PROJECT_ID;
    const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
    // A chave privada costuma vir com \n escapado quando salva como variável
    // de ambiente — precisa ser convertida de volta para quebras de linha reais.
    const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');

    if (!projectId || !clientEmail || !privateKey) {
        throw new Error(
            'Configuração do Firebase Admin ausente. Defina FIREBASE_PROJECT_ID, ' +
            'FIREBASE_CLIENT_EMAIL e FIREBASE_PRIVATE_KEY nas variáveis de ambiente da Vercel.'
        );
    }

    return { projectId, clientEmail, privateKey };
}

function getAdminApp() {
    if (getApps().length) return getApps()[0];
    return initializeApp({ credential: cert(getServiceAccount()) });
}

export const adminAuth = getAuth(getAdminApp());
export const db = getFirestore(getAdminApp());

// Chave pública do Web API do Firebase — usada para chamar a Identity
// Toolkit REST API (sign-in / sign-up / recuperação de senha) a partir
// das funções serverless, no mesmo espírito das chamadas que hoje são
// feitas direto à REST API do Supabase.
export const FIREBASE_API_KEY = process.env.FIREBASE_API_KEY || '';

export function requireApiKey() {
    if (!FIREBASE_API_KEY) {
        throw new Error('FIREBASE_API_KEY não configurada nas variáveis de ambiente da Vercel.');
    }
    return FIREBASE_API_KEY;
}
