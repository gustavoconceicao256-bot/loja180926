import crypto from 'node:crypto';

/*
 * Configuração compartilhada do OAuth do Discord.
 *
 * Regra principal: o fluxo inteiro precisa acontecer no MESMO domínio
 * em que a loja está aberta. Se o redirect_uri apontar para outro site,
 * o Discord devolve o código de autorização para esse outro domínio,
 * a troca do código falha e o cookie de sessão nunca chega na loja.
 */

const DEFAULT_CLIENT_ID = '1548916664895144046';

export const CALLBACK_PATH = '/api/discord-callback';
export const STATE_COOKIE = 'sapucaia_oauth_state';
export const SESSION_COOKIE = 'sapucaia_discord_session';

export const SESSION_MAX_AGE = 30 * 24 * 60 * 60; // 30 dias em segundos.
const STATE_MAX_AGE_MS = 10 * 60 * 1000; // 10 minutos.

export function getClientId() {
  return String(process.env.DISCORD_CLIENT_ID || DEFAULT_CLIENT_ID).trim();
}

export function getClientSecret() {
  return String(process.env.DISCORD_CLIENT_SECRET || '').trim();
}

export function getSessionSecret() {
  return String(process.env.DISCORD_SESSION_SECRET || '').trim();
}

/*
 * Origem pública do pedido (protocolo + domínio), respeitando os
 * cabeçalhos de proxy da Netlify.
 */
export function resolveOrigin(req) {
  const url = new URL(req.url);

  const forwardedHost = String(req.headers.get('x-forwarded-host') || '').split(',')[0].trim();
  const host = forwardedHost || String(req.headers.get('host') || '').trim() || url.host;

  const forwardedProto = String(req.headers.get('x-forwarded-proto') || '').split(',')[0].trim();
  const isLocal = /^(localhost|127\.0\.0\.1|\[::1\])(:\d+)?$/i.test(host);
  const proto = forwardedProto || (isLocal ? url.protocol.replace(':', '') : 'https');

  return `${proto}://${host}`;
}

/*
 * redirect_uri sempre no domínio atual.
 *
 * DISCORD_REDIRECT_URI só é usado quando aponta para a mesma origem do
 * pedido. Um valor de outro domínio é ignorado de propósito: era exatamente
 * isso que quebrava a autorização (o Discord devolvia o código para outro site).
 */
export function resolveRedirectUri(req) {
  const origin = resolveOrigin(req);
  const configured = String(process.env.DISCORD_REDIRECT_URI || '').trim();

  if (configured) {
    try {
      const parsed = new URL(configured);
      if (parsed.origin === origin) return parsed.toString();

      console.warn(
        `DISCORD_REDIRECT_URI (${parsed.origin}) não corresponde ao domínio da loja (${origin}). Usando o domínio atual.`
      );
    } catch {
      console.warn('DISCORD_REDIRECT_URI inválido. Usando o domínio atual.');
    }
  }

  return `${origin}${CALLBACK_PATH}`;
}

function sign(payload, secret) {
  return crypto.createHmac('sha256', secret).update(payload).digest('base64url');
}

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  return aa.length === bb.length && crypto.timingSafeEqual(aa, bb);
}

/*
 * O state carrega o redirect_uri e a origem usados no início do fluxo.
 * Assim a troca do código usa exatamente o mesmo redirect_uri enviado ao
 * Discord, mesmo que a configuração mude no meio do caminho.
 */
export function createState(secret, { redirectUri, origin }) {
  const data = {
    v: 1,
    t: Date.now(),
    n: crypto.randomBytes(16).toString('hex'),
    r: String(redirectUri || ''),
    o: String(origin || '')
  };

  const payload = Buffer.from(JSON.stringify(data), 'utf8').toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}

export function verifyState(state, secret) {
  try {
    const raw = String(state || '');
    const dot = raw.indexOf('.');
    if (dot <= 0) return null;

    const payload = raw.slice(0, dot);
    const signature = raw.slice(dot + 1);
    if (!payload || !signature) return null;
    if (!safeEqual(signature, sign(payload, secret))) return null;

    const decoded = Buffer.from(payload, 'base64url').toString('utf8');

    // Formato novo: JSON assinado com redirect_uri e origem.
    if (decoded.startsWith('{')) {
      const data = JSON.parse(decoded);
      const issuedAt = Number(data?.t);
      if (!Number.isFinite(issuedAt)) return null;

      const age = Date.now() - issuedAt;
      if (age > STATE_MAX_AGE_MS || age < -60 * 1000) return null;

      return {
        redirectUri: String(data.r || ''),
        origin: String(data.o || '')
      };
    }

    /*
     * Formato antigo ("<timestamp>.<nonce>"), aceito para não invalidar
     * fluxos iniciados antes deste deploy.
     */
    const separator = decoded.indexOf('.');
    if (separator === -1) return null;

    const legacyIssuedAt = Number(decoded.slice(0, separator));
    if (!Number.isFinite(legacyIssuedAt)) return null;

    const legacyAge = Date.now() - legacyIssuedAt;
    if (legacyAge > STATE_MAX_AGE_MS || legacyAge < -60 * 1000) return null;

    return { redirectUri: '', origin: '' };
  } catch {
    return null;
  }
}

/*
 * Secure só entra quando a origem é https, para o fluxo continuar
 * funcionando em desenvolvimento local (netlify dev em http).
 */
export function cookie(name, value, maxAge, origin) {
  const secure = String(origin || '').startsWith('https://') ? '; Secure' : '';
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly${secure}; SameSite=Lax; Max-Age=${maxAge}`;
}

export function createSessionToken(sessionData, secret) {
  const payload = Buffer.from(JSON.stringify(sessionData), 'utf8').toString('base64url');
  return `${payload}.${sign(payload, secret)}`;
}
