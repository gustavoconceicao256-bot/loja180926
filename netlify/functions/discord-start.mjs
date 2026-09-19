import {
  getClientId,
  getSessionSecret,
  resolveOrigin,
  resolveRedirectUri,
  createState,
  cookie,
  STATE_COOKIE
} from './_discord-oauth.mjs';

export default async (req) => {
  try {
    if (req.method !== 'GET') {
      return new Response('Método não permitido.', { status: 405 });
    }

    const sessionSecret = getSessionSecret();

    if (!sessionSecret) {
      console.error('DISCORD_SESSION_SECRET não configurado.');
      return new Response('Discord OAuth não configurado corretamente no servidor.', { status: 503 });
    }

    const clientId = getClientId();

    if (!clientId) {
      return new Response('Discord OAuth não configurado: falta DISCORD_CLIENT_ID.', { status: 503 });
    }

    const origin = resolveOrigin(req);
    const redirectUri = resolveRedirectUri(req);
    const state = createState(sessionSecret, { redirectUri, origin });

    const authUrl = new URL('https://discord.com/oauth2/authorize');
    authUrl.searchParams.set('client_id', clientId);
    authUrl.searchParams.set('response_type', 'code');
    authUrl.searchParams.set('redirect_uri', redirectUri);
    authUrl.searchParams.set('scope', 'identify email');
    authUrl.searchParams.set('state', state);

    return new Response(null, {
      status: 302,
      headers: {
        Location: authUrl.toString(),
        'Cache-Control': 'no-store, no-cache, must-revalidate',
        Pragma: 'no-cache',
        'Set-Cookie': cookie(STATE_COOKIE, state, 600, origin)
      }
    });
  } catch (error) {
    console.error('discord-start error:', error?.stack || error?.message || error);
    return new Response('Erro ao iniciar o login com Discord.', { status: 500 });
  }
};
