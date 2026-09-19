import * as crypto from 'node:crypto';

const DEFAULT_CLIENT_ID = '1548916664895144046';

function getDiscordConfig(req) {
  const clientId = String(
    process.env.DISCORD_CLIENT_ID || DEFAULT_CLIENT_ID
  ).trim();

  /*
   * O redirect_uri precisa ser exatamente o mesmo em /api/discord-start
   * e em /api/discord-callback, e precisa estar cadastrado no painel do
   * Discord. Usamos o domínio da requisição (ou DISCORD_REDIRECT_URI /
   * URL) para nunca apontar para um domínio antigo.
   */
  const explicit = String(
    process.env.DISCORD_REDIRECT_URI || ''
  ).trim();

  let origin = '';

  try {
    origin = new URL(req.url).origin;
  } catch {
    origin = '';
  }

  if (!origin) {
    origin = String(
      process.env.URL || ''
    ).trim().replace(/\/+$/, '');
  }

  const redirectUri = explicit ||
    `${origin}/api/discord-callback`;

  return { clientId, redirectUri };
}

function cookie(name, value, maxAge) {
  return `${name}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}

function createSignedState(secret) {
  const issuedAt = Date.now();
  const nonce = crypto.randomBytes(32).toString('hex');

  const payload = `${issuedAt}.${nonce}`;

  const signature = crypto
    .createHmac('sha256', secret)
    .update(payload)
    .digest('base64url');

  const encodedPayload = Buffer
    .from(payload, 'utf8')
    .toString('base64url');

  return `${encodedPayload}.${signature}`;
}

export default async (req) => {
  try {
    if (req.method !== 'GET') {
      return new Response('Método não permitido.', {
        status: 405
      });
    }

    const sessionSecret = String(
      process.env.DISCORD_SESSION_SECRET || ''
    ).trim();

    if (!sessionSecret) {
      console.error(
        'DISCORD_SESSION_SECRET não configurado.'
      );

      return new Response(
        'Discord OAuth não configurado corretamente no servidor.',
        { status: 503 }
      );
    }

    const { clientId, redirectUri } = getDiscordConfig(req);

    if (!clientId) {
      return new Response('Discord OAuth não configurado: falta DISCORD_CLIENT_ID.', { status: 503 });
    }

    const state = createSignedState(sessionSecret);

    const authUrl = new URL(
      'https://discord.com/oauth2/authorize'
    );

    authUrl.searchParams.set(
      'client_id',
      clientId
    );

    authUrl.searchParams.set(
      'response_type',
      'code'
    );

    authUrl.searchParams.set(
      'redirect_uri',
      redirectUri
    );

    authUrl.searchParams.set(
      'scope',
      'identify email'
    );

    authUrl.searchParams.set(
      'state',
      state
    );

    return new Response(null, {
      status: 302,

      headers: {
        Location: authUrl.toString(),

        'Cache-Control':
          'no-store, no-cache, must-revalidate',

        'Pragma':
          'no-cache',

        'Set-Cookie':
          cookie(
            'sapucaia_oauth_state',
            state,
            600
          )
      }
    });
  } catch (error) {
    console.error(
      'discord-start error:',
      error?.stack ||
        error?.message ||
        error
    );

    return new Response(
      'Erro ao iniciar o login com Discord.',
      { status: 500 }
    );
  }
};
