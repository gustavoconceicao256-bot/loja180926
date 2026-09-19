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

function safeEqual(a, b) {
  const aa = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));

  return (
    aa.length === bb.length &&
    crypto.timingSafeEqual(aa, bb)
  );
}

function verifySignedState(state, secret) {
  try {
    const parts = String(state || '').split('.');

    if (parts.length !== 2) {
      return false;
    }

    const [encodedPayload, signature] = parts;

    if (!encodedPayload || !signature) {
      return false;
    }

    const payload = Buffer
      .from(encodedPayload, 'base64url')
      .toString('utf8');

    const expectedSignature = crypto
      .createHmac('sha256', secret)
      .update(payload)
      .digest('base64url');

    if (
      !safeEqual(
        signature,
        expectedSignature
      )
    ) {
      return false;
    }

    const separator = payload.indexOf('.');

    if (separator === -1) {
      return false;
    }

    const issuedAt = Number(
      payload.slice(0, separator)
    );

    if (!Number.isFinite(issuedAt)) {
      return false;
    }

    const age = Date.now() - issuedAt;

    // Estado válido durante 10 minutos.
    if (age > 10 * 60 * 1000) {
      return false;
    }

    // Não aceita estado muito adiantado.
    if (age < -60 * 1000) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

export default async (req) => {
  try {
    if (req.method !== 'GET') {
      return new Response(
        'Método não permitido.',
        { status: 405 }
      );
    }

    const url = new URL(req.url);

    const code = String(
      url.searchParams.get('code') || ''
    ).trim();

    const state = String(
      url.searchParams.get('state') || ''
    ).trim();

    const { clientId, redirectUri } = getDiscordConfig(req);

    const clientSecret = String(
      process.env.DISCORD_CLIENT_SECRET || ''
    ).trim();

    const sessionSecret = String(
      process.env.DISCORD_SESSION_SECRET || ''
    ).trim();

    if (!clientSecret || !sessionSecret) {
      console.error(
        'Discord OAuth incompleto: falta DISCORD_CLIENT_SECRET ou DISCORD_SESSION_SECRET.'
      );

      return new Response(
        'Discord OAuth não configurado corretamente no servidor.',
        { status: 503 }
      );
    }

    if (!code || !state) {
      return new Response(
        'Autorização do Discord inválida ou expirada.',
        {
          status: 400,
          headers: {
            'content-type':
              'text/plain; charset=utf-8'
          }
        }
      );
    }

    /*
     * O state agora é validado pela assinatura criptográfica.
     * Não dependemos do cookie para validar a autorização.
     */
    if (
      !verifySignedState(
        state,
        sessionSecret
      )
    ) {
      return new Response(
        'Autorização do Discord inválida ou expirada.',
        {
          status: 400,
          headers: {
            'content-type':
              'text/plain; charset=utf-8'
          }
        }
      );
    }

    const tokenRes = await fetch(
      'https://discord.com/api/v10/oauth2/token',
      {
        method: 'POST',

        headers: {
          'Content-Type':
            'application/x-www-form-urlencoded'
        },

        body: new URLSearchParams({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: 'authorization_code',
          code,
          redirect_uri: redirectUri
        }).toString()
      }
    );

    const tokenBody = await tokenRes
      .json()
      .catch(() => ({}));

    if (
      !tokenRes.ok ||
      !tokenBody.access_token
    ) {
      console.error(
        'Discord token exchange failed:',
        tokenBody
      );

      return new Response(
        'Não foi possível concluir a autorização do Discord.',
        { status: 502 }
      );
    }

    const userRes = await fetch(
      'https://discord.com/api/v10/users/@me',
      {
        headers: {
          Authorization:
            `Bearer ${tokenBody.access_token}`
        }
      }
    );

    const user = await userRes
      .json()
      .catch(() => ({}));

    if (!userRes.ok || !user.id) {
      console.error(
        'Discord user lookup failed:',
        user
      );

      return new Response(
        'Não foi possível obter o usuário do Discord.',
        { status: 502 }
      );
    }

    const now = Date.now();

    /*
     * Dados da conta Discord.
     *
     * O ID é o identificador principal da conta.
     * O avatar é guardado para a loja mostrar a foto.
     */
    const sessionData = {
      id: String(user.id),

      username: String(
        user.username || ''
      ),

      global_name: String(
        user.global_name ||
          user.username ||
          ''
      ),

      email:
        user.email || null,

      avatar:
        user.avatar || null,

      iat: now,

      /*
       * A conta fica reconhecida por 30 dias
       * enquanto o cookie de sessão existir e for válido.
       */
      exp:
        now + 30 * 24 * 60 * 60 * 1000
    };

    const payload = Buffer
      .from(
        JSON.stringify(sessionData),
        'utf8'
      )
      .toString('base64url');

    const signature = crypto
      .createHmac(
        'sha256',
        sessionSecret
      )
      .update(payload)
      .digest('base64url');

    const sessionToken =
      `${payload}.${signature}`;

    const headers = new Headers({
      'content-type':
        'text/html; charset=utf-8',

      'cache-control':
        'no-store, no-cache, must-revalidate',

      Pragma:
        'no-cache'
    });

    /*
     * Sessão da conta Discord por 30 dias.
     */
    headers.append(
      'Set-Cookie',
      cookie(
        'sapucaia_discord_session',
        sessionToken,
        30 * 24 * 60 * 60
      )
    );

    /*
     * Limpa o state usado no OAuth.
     */
    headers.append(
      'Set-Cookie',
      cookie(
        'sapucaia_oauth_state',
        '',
        0
      )
    );

    const html = `
<!doctype html>
<html lang="pt-BR">
<head>
  <meta charset="utf-8">
  <meta name="viewport"
        content="width=device-width,initial-scale=1">

  <meta http-equiv="Cache-Control"
        content="no-store">

  <title>Discord conectado</title>
</head>

<body style="
  background:#06060a;
  color:#fff;
  font-family:Arial,sans-serif;
  display:grid;
  place-items:center;
  min-height:100vh;
  margin:0;
">

  <div style="
    text-align:center;
    padding:24px;
  ">
    <h2>Discord conectado ✅</h2>
    <p>Redirecionando para a loja...</p>
  </div>

  <script>
    window.location.replace(
      '/?discord=connected'
    );
  </script>

</body>
</html>
`;

    return new Response(
      html,
      {
        status: 200,
        headers
      }
    );

  } catch (error) {

    console.error(
      'discord-callback error:',
      error?.stack ||
        error?.message ||
        error
    );

    return new Response(
      'Erro ao conectar o Discord.',
      { status: 500 }
    );
  }
};
