import {
  getClientId,
  getClientSecret,
  getSessionSecret,
  resolveOrigin,
  resolveRedirectUri,
  verifyState,
  cookie,
  createSessionToken,
  STATE_COOKIE,
  SESSION_COOKIE,
  SESSION_MAX_AGE
} from './_discord-oauth.mjs';

function page(title, message, hint, origin, status) {
  const html = `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>${title}</title>
</head>
<body style="background:#06060a;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0">
<div style="text-align:center;padding:24px;max-width:520px">
<h2>${title}</h2>
<p style="color:#a6a0aa;line-height:1.5">${message}</p>
${hint ? `<p style="color:#ff4fa3;font-size:14px;line-height:1.5">${hint}</p>` : ''}
<p><a href="${origin}/" style="color:#ff087f">Voltar para a loja</a></p>
</div>
</body>
</html>`;

  return new Response(html, {
    status,
    headers: {
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache'
    }
  });
}

export default async (req) => {
  const origin = resolveOrigin(req);

  try {
    if (req.method !== 'GET') {
      return new Response('Método não permitido.', { status: 405 });
    }

    const url = new URL(req.url);
    const code = String(url.searchParams.get('code') || '').trim();
    const state = String(url.searchParams.get('state') || '').trim();
    const oauthError = String(url.searchParams.get('error') || '').trim();

    // O Discord avisa aqui quando a pessoa cancelou a autorização.
    if (oauthError) {
      const description = String(url.searchParams.get('error_description') || '').trim();

      return page(
        'Autorização cancelada',
        description || 'A autorização do Discord não foi concluída.',
        '',
        origin,
        400
      );
    }

    const clientId = getClientId();
    const clientSecret = getClientSecret();
    const sessionSecret = getSessionSecret();

    if (!clientSecret || !sessionSecret) {
      console.error('Discord OAuth incompleto: falta DISCORD_CLIENT_SECRET ou DISCORD_SESSION_SECRET.');
      return page(
        'Discord não configurado',
        'A loja ainda não tem as credenciais do Discord configuradas no servidor.',
        '',
        origin,
        503
      );
    }

    if (!code || !state) {
      return page('Autorização inválida', 'A autorização do Discord está inválida ou expirada.', '', origin, 400);
    }

    const verified = verifyState(state, sessionSecret);

    if (!verified) {
      return page(
        'Autorização inválida',
        'A autorização do Discord está inválida ou expirada. Tente entrar novamente.',
        '',
        origin,
        400
      );
    }

    /*
     * O redirect_uri da troca do código precisa ser idêntico ao enviado no
     * início do fluxo, por isso ele vem assinado dentro do state.
     */
    const redirectUri = verified.redirectUri || resolveRedirectUri(req);
    const storeOrigin = verified.origin || origin;

    const tokenRes = await fetch('https://discord.com/api/v10/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        client_id: clientId,
        client_secret: clientSecret,
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri
      }).toString()
    });

    const tokenBody = await tokenRes.json().catch(() => ({}));

    if (!tokenRes.ok || !tokenBody.access_token) {
      const reason = String(tokenBody?.error || '').trim();
      const description = String(tokenBody?.error_description || '').trim();

      console.error('Discord token exchange failed:', reason, description);

      let hint = '';

      if (reason === 'invalid_grant' || /redirect/i.test(description)) {
        hint = `Cadastre exatamente esta URL em Discord Developer Portal &rarr; OAuth2 &rarr; Redirects: <code>${redirectUri}</code>`;
      } else if (reason === 'invalid_client') {
        hint = 'O DISCORD_CLIENT_ID e o DISCORD_CLIENT_SECRET não pertencem à mesma aplicação do Discord.';
      }

      return page(
        'Não foi possível concluir a autorização do Discord',
        description || reason || 'O Discord recusou a troca do código de autorização.',
        hint,
        storeOrigin,
        502
      );
    }

    const userRes = await fetch('https://discord.com/api/v10/users/@me', {
      headers: { Authorization: `Bearer ${tokenBody.access_token}` }
    });

    const user = await userRes.json().catch(() => ({}));

    if (!userRes.ok || !user.id) {
      console.error('Discord user lookup failed:', user?.message || userRes.status);
      return page(
        'Não foi possível obter o usuário do Discord',
        'A autorização funcionou, mas os dados da conta não puderam ser lidos.',
        '',
        storeOrigin,
        502
      );
    }

    const now = Date.now();

    const sessionData = {
      id: String(user.id),
      username: String(user.username || ''),
      global_name: String(user.global_name || user.username || ''),
      email: user.email || null,
      avatar: user.avatar || null,
      iat: now,
      exp: now + SESSION_MAX_AGE * 1000
    };

    const sessionToken = createSessionToken(sessionData, sessionSecret);

    const headers = new Headers({
      'content-type': 'text/html; charset=utf-8',
      'cache-control': 'no-store, no-cache, must-revalidate',
      Pragma: 'no-cache'
    });

    headers.append('Set-Cookie', cookie(SESSION_COOKIE, sessionToken, SESSION_MAX_AGE, origin));
    headers.append('Set-Cookie', cookie(STATE_COOKIE, '', 0, origin));

    const html = `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Cache-Control" content="no-store">
<title>Discord conectado</title>
</head>
<body style="background:#06060a;color:#fff;font-family:Arial,sans-serif;display:grid;place-items:center;min-height:100vh;margin:0">
<div style="text-align:center;padding:24px">
<h2>Discord conectado ✅</h2>
<p>Redirecionando para a loja...</p>
</div>
<script>window.location.replace('/?discord=connected');</script>
</body>
</html>`;

    return new Response(html, { status: 200, headers });
  } catch (error) {
    console.error('discord-callback error:', error?.stack || error?.message || error);
    return page('Erro ao conectar o Discord', 'Tente novamente em alguns instantes.', '', origin, 500);
  }
};
