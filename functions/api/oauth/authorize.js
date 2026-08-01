export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const params = new URLSearchParams(url.search);
  const redirectUri = params.get('redirect_uri');
  const state = params.get('state');
  const codeChallenge = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method');
  const clientId = params.get('client_id') || context.env?.HACKCLUB_CLIENT_ID;
  if (!clientId) {
    return new Response('OAuth client is not configured', { status: 500 });
  }

  const allowedRedirects = new Set([
    'https://youspudwespud.sami-s.dev/form/',
    'https://youspudwespud.sami-s.dev/admin/',
  ]);
  if (!redirectUri || !allowedRedirects.has(redirectUri)) {
    return new Response('Invalid redirect_uri', { status: 400 });
  }
  if (!state || state.length < 8 || state.length > 256) {
    return new Response('Invalid state', { status: 400 });
  }
  if (!codeChallenge || !codeChallengeMethod) {
    return new Response('Missing PKCE parameters', { status: 400 });
  }

  const authUrl = new URL('https://auth.hackclub.com/oauth/authorize');
  authUrl.searchParams.set('client_id', clientId);
  authUrl.searchParams.set('redirect_uri', allowedRedirect);
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('scope', 'openid profile email');
  authUrl.searchParams.set('state', state);
  authUrl.searchParams.set('code_challenge', codeChallenge);
  authUrl.searchParams.set('code_challenge_method', codeChallengeMethod);

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      'Cache-Control': 'no-store',
      'Content-Security-Policy': "default-src 'none'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer',
    },
  });
}
