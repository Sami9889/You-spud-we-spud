export async function onRequestGet(context) {
  const url = new URL(context.request.url);
  const params = new URLSearchParams(url.search);
  const redirectUri = params.get('redirect_uri');
  const clientId = params.get('client_id');
  const state = params.get('state');
  const codeChallenge = params.get('code_challenge');
  const codeChallengeMethod = params.get('code_challenge_method');

  const authUrl = new URL('https://auth.hackclub.com/oauth/authorize');
  authUrl.searchParams.set('client_id', clientId || '');
  authUrl.searchParams.set('redirect_uri', redirectUri || '');
  authUrl.searchParams.set('response_type', 'code');
  authUrl.searchParams.set('state', state || '');
  authUrl.searchParams.set('code_challenge', codeChallenge || '');
  authUrl.searchParams.set('code_challenge_method', codeChallengeMethod || 'S256');

  return Response.redirect(authUrl.toString(), 302);
}
