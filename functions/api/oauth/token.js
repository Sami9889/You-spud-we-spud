export async function onRequestPost(context) {
  const bodyText = await context.request.text();
  const upstream = 'https://auth.hackclub.com/oauth/token';
  const params = new URLSearchParams(bodyText);
  const clientId = context.env?.HACKCLUB_CLIENT_ID || context.env?.CLIENT_ID || params.get('client_id') || 'e63922a40cd5f15e2d772276dcba8404';
  const clientSecret = context.env?.HACKCLUB_CLIENT_SECRET || context.env?.CLIENT_SECRET;

  params.set('client_id', clientId);
  if (clientSecret) {
    params.set('client_secret', clientSecret);
  }

  const headers = {
    'content-type': 'application/x-www-form-urlencoded',
    'accept': 'application/json',
    'user-agent': 'you-spud-we-spud/1.0',
  };

  if (clientSecret) {
    headers.authorization = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
  }

  const response = await fetch(upstream, {
    method: 'POST',
    headers,
    body: params.toString(),
  });

  const text = await response.text();
  return new Response(text, {
    status: response.status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': 'https://youspudwespud.sami-s.dev',
      'access-control-allow-headers': 'content-type, authorization',
      'access-control-allow-methods': 'POST, OPTIONS',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}
