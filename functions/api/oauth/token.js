export async function onRequestPost(context) {
  const body = await context.request.text();
  const upstream = 'https://auth.hackclub.com/oauth/token';

  const response = await fetch(upstream, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
      'user-agent': 'you-spud-we-spud/1.0',
    },
    body,
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
