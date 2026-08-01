export async function onRequestGet(context) {
  const auth = context.request.headers.get('authorization');
  if (!auth || !auth.startsWith('Bearer ')) {
    return new Response(JSON.stringify({ error: 'missing authorization header' }), {
      status: 401,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'cache-control': 'no-store',
        'access-control-allow-origin': 'https://youspudwespud.sami-s.dev',
        'access-control-allow-headers': 'authorization',
        'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
        'x-content-type-options': 'nosniff',
        'referrer-policy': 'no-referrer',
      },
    });
  }

  const response = await fetch('https://auth.hackclub.com/oauth/userinfo', {
    headers: {
      authorization: auth,
      accept: 'application/json',
      'user-agent': 'you-spud-we-spud/1.0',
    },
  });

  const text = await response.text();
  return new Response(text, {
    status: response.status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'access-control-allow-origin': 'https://youspudwespud.sami-s.dev',
      'access-control-allow-headers': 'authorization',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
    },
  });
}
