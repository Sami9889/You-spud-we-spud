export async function onRequestGet(context) {
  const auth = context.request.headers.get('authorization');
  if (!auth) {
    return new Response(JSON.stringify({ error: 'missing authorization header' }), {
      status: 401,
      headers: {
        'content-type': 'application/json; charset=utf-8',
        'access-control-allow-origin': '*',
      },
    });
  }

  const response = await fetch('https://auth.hackclub.com/oauth/userinfo', {
    headers: {
      authorization: auth,
      accept: 'application/json',
    },
  });

  const text = await response.text();
  return new Response(text, {
    status: response.status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}
