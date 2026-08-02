export async function onRequestPost(context) {
  await context.env.ORDERS.delete('admin_api_token');

  const isSecure = new URL(context.request.url).protocol === 'https:';
  const cookieAttributes = [
    'admin_token=',
    'Path=/',
    'Max-Age=0',
    'HttpOnly',
    'SameSite=Strict',
    isSecure ? 'Secure' : '',
  ].filter(Boolean).join('; ');

  return new Response(JSON.stringify({ ok: true }), {
    status: 200,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'cache-control': 'no-store',
      'content-security-policy': "default-src 'none'; frame-ancestors 'none'",
      'x-content-type-options': 'nosniff',
      'referrer-policy': 'no-referrer',
      'Set-Cookie': cookieAttributes,
    },
  });
}
