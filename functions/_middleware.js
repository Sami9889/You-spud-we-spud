export async function onRequest(context) {
  const url = new URL(context.request.url);

  if (!url.pathname.startsWith('/admin')) {
    return context.next();
  }

  const publicPaths = ['/api/admin/login', '/api/admin/logout', '/api/admin/migrate', '/admin', '/admin/', '/admin/index.html'];
  if (publicPaths.includes(url.pathname)) {
    return context.next();
  }

  const cookieHeader = context.request.headers.get('Cookie') || '';
  const match = cookieHeader.match(/admin_token=([^;]+)/);
  if (!match) {
    return new Response('Access denied', {
      status: 403,
      headers: {
        'content-type': 'text/plain',
        'cache-control': 'no-store',
      },
    });
  }

  const token = decodeURIComponent(match[1]);
  const expected = await context.env.ORDERS.get('admin_api_token', 'text');
  if (!expected || expected !== token) {
    return new Response('Access denied', {
      status: 403,
      headers: {
        'content-type': 'text/plain',
        'cache-control': 'no-store',
      },
    });
  }

  return context.next();
}
