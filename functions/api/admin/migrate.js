async function isAdminRequest(context) {
  const auth = context.request.headers.get("Authorization") || "";
  if (auth.startsWith("Bearer ")) {
    const token = auth.slice(7).trim();
    if (token) {
      const expected = await context.env.ORDERS.get("admin_api_token", "text");
      if (expected === token) return true;
    }
  }

  const cookieHeader = context.request.headers.get("Cookie") || "";
  const match = cookieHeader.match(/admin_token=([^;]+)/);
  if (match) {
    const token = decodeURIComponent(match[1]);
    const expected = await context.env.ORDERS.get("admin_api_token", "text");
    if (expected && expected === token) return true;
  }

  return false;
}

function isSameOrigin(request) {
  const origin = request.headers.get("Origin");
  if (origin) {
    const url = new URL(request.url);
    return origin === `${url.protocol}//${url.host}`;
  }

  const host = request.headers.get("Host");
  if (!host) return false;
  const url = new URL(request.url);
  return host === url.host;
}

function securityHeaders(extra = {}) {
  return {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
    "x-content-type-options": "nosniff",
    "referrer-policy": "no-referrer",
    ...extra,
  };
}

export async function onRequest(context) {
  if (!(await isAdminRequest(context))) {
    return new Response(JSON.stringify({ error: "Unauthorized." }), {
      status: 401,
      headers: securityHeaders(),
    });
  }

  if (!isSameOrigin(context.request)) {
    return new Response(JSON.stringify({ error: "Invalid origin." }), {
      status: 403,
      headers: securityHeaders(),
    });
  }

  if (context.request.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed." }), {
      status: 405,
      headers: securityHeaders(),
    });
  }

  const list = await context.env.ORDERS.list({ limit: 1000, prefix: "order:" });
  let migrated = 0;
  for (const key of list.keys) {
    const raw = await context.env.ORDERS.get(key.name, "json");
    if (raw) {
      await context.env.ORDERS.put(key.name, JSON.stringify(raw));
      migrated++;
    }
  }

  return new Response(JSON.stringify({ ok: true, migrated }), {
    status: 200,
    headers: securityHeaders(),
  });
}
