async function isAdminRequest(context) {
  const auth = context.request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;

  const token = auth.slice(7).trim();
  if (!token) return false;

  const expected = await context.env.ORDERS.get("admin_api_token", "text");
  return expected === token;
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

export async function onRequestPost(context) {
  if (!(await isAdminRequest(context))) {
    return new Response(JSON.stringify({ error: "Unauthorized." }), {
      status: 401,
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
