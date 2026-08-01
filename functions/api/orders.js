const KV_PREFIX = "order:";
const MAX_KEYS = 1000;

function serializeOrder(order) {
  return {
    _id: order._id || crypto.randomUUID(),
    _ts: order._ts || new Date().toISOString(),
    ...order,
  };
}

async function listOrders(env) {
  const list = await env.ORDERS.list({ limit: MAX_KEYS, prefix: KV_PREFIX });
  const orders = [];
  for (const key of list.keys) {
    const raw = await env.ORDERS.get(key.name, "json");
    if (raw) orders.push(raw);
  }
  orders.sort((a, b) => (b.timestamp || b._ts || "").localeCompare(a.timestamp || a._ts || ""));
  return orders;
}

export async function onRequestGet(context) {
  const orders = await listOrders(context.env);
  return new Response(JSON.stringify(orders), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}

export async function onRequestPost(context) {
  let payload = {};
  try {
    payload = await context.request.json();
  } catch {
    payload = {};
  }

  const order = serializeOrder(payload);
  const key = `${KV_PREFIX}${Date.now()}:${crypto.randomUUID()}`;
  await context.env.ORDERS.put(key, JSON.stringify(order), {
    expirationTtl: 60 * 60 * 24 * 365,
  });

  return new Response(JSON.stringify({ ok: true, id: order._id }), {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
      "x-content-type-options": "nosniff",
      "referrer-policy": "no-referrer",
    },
  });
}
