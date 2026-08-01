const KV_PREFIX = "order:";
const MAX_KEYS = 1000;
<<<<<<< ours
const ADMIN_TOKEN = "__ADMIN_ORDER_TOKEN__";

if (!ADMIN_TOKEN || ADMIN_TOKEN === "__ADMIN_ORDER_TOKEN__") {
  throw new Error("ADMIN_ORDER_TOKEN must be configured");
}
=======
>>>>>>> theirs

function sanitizeString(value) {
  if (typeof value !== "string") return "";
  return value.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 5000);
}

function validateOrder(payload) {
  if (!payload || typeof payload !== "object") {
    return { ok: false, error: "Invalid payload." };
  }

  const required = [
    "project_name", "project_url", "source_url", "file_size_kb",
    "description", "tier", "ship_name", "phone",
    "ship_line1", "ship_city", "ship_country", "ship_postal"
  ];

  for (const field of required) {
    if (!payload[field] || typeof payload[field] !== "string" || !payload[field].trim()) {
      return { ok: false, error: `Missing required field: ${field}.` };
    }
  }

  return { ok: true };
}

function serializeOrder(order) {
  return {
    _id: order._id || crypto.randomUUID(),
    _ts: order._ts || new Date().toISOString(),
    timestamp: sanitizeString(order.timestamp),
    hc_name: sanitizeString(order.hc_name),
    hc_email: sanitizeString(order.hc_email),
    hc_slack_id: sanitizeString(order.hc_slack_id),
    hc_verified: sanitizeString(order.hc_verified),
    hc_username: sanitizeString(order.hc_username),
    project_name: sanitizeString(order.project_name),
    project_url: sanitizeString(order.project_url),
    source_url: sanitizeString(order.source_url),
    file_size_kb: sanitizeString(order.file_size_kb),
    description: sanitizeString(order.description),
    tier: sanitizeString(order.tier),
    phone: sanitizeString(order.phone),
    ship_name: sanitizeString(order.ship_name),
    ship_line1: sanitizeString(order.ship_line1),
    ship_line2: sanitizeString(order.ship_line2),
    ship_city: sanitizeString(order.ship_city),
    ship_state: sanitizeString(order.ship_state),
    ship_country: sanitizeString(order.ship_country),
    ship_postal: sanitizeString(order.ship_postal),
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

<<<<<<< ours
function checkAdminAuth(request) {
  const auth = request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7).trim();
  return token === ADMIN_TOKEN;
}

export async function onRequestGet(context) {
  if (!checkAdminAuth(context.request)) {
    return new Response(JSON.stringify({ error: "Unauthorized." }), {
      status: 401,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

=======
export async function onRequestGet(context) {
>>>>>>> theirs
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
    return new Response(JSON.stringify({ error: "Invalid JSON payload." }), {
      status: 400,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const validation = validateOrder(payload);
  if (!validation.ok) {
    return new Response(JSON.stringify(validation), {
      status: 422,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
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
