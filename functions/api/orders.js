const KV_PREFIX = "order:";
const MAX_KEYS = 1000;
const RATE_PREFIX = "rate:";
const RATE_LIMIT = 10;
const RATE_WINDOW_SEC = 60 * 60;

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
    deadline: sanitizeString(order.deadline),
    shipping_id: sanitizeString(order.shipping_id),
    shipping_status: sanitizeString(order.shipping_status),
    cancelled: Boolean(order.cancelled),
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

async function findOrderKey(env, orderId) {
  const list = await env.ORDERS.list({ limit: MAX_KEYS, prefix: KV_PREFIX });
  for (const key of list.keys) {
    const raw = await env.ORDERS.get(key.name, "json");
    if (raw && raw._id === orderId) {
      return key.name;
    }
  }
  return null;
}

function clientIp(request) {
  return (
    request.headers.get("CF-Connecting-IP") ||
    request.headers.get("X-Forwarded-For") ||
    "unknown"
  );
}

async function checkRateLimit(env, ip) {
  if (!ip || ip === "unknown") return true;
  const key = `${RATE_PREFIX}${ip}`;
  const count = await env.ORDERS.get(key, "text");
  if (count && Number(count) >= RATE_LIMIT) {
    return false;
  }
  return true;
}

async function recordRateLimit(env, ip) {
  if (!ip || ip === "unknown") return;
  const key = `${RATE_PREFIX}${ip}`;
  try {
    await env.ORDERS.put(key, String(Number((await env.ORDERS.get(key, "text")) || 0) + 1), {
      expirationTtl: RATE_WINDOW_SEC,
    });
  } catch (err) {}
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
  const ip = clientIp(context.request);

  if (!(await checkRateLimit(context.env, ip))) {
    return new Response(JSON.stringify({ error: "Too many submissions. Please try again later." }), {
      status: 429,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
        "retry-after": String(RATE_WINDOW_SEC),
      },
    });
  }

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

  await recordRateLimit(context.env, ip);

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

export async function onRequestPatch(context) {
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

  const orderId = sanitizeString(payload.id);
  if (!orderId) {
    return new Response(JSON.stringify({ error: "Missing order id." }), {
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

  const key = await findOrderKey(context.env, orderId);
  if (!key) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const raw = await context.env.ORDERS.get(key, "json");
  if (!raw) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const allowed = ["cancelled", "shipping_id", "shipping_status", "deadline"];
  const updates = {};
  for (const field of allowed) {
    if (payload[field] !== undefined) {
      updates[field] = sanitizeString(String(payload[field]));
    }
  }

  const updated = { ...raw, ...updates, _ts: new Date().toISOString() };
  await context.env.ORDERS.put(key, JSON.stringify(updated));

  return new Response(JSON.stringify({ ok: true, order: updated }), {
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

export async function onRequestDelete(context) {
  let payload = {};
  try {
    payload = await context.request.json();
  } catch {
    payload = {};
  }

  const orderId = sanitizeString(payload.id);
  if (!orderId) {
    return new Response(JSON.stringify({ error: "Missing order id." }), {
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

  const key = await findOrderKey(context.env, orderId);
  if (!key) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const raw = await context.env.ORDERS.get(key, "json");
  if (!raw) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  if (!raw.cancelled) {
    return new Response(JSON.stringify({ error: "Only cancelled orders can be deleted." }), {
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

  await context.env.ORDERS.delete(key);

  return new Response(JSON.stringify({ ok: true }), {
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
