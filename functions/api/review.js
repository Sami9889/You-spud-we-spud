const KV_PREFIX = "order:";
const MAX_KEYS = 1000;
const RULES_KEY = "rules";

function sanitizeString(value) {
  if (typeof value !== "string") return "";
  return value.replace(/[\x00-\x1f\x7f]/g, "").slice(0, 5000);
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

async function isAdminRequest(context) {
  const auth = context.request.headers.get("Authorization") || "";
  if (!auth.startsWith("Bearer ")) return false;
  const token = auth.slice(7).trim();
  if (!token) return false;
  const expected = await context.env.ORDERS.get("admin_api_token", "text");
  return expected === token;
}

async function getRules(env) {
  try {
    const raw = await env.ORDERS.get(RULES_KEY, "text");
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (e) {
    return {};
  }
}

function validateTier(order, rules) {
  const tier = order.tier || "";
  const size = parseFloat(order.file_size_kb) || 0;
  for (const t of rules.tiers || []) {
    if (tier === t.label || tier === t.id) {
      return { pass: size < t.max_size_kb, actual: size, limit: t.max_size_kb, tier: t.label || tier };
    }
  }
  return { pass: false, actual: size, limit: 0, tier: tier || "unknown" };
}

function validateRequiredFields(order, rules) {
  const missing = [];
  const all = [];
  if (rules.required_fields) {
    for (const group of Object.values(rules.required_fields)) {
      if (Array.isArray(group)) all.push(...group);
    }
  }
  for (const field of all) {
    if (!order[field] || !String(order[field]).trim()) {
      missing.push(field);
    }
  }
  return { pass: missing.length === 0, missing };
}

function validateUrls(order, rules) {
  const issues = [];
  const urls = [order.project_url, order.source_url].filter(Boolean);
  for (const url of urls) {
    if (!/^https?:\/\//i.test(url)) {
      issues.push("Non-HTTPS URL");
    }
  }
  if (rules.url_rules?.github_repo_pattern && order.source_url) {
    const re = new RegExp(rules.url_rules.github_repo_pattern);
    if (!re.test(order.source_url)) {
      issues.push("Source URL doesn't match GitHub repo pattern");
    }
  }
  return { pass: issues.length === 0, issues };
}

export async function onRequestGet(context) {
  if (!(await isAdminRequest(context))) {
    return new Response(JSON.stringify({ error: "Unauthorized." }), {
      status: 401,
      headers: securityHeaders(),
    });
  }

  const url = new URL(context.request.url);
  const orderId = url.searchParams.get("id");

  if (!orderId) {
    return new Response(JSON.stringify({ error: "Missing order id." }), {
      status: 400,
      headers: securityHeaders(),
    });
  }

  const list = await context.env.ORDERS.list({ limit: MAX_KEYS, prefix: KV_PREFIX });
  let order = null;
  for (const key of list.keys) {
    const raw = await context.env.ORDERS.get(key.name, "json");
    if (raw && raw._id === orderId) {
      order = raw;
      break;
    }
  }

  if (!order) {
    return new Response(JSON.stringify({ error: "Order not found." }), {
      status: 404,
      headers: securityHeaders(),
    });
  }

  const rules = await getRules(context.env);
  const tierCheck = validateTier(order, rules);
  const fieldsCheck = validateRequiredFields(order, rules);
  const urlCheck = validateUrls(order, rules);

  const orderForReview = {
    _id: order._id,
    project_name: order.project_name,
    project_url: order.project_url,
    source_url: order.source_url,
    file_size_kb: order.file_size_kb,
    description: order.description,
    tier: order.tier,
    hc_name: order.hc_name,
    hc_email: order.hc_email,
    hc_verified: order.hc_verified,
    deadline: order.deadline,
    accepted: order.accepted,
  };

  return new Response(JSON.stringify({
    ok: true,
    order_id: orderId,
    review: {
      passed: tierCheck.pass && fieldsCheck.pass && urlCheck.pass,
      tier: tierCheck,
      fields: fieldsCheck,
      urls: urlCheck,
    },
    order: orderForReview,
  }), {
    status: 200,
    headers: securityHeaders(),
  });
}
