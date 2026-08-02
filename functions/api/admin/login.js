export function parseAdminCredentials(rawValue = "") {
  if (!rawValue) {
    return [];
  }

  const trimmed = String(rawValue).trim();
  if (!trimmed) {
    return [];
  }

  const entries = trimmed.split(/[\n,;|]+/).map(entry => entry.trim()).filter(Boolean);
  const parsed = [];

  for (const entry of entries) {
    if (!entry) continue;

    const parts = entry.split("=").map(part => part.trim());
    if (parts.length < 3) continue;

    const username = parts[0];
    const email = parts[1];
    const password = parts.slice(2).join("=").trim();

    if (!username || !email || !password) continue;

    parsed.push({ username, email, password });
  }

  return parsed;
}

export function matchesAdminCredential(rawValue, username, email, password) {
  const normalizedUsername = String(username || "").trim().toLowerCase();
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const normalizedPassword = String(password || "").trim();

  if (!normalizedUsername || !normalizedEmail || !normalizedPassword) {
    return false;
  }

  return parseAdminCredentials(rawValue).some(entry => {
    return (
      entry.username.toLowerCase() === normalizedUsername &&
      entry.email.toLowerCase() === normalizedEmail &&
      entry.password === normalizedPassword
    );
  });
}

export async function onRequestPost(context) {
  const origin = context.request.headers.get("Origin");
  if (origin) {
    const url = new URL(context.request.url);
    const allowedOrigin = `${url.protocol}//${url.host}`;
    if (origin !== allowedOrigin) {
      return new Response(JSON.stringify({ ok: false, error: "Invalid origin." }), {
        status: 403,
        headers: {
          "content-type": "application/json; charset=utf-8",
          "cache-control": "no-store",
          "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
          "x-content-type-options": "nosniff",
          "referrer-policy": "no-referrer",
        },
      });
    }
  }

  let payload = {};
  const bodyText = await context.request.text();

  try {
    payload = JSON.parse(bodyText);
  } catch (err) {
    try {
      payload = Object.fromEntries(new URLSearchParams(bodyText));
    } catch (parseErr) {
      payload = {};
    }
  }

  const username = String(payload.username || "").trim();
  const email = String(payload.email || "").trim();
  const password = String(payload.password || "").trim();

  const rawCredentials = context.env?.ADMIN_CREDENTIALS;
  const parsedCount = parseAdminCredentials(rawCredentials).length;

  if (!rawCredentials) {
    return new Response(JSON.stringify({ ok: false, error: "Admin credentials are not configured on the server." }), {
      status: 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  if (parsedCount === 0) {
    return new Response(JSON.stringify({ ok: false, error: "Admin credentials are set, but no valid credential entries were parsed." }), {
      status: 500,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const isAuthorized = matchesAdminCredential(rawCredentials, username, email, password);

  if (!isAuthorized) {
    return new Response(JSON.stringify({ ok: false, error: "Invalid admin credentials." }), {
      status: 403,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "cache-control": "no-store",
        "content-security-policy": "default-src 'none'; frame-ancestors 'none'",
        "x-content-type-options": "nosniff",
        "referrer-policy": "no-referrer",
      },
    });
  }

  const adminApiToken = crypto.randomUUID();
  await context.env.ORDERS.put("admin_api_token", adminApiToken, {
    expirationTtl: 60 * 60 * 24 * 30,
  });

  const isSecure = new URL(context.request.url).protocol === 'https:';
  const cookieAttributes = [
    `admin_token=${adminApiToken}`,
    'Path=/',
    'Max-Age=2592000',
    'HttpOnly',
    'SameSite=Strict',
    isSecure ? 'Secure' : '',
  ].filter(Boolean).join('; ');

  return new Response(JSON.stringify({ ok: true, user: { name: username, email }, adminApiToken }), {
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
