const DEFAULT_CREDENTIALS = "__ADMIN_CREDENTIALS__";

if (DEFAULT_CREDENTIALS === "__ADMIN_CREDENTIALS__") {
  throw new Error("ADMIN_CREDENTIALS must be injected at build time");
}

export function parseAdminCredentials(rawValue = "") {
  if (!rawValue) {
    return [];
  }

  return rawValue
    .replace(/\r/g, "")
    .split(/[\n,;|]+/)
    .map(entry => entry.trim())
    .filter(Boolean)
    .map(entry => {
      const parts = entry.split("=").map(part => part.trim());
      if (parts.length < 3) {
        return null;
      }
      const username = parts[0];
      const email = parts[1];
      const password = parts.slice(2).join("=").trim();
      if (!username || !email || !password) {
        return null;
      }
      return { username, email, password };
    })
    .filter(Boolean);
}

export function matchesAdminCredential(rawValue, username, email, password) {
  const normalizedUsername = String(username || "").trim().toLowerCase();
  const normalizedEmail = String(email || "").trim().toLowerCase();
  const normalizedPassword = String(password || "").trim();

  return parseAdminCredentials(rawValue).some(entry => {
    return (
      entry.username.toLowerCase() === normalizedUsername &&
      entry.email.toLowerCase() === normalizedEmail &&
      entry.password === normalizedPassword
    );
  });
}

export async function onRequestPost(context) {
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

  const rawCredentials = context.env?.ADMIN_CREDENTIALS || DEFAULT_CREDENTIALS;
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

  return new Response(JSON.stringify({ ok: true, user: { name: username, email } }), {
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
