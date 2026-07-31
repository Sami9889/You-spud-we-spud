const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

const CODE_LENGTH_MAX = 2000;
const REDIRECT_URI = "https://youspudwespud.sami-s.dev/form/";

function json(status, body, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...CORS_HEADERS,
      ...headers,
    },
  });
}

export default {
  async fetch(request, env, ctx) {
    if (request.method === "OPTIONS") {
      return new Response(null, { status: 204, headers: CORS_HEADERS });
    }

    if (request.method !== "POST") {
      return json(405, { error: "Method not allowed" });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return json(400, { error: "Invalid JSON body" });
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json(400, { error: "Invalid request body" });
    }

    const { code, redirect_uri } = body;

    if (!code || typeof code !== "string" || code.length > CODE_LENGTH_MAX) {
      return json(400, { error: "Missing or invalid authorization code" });
    }

    const params = new URLSearchParams({
      grant_type: "authorization_code",
      client_id: "e63922a40cd5f15e2d772276dcba8404",
      client_secret: env.API_HC,
      redirect_uri: redirect_uri || REDIRECT_URI,
      code,
    });

    const basicAuth = btoa("e63922a40cd5f15e2d772276dcba8404:" + env.API_HC);

    let hcRes;
    try {
      hcRes = await fetch("https://auth.hackclub.com/oauth/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "Authorization": "Basic " + basicAuth,
        },
        body: params.toString(),
      });
    } catch {
      return json(502, { error: "Token endpoint unreachable" });
    }

    let tok;
    try {
      tok = await hcRes.json();
    } catch {
      tok = {};
    }

    if (!hcRes.ok) {
      const message = tok.error_description || tok.error || "Token exchange failed";
      return json(hcRes.status, { error: message });
    }

    let meRes;
    try {
      meRes = await fetch("https://auth.hackclub.com/oauth/userinfo", {
        headers: { Authorization: `Bearer ${tok.access_token}` },
      });
    } catch {
      return json(502, { error: "User info endpoint unreachable" });
    }

    let user;
    try {
      user = await meRes.json();
    } catch {
      user = {};
    }

    if (!meRes.ok) {
      const message = user.error || "Failed to fetch user info";
      return json(meRes.status, { error: message });
    }

    return json(200, { token: tok, user });
  }
};
