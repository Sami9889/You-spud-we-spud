exports.handler = async (event, context) => {
  if (event.httpMethod !== "POST") {
    return {
      statusCode: 405,
      body: JSON.stringify({ error: "Method not allowed" }),
    };
  }

  let body;
  try {
    body = JSON.parse(event.body || "{}");
  } catch (e) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Invalid JSON body" }),
    };
  }

  const { code, redirect_uri } = body;

  if (!code) {
    return {
      statusCode: 400,
      body: JSON.stringify({ error: "Missing authorization code" }),
    };
  }

  const params = new URLSearchParams({
    grant_type: "authorization_code",
    client_id: "e63922a40cd5f15e2d772276dcba8404",
    client_secret: process.env.API_HC,
    redirect_uri: redirect_uri || "https://youspudwespud.sami-s.dev/form/",
    code,
  });

  try {
    const hcRes = await fetch("https://auth.hackclub.com/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });

    const tok = await hcRes.json();

    if (!hcRes.ok) {
      return {
        statusCode: hcRes.status,
        body: JSON.stringify(tok),
      };
    }

    const meRes = await fetch("https://auth.hackclub.com/api/v1/me", {
      headers: { Authorization: "Bearer " + tok.access_token },
    });

    const user = await meRes.json();

    if (!meRes.ok) {
      return {
        statusCode: meRes.status,
        body: JSON.stringify(user),
      };
    }

    return {
      statusCode: 200,
      body: JSON.stringify({ token: tok, user: user }),
    };
  } catch (err) {
    return {
      statusCode: 500,
      body: JSON.stringify({ error: "Token exchange failed", detail: err.message }),
    };
  }
};
