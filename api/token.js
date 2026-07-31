module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return res.status(405).json({ error: "Method not allowed" });
  }

  const { code, redirect_uri } = req.body || {};

  if (!code) {
    return res.status(400).json({ error: "Missing authorization code" });
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
      return res.status(hcRes.status).json(tok);
    }

    const meRes = await fetch("https://auth.hackclub.com/api/v1/me", {
      headers: { Authorization: "Bearer " + tok.access_token },
    });

    const user = await meRes.json();

    if (!meRes.ok) {
      return res.status(meRes.status).json(user);
    }

    return res.status(200).json({ token: tok, user: user });
  } catch (err) {
    return res.status(500).json({ error: "Token exchange failed", detail: err.message });
  }
};
