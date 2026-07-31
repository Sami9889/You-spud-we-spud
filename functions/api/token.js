export const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type",
};

export async function onRequestPost(context) {
  const { env } = context;

  if (!env.API_HC) {
    return new Response(
      JSON.stringify({ error: "Server misconfigured", detail: "API_HC missing" }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }

  let body;
  try {
    body = await context.request.json();
  } catch {
    return new Response(
      JSON.stringify({ error: "Invalid JSON body" }),
      { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }

  const { code, redirect_uri } = body || {};

  if (!code) {
    return new Response(
      JSON.stringify({ error: "Missing authorization code" }),
      { status: 400, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }

  const params = new URLSearchParams({
    grant_type:    "authorization_code",
    client_id:     "e63922a40cd5f15e2d772276dcba8404",
    client_secret: env.API_HC,
    redirect_uri:  redirect_uri || "https://youspudwespud.sami-s.dev/form/",
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
      return new Response(JSON.stringify(tok), {
        status: hcRes.status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    const meRes = await fetch("https://auth.hackclub.com/oauth/userinfo", {
      headers: { Authorization: `Bearer ${tok.access_token}` },
    });

    const user = await meRes.json();
    if (!meRes.ok) {
      return new Response(JSON.stringify(user), {
        status: meRes.status,
        headers: { "Content-Type": "application/json", ...corsHeaders },
      });
    }

    return new Response(JSON.stringify({ token: tok, user }), {
      status: 200,
      headers: { "Content-Type": "application/json", ...corsHeaders },
    });
  } catch (err) {
    return new Response(
      JSON.stringify({ error: "Token exchange failed", detail: err.message }),
      { status: 500, headers: { "Content-Type": "application/json", ...corsHeaders } }
    );
  }
}

export async function onRequestOptions() {
  return new Response(null, {
    status: 204,
    headers: corsHeaders,
  });
}
