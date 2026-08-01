export async function onRequestPost(context) {
  const body = await context.request.text();
  const upstream = 'https://auth.hackclub.com/oauth/token';

  const response = await fetch(upstream, {
    method: 'POST',
    headers: {
      'content-type': 'application/x-www-form-urlencoded',
      'accept': 'application/json',
    },
    body,
  });

  const text = await response.text();
  return new Response(text, {
    status: response.status,
    headers: {
      'content-type': 'application/json; charset=utf-8',
      'access-control-allow-origin': '*',
    },
  });
}
