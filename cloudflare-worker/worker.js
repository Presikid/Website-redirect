// Website Redirect - Short Link Backend
// Cloudflare Worker + D1 backend

function generateCode(length = 6) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let code = '';
  for (let i = 0; i < length; i++) {
    code += chars[Math.floor(Math.random() * chars.length)];
  }
  return code;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    // Create short link API
    if (request.method === 'POST' && url.pathname === '/create') {
      const body = await request.json();
      const target = body.url;

      if (!target) {
        return new Response(JSON.stringify({ error: 'Missing URL' }), {
          status: 400,
          headers: { 'Content-Type': 'application/json' }
        });
      }

      const code = generateCode();

      await env.DB.prepare(
        'INSERT INTO links (code, target_url) VALUES (?, ?)'
      ).bind(code, target).run();

      return new Response(JSON.stringify({
        short: `${url.origin}/${code}`
      }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Redirect short link
    const code = url.pathname.slice(1);

    if (!code) {
      return new Response('Short link service is running.');
    }

    const result = await env.DB.prepare(
      'SELECT target_url FROM links WHERE code = ?'
    ).bind(code).first();

    if (!result) {
      return new Response('Short link not found.', { status: 404 });
    }

    return Response.redirect(result.target_url, 302);
  }
};
