// Website Redirect - Short Link Backend
// Deploy this file as a Cloudflare Worker after creating a D1 database.

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
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
