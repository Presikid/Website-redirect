const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

function randomCode(length = 3) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  let out = '';
  for (const b of bytes) out += ALPHABET[b % ALPHABET.length];
  return out;
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const cors = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type'
    };

    if (request.method === 'OPTIONS') return new Response(null, { headers: cors });

    if (request.method === 'GET' && url.pathname === '/') {
      return fetch('https://presikid.github.io/Website-redirect/');
    }

    if (request.method === 'POST' && url.pathname === '/create') {
      const body = await request.json();
      const target = body.url;
      const duration = body.duration || 'permanent';

      if (!target) {
        return Response.json({ error: 'Missing url' }, { status: 400, headers: cors });
      }

      const old = await env.DB
        .prepare('SELECT code, expires_at FROM links WHERE target_url = ?')
        .bind(target)
        .first();

      if (old) {
        return Response.json({
          code: old.code,
          url: url.origin + '/' + old.code,
          existing: true,
          expires_at: old.expires_at || null
        }, { headers: cors });
      }

      let expiresAt = null;
      const ms = {
        m1: 60000,
        m5: 300000,
        m10: 600000,
        h1: 3600000,
        h5: 18000000,
        d1: 86400000,
        w1: 604800000,
        mo1: 2592000000,
        y1: 31536000000
      };
      if (ms[duration]) expiresAt = new Date(Date.now() + ms[duration]).toISOString();

      let code;
      let created = false;
      let attempts = 0;

      while (!created && attempts < 100) {
        attempts++;
        code = randomCode(3);
        try {
          await env.DB
            .prepare('INSERT INTO links (code,target_url,expires_at) VALUES (?,?,?)')
            .bind(code, target, expiresAt)
            .run();
          created = true;
        } catch (e) {
          // Collision on UNIQUE(code): generate another code.
        }
      }

      if (!created) {
        return Response.json(
          { error: 'Unable to allocate a short code. Please try again.' },
          { status: 503, headers: cors }
        );
      }

      return Response.json({
        code,
        url: url.origin + '/' + code,
        existing: false,
        expires_at: expiresAt
      }, { headers: cors });
    }

    if (request.method === 'GET' && url.pathname.startsWith('/info/')) {
      const code = url.pathname.slice(6);
      const row = await env.DB
        .prepare('SELECT code,target_url,created_at,visits,expires_at FROM links WHERE code=?')
        .bind(code)
        .first();

      if (!row) {
        return Response.json({ error: 'Not found' }, { status: 404, headers: cors });
      }
      return Response.json(row, { headers: cors });
    }

    const code = url.pathname.slice(1);
    if (!code) return new Response('Website Redirect');

    const row = await env.DB
      .prepare('SELECT target_url,expires_at FROM links WHERE code=?')
      .bind(code)
      .first();

    if (!row) return new Response('Not found', { status: 404 });

    if (row.expires_at && new Date(row.expires_at) < new Date()) {
      return new Response('Link expired', { status: 410 });
    }

    await env.DB
      .prepare('UPDATE links SET visits=visits+1 WHERE code=?')
      .bind(code)
      .run();

    return Response.redirect(row.target_url, 302);
  }
};
