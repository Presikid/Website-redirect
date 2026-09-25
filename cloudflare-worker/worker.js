const ALPHABET = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';
const ADMIN_SESSION_SECONDS = 1800;
const ADMIN_MAX_FAILURES = 5;
const ADMIN_BLOCK_SECONDS = 600;

function randomCode(length = 3) {
  let out = '';
  for (let i = 0; i < length; i++) {
    const bytes = new Uint8Array(1);
    let x;
    do {
      crypto.getRandomValues(bytes);
      x = bytes[0];
    } while (x >= 248);
    out += ALPHABET[x % 62];
  }
  return out;
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function bytesToHex(bytes) {
  return Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
}

function constantTimeEqualHex(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function hmacHex(secretHex, message) {
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(secretHex),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(message));
  return bytesToHex(new Uint8Array(sig));
}

function getCookie(request, name) {
  const cookie = request.headers.get('Cookie') || '';
  for (const part of cookie.split(';')) {
    const [k, ...rest] = part.trim().split('=');
    if (k === name) return rest.join('=');
  }
  return null;
}

async function getAdminConfig(env) {
  return env.DB.prepare(
    'SELECT password_salt,password_hash,session_secret FROM admin_config WHERE id=1'
  ).first();
}

async function verifyAdmin(request, env) {
  const token = getCookie(request, 'admin_session');
  if (!token) return false;
  const dot = token.indexOf('.');
  if (dot <= 0) return false;
  const expText = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const exp = Number(expText);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isFinite(exp) || exp <= now || exp > now + ADMIN_SESSION_SECONDS + 60) return false;
  const cfg = await getAdminConfig(env);
  if (!cfg) return false;
  const expected = await hmacHex(cfg.session_secret, 'admin:' + expText);
  return constantTimeEqualHex(sig, expected);
}

function adminCookie(exp, sig) {
  return [
    'admin_session=' + exp + '.' + sig,
    'Path=/control',
    'Max-Age=' + ADMIN_SESSION_SECONDS,
    'HttpOnly',
    'Secure',
    'SameSite=Strict'
  ].join('; ');
}

function clearAdminCookie() {
  return 'admin_session=; Path=/control; Max-Age=0; HttpOnly; Secure; SameSite=Strict';
}

function adminHeaders(extra = {}) {
  return {
    'Cache-Control': 'no-store, max-age=0',
    'Pragma': 'no-cache',
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    ...extra
  };
}

function adminJson(data, init = {}) {
  const headers = adminHeaders({ 'Content-Type': 'application/json; charset=utf-8', ...(init.headers || {}) });
  return new Response(JSON.stringify(data), { ...init, headers });
}

const CONTROL_HTML = String.raw`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Website Redirect Control</title>
<style>
:root{color-scheme:dark}*{box-sizing:border-box}body{margin:0;min-height:100vh;font-family:Arial,sans-serif;background:#0b1220;color:#eef4ff}.shell{width:min(1100px,94vw);margin:48px auto}.card{background:#121c2e;border:1px solid #263650;border-radius:16px;padding:24px;box-shadow:0 12px 40px #0005}.login{width:min(440px,94vw);margin:12vh auto}.muted{color:#9fb0c8}.row{display:flex;gap:10px;align-items:center;flex-wrap:wrap}input,button{border:0;border-radius:10px;padding:12px 14px;font-size:15px}input{background:#0c1525;color:#fff;border:1px solid #2d405e;flex:1;min-width:180px}button{background:#e8f0ff;color:#12315f;font-weight:700;cursor:pointer}.danger{background:#dc3545;color:#fff}.ghost{background:#263650;color:#eef4ff}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin:18px 0}.stat{background:#0c1525;border:1px solid #263650;border-radius:12px;padding:16px}.stat b{display:block;font-size:25px;margin-top:6px}.toolbar{display:flex;justify-content:space-between;align-items:center;gap:12px;margin:20px 0 10px}.tablewrap{overflow:auto;border:1px solid #263650;border-radius:12px}table{width:100%;border-collapse:collapse;min-width:820px}th,td{padding:12px;text-align:left;border-bottom:1px solid #22324b;vertical-align:top}th{background:#0c1525}.target{max-width:420px;word-break:break-all}.code{font-family:monospace;font-size:16px}.dangerbox{margin-top:24px;border:1px solid #7d2a34;background:#2a1418;border-radius:12px;padding:18px}.error{color:#ff9aa6;margin-top:12px}.ok{color:#a7e3b6;margin-top:12px}.hidden{display:none}@media(max-width:700px){.stats{grid-template-columns:1fr}.shell{margin:20px auto}.card{padding:16px}}
</style>
</head>
<body>
<div id="loginView" class="login card hidden">
  <h1>Website Redirect Control</h1>
  <p class="muted">Administrator authentication required.</p>
  <div class="row">
    <input id="password" type="password" autocomplete="current-password" placeholder="Password">
    <button id="loginBtn">Login</button>
  </div>
  <div id="loginMsg"></div>
</div>

<div id="dashboard" class="shell hidden">
  <div class="card">
    <div class="toolbar">
      <div>
        <h1 style="margin:0">Control Panel</h1>
        <div class="muted">Short-link administration</div>
      </div>
      <button id="logoutBtn" class="ghost">Log out</button>
    </div>

    <div class="stats">
      <div class="stat"><span class="muted">Short links</span><b id="linkCount">—</b></div>
      <div class="stat"><span class="muted">Total visits</span><b id="visitCount">—</b></div>
      <div class="stat"><span class="muted">Created today</span><b id="todayCount">—</b></div>
    </div>

    <div class="toolbar">
      <h2 style="margin:0">Links</h2>
      <div class="row">
        <input id="searchInput" type="search" placeholder="Short code or full short URL" aria-label="Search short links">
        <button id="searchBtn" class="ghost">Search</button>
        <button id="clearSearchBtn" class="ghost">Clear</button>
        <button id="refreshBtn" class="ghost">Refresh</button>
      </div>
    </div>
    <div class="tablewrap">
      <table>
        <thead><tr><th>Code</th><th>Target</th><th>Created</th><th>Expires</th><th>Visits</th><th>Action</th></tr></thead>
        <tbody id="linksBody"></tbody>
      </table>
    </div>
    <div id="panelMsg"></div>

    <div class="dangerbox">
      <h2 style="margin-top:0">Danger zone</h2>
      <p class="muted">Permanently delete every saved short link. Administrator settings are not deleted.</p>
      <button id="cleanBtn" class="danger">Delete all short links</button>
    </div>
  </div>
</div>

<script>
const loginView=document.getElementById('loginView');
const dashboard=document.getElementById('dashboard');
const loginMsg=document.getElementById('loginMsg');
const panelMsg=document.getElementById('panelMsg');
let searchTerm='';

async function api(path,options){
  const r=await fetch(path,options||{});
  let d={};
  try{d=await r.json()}catch(e){}
  if(r.status===401){showLogin();throw new Error('Unauthorized')}
  if(!r.ok)throw new Error(d.error||('Request failed: '+r.status));
  return d;
}
function showLogin(){dashboard.classList.add('hidden');loginView.classList.remove('hidden');}
function showDashboard(){loginView.classList.add('hidden');dashboard.classList.remove('hidden');}
function message(el,text,ok){el.textContent=text||'';el.className=text?(ok?'ok':'error'):'';}

async function checkSession(){
  try{await api('/control/api/session');showDashboard();await refreshAll()}
  catch(e){showLogin()}
}
async function login(){
  message(loginMsg,'',false);
  const password=document.getElementById('password').value;
  if(!password){message(loginMsg,'Enter the administrator password.',false);return}
  try{
    await api('/control/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({password:password})});
    document.getElementById('password').value='';
    showDashboard();
    await refreshAll();
  }catch(e){message(loginMsg,e.message,false)}
}
async function logout(){
  try{await fetch('/control/logout',{method:'POST',headers:{'X-Admin-Request':'1'}})}catch(e){}
  showLogin();
}
async function refreshAll(){
  message(panelMsg,'',true);
  const params=new URLSearchParams({limit:'200',offset:'0'});
  if(searchTerm)params.set('search',searchTerm);
  const [stats,links]=await Promise.all([api('/control/api/stats'),api('/control/api/links?'+params)]);
  document.getElementById('linkCount').textContent=stats.links;
  document.getElementById('visitCount').textContent=stats.visits;
  document.getElementById('todayCount').textContent=stats.today;
  const body=document.getElementById('linksBody');
  body.innerHTML='';
  if(!links.links.length && searchTerm)message(panelMsg,'No short links found.',false);
  for(const row of links.links){
    const tr=document.createElement('tr');
    const values=[row.code,row.target_url,row.created_at,row.expires_at||'Never',row.visits];
    values.forEach(function(v,i){
      const td=document.createElement('td');
      td.textContent=String(v==null?'':v);
      if(i===0)td.className='code';
      if(i===1)td.className='target';
      tr.appendChild(td);
    });
    const action=document.createElement('td');
    const btn=document.createElement('button');
    btn.className='danger';
    btn.textContent='Delete';
    btn.addEventListener('click',async function(){
      if(!confirm('Delete short link '+row.code+'?'))return;
      try{
        await api('/control/api/delete',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Request':'1'},body:JSON.stringify({code:row.code})});
        await refreshAll();
      }catch(e){message(panelMsg,e.message,false)}
    });
    action.appendChild(btn);
    tr.appendChild(action);
    body.appendChild(tr);
  }
}
async function cleanAll(){
  if(!confirm('Permanently delete ALL saved short links? This cannot be undone.'))return;
  if(!confirm('Final confirmation: delete every short link?'))return;
  try{
    const d=await api('/control/api/clean',{method:'POST',headers:{'Content-Type':'application/json','X-Admin-Request':'1'},body:JSON.stringify({confirm:'DELETE ALL'})});
    message(panelMsg,'Deleted '+d.deleted+' short links.',true);
    await refreshAll();
  }catch(e){message(panelMsg,e.message,false)}
}

document.getElementById('loginBtn').addEventListener('click',login);
document.getElementById('password').addEventListener('keydown',function(e){if(e.key==='Enter')login()});
document.getElementById('logoutBtn').addEventListener('click',logout);
document.getElementById('refreshBtn').addEventListener('click',function(){refreshAll().catch(e=>message(panelMsg,e.message,false))});
document.getElementById('searchBtn').addEventListener('click',function(){
  searchTerm=document.getElementById('searchInput').value.trim();
  refreshAll().catch(e=>message(panelMsg,e.message,false));
});
document.getElementById('searchInput').addEventListener('keydown',function(e){
  if(e.key==='Enter')document.getElementById('searchBtn').click();
});
document.getElementById('clearSearchBtn').addEventListener('click',function(){
  searchTerm='';
  document.getElementById('searchInput').value='';
  refreshAll().catch(e=>message(panelMsg,e.message,false));
});
document.getElementById('cleanBtn').addEventListener('click',cleanAll);
checkSession();
</script>
</body>
</html>`;

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const isControl = url.pathname === '/control' || url.pathname.startsWith('/control/');

    if (isControl) {
      if (request.method === 'OPTIONS') {
        return new Response('Method not allowed', { status: 405, headers: adminHeaders() });
      }

      if (request.method === 'GET' && (url.pathname === '/control' || url.pathname === '/control/')) {
        return new Response(CONTROL_HTML, {
          headers: adminHeaders({
            'Content-Type': 'text/html; charset=utf-8',
            'Content-Security-Policy': "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
          })
        });
      }

      if (request.method === 'POST' && url.pathname === '/control/login') {
        const cfg = await getAdminConfig(env);
        if (!cfg) return adminJson({ error: 'Administrator configuration is unavailable.' }, { status: 503 });

        let body;
        try {
          body = await request.json();
        } catch {
          return adminJson({ error: 'Invalid request.' }, { status: 400 });
        }

        const password = typeof body.password === 'string' ? body.password : '';
        if (!password || password.length > 256) {
          return adminJson({ error: 'Invalid password.' }, { status: 401 });
        }

        const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
        const ipHash = await hmacHex(cfg.session_secret, 'ip:' + ip);
        const now = Math.floor(Date.now() / 1000);
        const attempt = await env.DB.prepare(
          'SELECT failures,blocked_until,updated_at FROM admin_login_attempts WHERE ip_hash=?'
        ).bind(ipHash).first();

        if (attempt && Number(attempt.blocked_until) > now) {
          return adminJson({ error: 'Too many failed attempts. Try again later.' }, { status: 429 });
        }

        if (!env.ADMIN_PASSWORD_KEY) {
          console.error('Missing ADMIN_PASSWORD_KEY binding');
          return adminJson({ error: 'Administrator configuration needs repair.' }, { status: 503 });
        }
        const derived = await hmacHex(env.ADMIN_PASSWORD_KEY, cfg.password_salt + ':' + password);
        const valid = constantTimeEqualHex(derived, cfg.password_hash);

        if (!valid) {
          const recent = attempt && now - Number(attempt.updated_at) < ADMIN_BLOCK_SECONDS;
          const failures = (recent ? Number(attempt.failures) : 0) + 1;
          const blockedUntil = failures >= ADMIN_MAX_FAILURES ? now + ADMIN_BLOCK_SECONDS : 0;
          await env.DB.prepare(
            'INSERT INTO admin_login_attempts (ip_hash,failures,blocked_until,updated_at) VALUES (?,?,?,?) ON CONFLICT(ip_hash) DO UPDATE SET failures=excluded.failures,blocked_until=excluded.blocked_until,updated_at=excluded.updated_at'
          ).bind(ipHash, failures, blockedUntil, now).run();
          return adminJson(
            { error: blockedUntil ? 'Too many failed attempts. Try again later.' : 'Invalid password.' },
            { status: blockedUntil ? 429 : 401 }
          );
        }

        await env.DB.prepare('DELETE FROM admin_login_attempts WHERE ip_hash=?').bind(ipHash).run();
        const exp = now + ADMIN_SESSION_SECONDS;
        const sig = await hmacHex(cfg.session_secret, 'admin:' + exp);
        return adminJson(
          { success: true },
          { headers: { 'Set-Cookie': adminCookie(exp, sig) } }
        );
      }

      if (request.method === 'POST' && url.pathname === '/control/logout') {
        return adminJson({ success: true }, { headers: { 'Set-Cookie': clearAdminCookie() } });
      }

      const authenticated = await verifyAdmin(request, env);
      if (!authenticated) return adminJson({ error: 'Unauthorized' }, { status: 401 });

      if (request.method === 'GET' && url.pathname === '/control/api/session') {
        return adminJson({ authenticated: true });
      }

      if (request.method === 'GET' && url.pathname === '/control/api/stats') {
        const row = await env.DB.prepare(
          "SELECT COUNT(*) AS links, COALESCE(SUM(visits),0) AS visits, COALESCE(SUM(CASE WHEN created_at >= datetime('now','start of day') THEN 1 ELSE 0 END),0) AS today FROM links"
        ).first();
        return adminJson({
          links: Number(row?.links || 0),
          visits: Number(row?.visits || 0),
          today: Number(row?.today || 0)
        });
      }

      if (request.method === 'GET' && url.pathname === '/control/api/links') {
        const limit = Math.min(Math.max(Number(url.searchParams.get('limit')) || 100, 1), 200);
        const offset = Math.max(Number(url.searchParams.get('offset')) || 0, 0);
        let search = (url.searchParams.get('search') || '').trim();
        if (search.length > 256) return adminJson({ error: 'Search is too long.' }, { status: 400 });
        if (/^(?:https?:\/\/)?s\.presikid\.com\//i.test(search)) {
          try {
            const shortUrl = new URL(/^https?:\/\//i.test(search) ? search : 'https://' + search);
            if (shortUrl.hostname.toLowerCase() !== 's.presikid.com') throw new Error('Invalid host');
            search = decodeURIComponent(shortUrl.pathname.slice(1));
          } catch {
            return adminJson({ error: 'Invalid short link.' }, { status: 400 });
          }
        }
        if (search && !/^[0-9A-Za-z]{1,32}$/.test(search)) {
          return adminJson({ error: 'Enter a short code or full short link.' }, { status: 400 });
        }
        const result = search
          ? await env.DB.prepare(
              'SELECT code,target_url,created_at,expires_at,visits FROM links WHERE instr(lower(code),lower(?))>0 ORDER BY id DESC LIMIT ? OFFSET ?'
            ).bind(search, limit, offset).all()
          : await env.DB.prepare(
              'SELECT code,target_url,created_at,expires_at,visits FROM links ORDER BY id DESC LIMIT ? OFFSET ?'
            ).bind(limit, offset).all();
        return adminJson({ links: result.results || [] });
      }

      if (request.method === 'POST' && url.pathname === '/control/api/delete') {
        if (request.headers.get('X-Admin-Request') !== '1') {
          return adminJson({ error: 'Forbidden' }, { status: 403 });
        }
        let body;
        try { body = await request.json(); } catch { body = {}; }
        const code = typeof body.code === 'string' ? body.code.trim() : '';
        if (!code || code.length > 32) return adminJson({ error: 'Invalid code.' }, { status: 400 });
        const result = await env.DB.prepare('DELETE FROM links WHERE code=?').bind(code).run();
        return adminJson({ success: true, deleted: Number(result.meta?.changes || 0) });
      }

      if (request.method === 'POST' && url.pathname === '/control/api/clean') {
        if (request.headers.get('X-Admin-Request') !== '1') {
          return adminJson({ error: 'Forbidden' }, { status: 403 });
        }
        let body;
        try { body = await request.json(); } catch { body = {}; }
        if (body.confirm !== 'DELETE ALL') {
          return adminJson({ error: 'Confirmation required.' }, { status: 400 });
        }
        const count = await env.DB.prepare('SELECT COUNT(*) AS n FROM links').first();
        await env.DB.prepare('DELETE FROM links').run();
        return adminJson({ success: true, deleted: Number(count?.n || 0) });
      }

      return adminJson({ error: 'Not found' }, { status: 404 });
    }

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
      let body;
      try {
        body = await request.json();
      } catch {
        return Response.json({ error: 'Invalid JSON' }, { status: 400, headers: cors });
      }

      const target = typeof body.url === 'string' ? body.url.trim() : '';
      const duration = body.duration || 'permanent';
      if (!target) return Response.json({ error: 'Missing url' }, { status: 400, headers: cors });

      try {
        const parsed = new URL(target);
        if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') throw new Error('scheme');
      } catch {
        return Response.json({ error: 'Only http:// and https:// URLs are allowed' }, { status: 400, headers: cors });
      }

      const old = await env.DB.prepare(
        'SELECT code,expires_at FROM links WHERE target_url=? ORDER BY id DESC LIMIT 1'
      ).bind(target).first();

      if (old) {
        const stillValid = !old.expires_at || new Date(old.expires_at).getTime() > Date.now();
        if (stillValid && old.code.length === 3) {
          return Response.json({
            code: old.code,
            url: url.origin + '/' + old.code,
            existing: true,
            expires_at: old.expires_at || null
          }, { headers: cors });
        }
        if (!stillValid) {
          await env.DB.prepare('DELETE FROM links WHERE code=?').bind(old.code).run();
        }
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

      let code = null;
      let created = false;
      for (let attempt = 0; attempt < 2000 && !created; attempt++) {
        code = randomCode(3);
        try {
          await env.DB.prepare(
            'INSERT INTO links (code,target_url,expires_at) VALUES (?,?,?)'
          ).bind(code, target, expiresAt).run();
          created = true;
        } catch {}
      }

      if (!created) {
        return Response.json({ error: 'Unable to allocate a 3-character short code' }, { status: 503, headers: cors });
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
      const row = await env.DB.prepare(
        'SELECT code,target_url,created_at,visits,expires_at FROM links WHERE code=?'
      ).bind(code).first();

      if (!row) return Response.json({ error: 'Not found' }, { status: 404, headers: cors });
      return Response.json({
        ...row,
        expired: Boolean(row.expires_at && new Date(row.expires_at).getTime() <= Date.now())
      }, { headers: cors });
    }

    if (request.method !== 'GET') return new Response('Method not allowed', { status: 405 });

    const code = url.pathname.slice(1);
    if (!code) return new Response('Website Redirect');

    const row = await env.DB.prepare(
      'SELECT target_url,expires_at FROM links WHERE code=?'
    ).bind(code).first();

    if (!row) return new Response('Not found', { status: 404 });
    if (row.expires_at && new Date(row.expires_at).getTime() <= Date.now()) {
      return new Response('Link expired', { status: 410 });
    }

    await env.DB.prepare('UPDATE links SET visits=visits+1 WHERE code=?').bind(code).run();
    return Response.redirect(row.target_url, 302);
  }
};
