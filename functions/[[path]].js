const SUBPAGE_FALLBACKS = [
  { pattern: /^\/article\//, fallback: '/article/' },
  { pattern: /^\/profile\//, fallback: '/profile/' }
];

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  if (!path.startsWith('/api/')) {
    const response = await next();
    if (response.status !== 404) {
      return response;
    }

    for (const route of SUBPAGE_FALLBACKS) {
      if (route.pattern.test(path)) {
        return Response.redirect(url.origin + route.fallback, 302);
      }
    }

    return Response.redirect(url.origin + '/', 302);
  }

  console.log('API Request:', path, request.method);

  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
    'Access-Control-Allow-Credentials': 'true'
  };

  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  if (path === '/api/test') {
    return new Response(JSON.stringify({
      status: 'OK',
      message: 'API is working!'
    }), { headers });
  }

  if (path === '/api/auth/signup' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;

      if (!username || username.length < 3) {
        return new Response(JSON.stringify({ error: 'insufficient characters (username)' }), { status: 400, headers });
      }
      if (!password || password.length < 8) {
        return new Response(JSON.stringify({ error: 'insufficient characters (token)' }), { status: 400, headers });
      }

      const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
      if (existing) {
        return new Response(JSON.stringify({ error: 'username used' }), { status: 409, headers });
      }

      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

      await env.DB.prepare(
        'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
      ).bind(username, hashHex, 'user', new Date().toISOString()).run();

      const sessionId = crypto.randomUUID();
      await env.DB.prepare(
        'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
      ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();

      const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7*24*60*60}`;
      headers['Set-Cookie'] = cookie;

      return new Response(JSON.stringify({ success: true, username }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/auth/signin' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;

      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) {
        return new Response(JSON.stringify({ error: 'invalid data provided' }), { status: 401, headers });
      }

      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');

      if (user.password_hash !== hashHex) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers });
      }

      const sessionId = crypto.randomUUID();
      await env.DB.prepare(
        'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
      ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();

      const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7*24*60*60}`;
      headers['Set-Cookie'] = cookie;

      return new Response(JSON.stringify({ success: true, username, role: user.role }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/auth/status') {
    try {
      const cookie = request.headers.get('Cookie') || '';
      const sessionId = cookie.match(/session=([^;]+)/)?.[1];

      if (!sessionId) {
        return new Response(JSON.stringify({ authenticated: false }), { headers });
      }

      const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
      if (!session || new Date(session.expires_at) < new Date()) {
        return new Response(JSON.stringify({ authenticated: false }), { headers });
      }

      const user = await env.DB.prepare('SELECT username, role, avatar_url, bio FROM users WHERE username = ?').bind(session.username).first();
      return new Response(JSON.stringify({ authenticated: true, user: await withProfileDefaults(user) }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ authenticated: false }), { headers });
    }
  }

  if (path === '/api/auth/signout' && request.method === 'POST') {
    try {
      const cookie = request.headers.get('Cookie') || '';
      const sessionId = cookie.match(/session=([^;]+)/)?.[1];

      if (sessionId) {
        await env.DB.prepare('DELETE FROM sessions WHERE session_id = ?').bind(sessionId).run();
      }

      headers['Set-Cookie'] = 'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
      return new Response(JSON.stringify({ success: true }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/profile' && request.method === 'GET') {
    try {
      const user = await getSessionUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      }

      const profile = await env.DB.prepare(
        'SELECT username, role, avatar_url, bio FROM users WHERE username = ?'
      ).bind(user.username).first();

      return new Response(JSON.stringify(await withProfileDefaults(profile)), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/profile' && request.method === 'PUT') {
    try {
      const user = await getSessionUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      }

      const body = await request.json();
      let avatar_url = (body.avatar_url || '').trim();
      let bio = (body.bio || '').trim();

      if (avatar_url.length > 500) {
        return new Response(JSON.stringify({ error: 'excessive characters (max 500 / image url)' }), { status: 400, headers });
      }
      if (avatar_url && !/^https?:\/\/.+/i.test(avatar_url)) {
        return new Response(JSON.stringify({ error: 'image url requires http:// or https:// to start' }), { status: 400, headers });
      }
      if (bio.length > 1000) {
        return new Response(JSON.stringify({ error: 'description exceeds permitted characters (max 1000)' }), { status: 400, headers });
      }

      await env.DB.prepare(
        'UPDATE users SET avatar_url = ?, bio = ? WHERE username = ?'
      ).bind(avatar_url, bio, user.username).run();

      return new Response(JSON.stringify({
        success: true,
        avatar_url: avatar_url || DEFAULT_AVATAR_URL,
        bio: bio || DEFAULT_BIO
      }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  const publicProfileMatch = path.match(/^\/api\/users\/([^\/]+)\/profile$/);
  if (publicProfileMatch && request.method === 'GET') {
    try {
      const username = publicProfileMatch[1];
      const profile = await env.DB.prepare(
        'SELECT username, role, avatar_url, bio FROM users WHERE username = ?'
      ).bind(username).first();

      if (!profile) {
        return new Response(JSON.stringify({ error: 'User not found' }), { status: 404, headers });
      }

      return new Response(JSON.stringify(await withProfileDefaults(profile)), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/articles' && request.method === 'GET') {
    try {
      const articles = await env.DB.prepare(
        'SELECT id, title, content, author, created_at FROM articles ORDER BY created_at DESC'
      ).all();
      return new Response(JSON.stringify(articles.results || []), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/articles' && request.method === 'POST') {
    try {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'sysadmin') {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers });
      }

      const body = await request.json();
      const { title, content } = body;

      if (!title || !content) {
        return new Response(JSON.stringify({ error: 'Title and content required' }), { status: 400, headers });
      }

      const result = await env.DB.prepare(
        'INSERT INTO articles (title, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(title, content, user.username, new Date().toISOString(), new Date().toISOString()).run();

      return new Response(JSON.stringify({ success: true, id: result.meta.last_row_id }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  const articleIdMatch = path.match(/^\/api\/articles\/(\d+)$/);
  if (articleIdMatch && request.method === 'GET') {
    try {
      const id = parseInt(articleIdMatch[1]);
      const article = await env.DB.prepare('SELECT * FROM articles WHERE id = ?').bind(id).first();
      if (!article) {
        return new Response(JSON.stringify({ error: 'Article not found' }), { status: 404, headers });
      }
      return new Response(JSON.stringify(article), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (articleIdMatch && request.method === 'PUT') {
    try {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'sysadmin') {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers });
      }

      const id = parseInt(articleIdMatch[1]);
      const body = await request.json();
      const { title, content } = body;

      if (!title || !content) {
        return new Response(JSON.stringify({ error: 'Title and content required' }), { status: 400, headers });
      }

      await env.DB.prepare(
        'UPDATE articles SET title = ?, content = ?, updated_at = ? WHERE id = ?'
      ).bind(title, content, new Date().toISOString(), id).run();

      return new Response(JSON.stringify({ success: true }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (articleIdMatch && request.method === 'DELETE') {
    try {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'sysadmin') {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers });
      }

      const id = parseInt(articleIdMatch[1]);
      await env.DB.prepare('DELETE FROM articles WHERE id = ?').bind(id).run();

      return new Response(JSON.stringify({ success: true }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  if (path === '/api/users' && request.method === 'GET') {
    try {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'sysadmin') {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers });
      }

      const users = await env.DB.prepare('SELECT username, role FROM users ORDER BY username').all();
      return new Response(JSON.stringify(users.results || []), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  const grantMatch = path.match(/^\/api\/users\/(.+)\/grant$/);
  if (grantMatch && request.method === 'POST') {
    try {
      const user = await getSessionUser(request, env);
      if (!user || user.role !== 'sysadmin') {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403, headers });
      }

      const username = grantMatch[1];
      await env.DB.prepare('UPDATE users SET role = ? WHERE username = ?').bind('sysadmin', username).run();

      return new Response(JSON.stringify({ success: true }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  return new Response(JSON.stringify({
    error: 'Not found',
    path: path,
    method: request.method
  }), { status: 404, headers });
}

const DEFAULT_AVATAR_URL = 'https://i.imgur.com/baiP4yN.png';
const DEFAULT_BIO = "i'm an anonymous private bitch and consequently refuse to provide a simple description";

async function withProfileDefaults(profile) {
  if (!profile) return profile;

  const avatar_url = profile.avatar_url && profile.avatar_url.trim() ? profile.avatar_url.trim() : '';

  return {
    ...profile,
    avatar_url: avatar_url || DEFAULT_AVATAR_URL,
    bio: profile.bio && profile.bio.trim() ? profile.bio : DEFAULT_BIO
  };
}

async function getSessionUser(request, env) {
  try {
    const cookie = request.headers.get('Cookie') || '';
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];

    if (!sessionId) return null;

    const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
    if (!session || new Date(session.expires_at) < new Date()) return null;

    return await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();

  } catch (err) {
    return null;
  }
}
