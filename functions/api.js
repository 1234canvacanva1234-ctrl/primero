export async function onRequest(context) {
  const { request, env, url } = context;
  const path = new URL(request.url).pathname;
  
  if (path === '/api/auth/signup' && request.method === 'POST') {
    return handleSignup(request, env);
  }
  if (path === '/api/auth/signin' && request.method === 'POST') {
    return handleSignin(request, env);
  }
  if (path === '/api/auth/signout' && request.method === 'POST') {
    return handleSignout(request, env);
  }
  if (path === '/api/auth/status') {
    return handleStatus(request, env);
  }
  if (path === '/api/articles' && request.method === 'GET') {
    return getArticles(env);
  }
  if (path === '/api/articles' && request.method === 'POST') {
    return createArticle(request, env);
  }
  if (path.match(/^\/api\/articles\/\d+$/) && request.method === 'GET') {
    const id = path.split('/').pop();
    return getArticle(env, id);
  }
  if (path.match(/^\/api\/articles\/\d+$/) && request.method === 'PUT') {
    const id = path.split('/').pop();
    return updateArticle(request, env, id);
  }
  if (path.match(/^\/api\/articles\/\d+$/) && request.method === 'DELETE') {
    const id = path.split('/').pop();
    return deleteArticle(request, env, id);
  }
  if (path === '/api/users' && request.method === 'GET') {
    return getUsers(request, env);
  }
  if (path.match(/^\/api\/users\/.+\/grant$/) && request.method === 'POST') {
    const username = path.split('/')[3];
    return grantAdmin(request, env, username);
  }
  
  return new Response(JSON.stringify({ error: 'Not found' }), { status: 404 });
}

// ===== AUTH HANDLERS =====

async function handleSignup(request, env) {
  try {
    const { username, password } = await request.json();
    if (!username || !password || password.length < 8) {
      return jsonResponse({ error: 'Invalid credentials' }, 400);
    }
    
    const existing = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (existing) {
      return jsonResponse({ error: 'Username already taken' }, 409);
    }
    
    const hashed = await hashPassword(password);
    await env.DB.prepare(
      'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
    ).bind(username, hashed, 'user', new Date().toISOString()).run();
    
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();
    
    return jsonResponse({ success: true }, 200, sessionId);
  } catch (err) {
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleSignin(request, env) {
  try {
    const { username, password } = await request.json();
    if (!username || !password) {
      return jsonResponse({ error: 'Missing credentials' }, 400);
    }
    
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) {
      return jsonResponse({ error: 'Invalid credentials' }, 401);
    }
    
    const hashed = await hashPassword(password);
    if (user.password_hash !== hashed) {
      return jsonResponse({ error: 'Invalid credentials' }, 401);
    }
    
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();
    
    return jsonResponse({ success: true, role: user.role }, 200, sessionId);
  } catch (err) {
    return jsonResponse({ error: 'Internal server error' }, 500);
  }
}

async function handleSignout(request, env) {
  const sessionId = getSessionId(request);
  if (sessionId) {
    await env.DB.prepare('DELETE FROM sessions WHERE session_id = ?').bind(sessionId).run();
  }
  return jsonResponse({ success: true }, 200, null, true);
}

async function handleStatus(request, env) {
  const sessionId = getSessionId(request);
  if (!sessionId) {
    return jsonResponse({ authenticated: false }, 200);
  }
  
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
  if (!session || new Date(session.expires_at) < new Date()) {
    if (session) {
      await env.DB.prepare('DELETE FROM sessions WHERE session_id = ?').bind(sessionId).run();
    }
    return jsonResponse({ authenticated: false }, 200);
  }
  
  const user = await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
  return jsonResponse({ authenticated: true, user }, 200);
}

// ===== ARTICLE HANDLERS =====

async function getArticles(env) {
  try {
    const articles = await env.DB.prepare(
      'SELECT id, title, content, author, created_at, updated_at FROM articles ORDER BY created_at DESC'
    ).all();
    return jsonResponse(articles.results || [], 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

async function createArticle(request, env) {
  const user = await getSessionUser(request, env);
  if (!user || user.role !== 'sysadmin') {
    return jsonResponse({ error: 'Unauthorized' }, 403);
  }
  
  try {
    const { title, content } = await request.json();
    if (!title || !content) {
      return jsonResponse({ error: 'Missing fields' }, 400);
    }
    
    const result = await env.DB.prepare(
      'INSERT INTO articles (title, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(title, content, user.username, new Date().toISOString(), new Date().toISOString()).run();
    
    return jsonResponse({ success: true, id: result.meta.last_row_id }, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

async function getArticle(env, id) {
  try {
    const article = await env.DB.prepare('SELECT * FROM articles WHERE id = ?').bind(id).first();
    if (!article) {
      return jsonResponse({ error: 'Not found' }, 404);
    }
    return jsonResponse(article, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

async function updateArticle(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user || user.role !== 'sysadmin') {
    return jsonResponse({ error: 'Unauthorized' }, 403);
  }
  
  try {
    const { title, content } = await request.json();
    if (!title || !content) {
      return jsonResponse({ error: 'Missing fields' }, 400);
    }
    
    await env.DB.prepare(
      'UPDATE articles SET title = ?, content = ?, updated_at = ? WHERE id = ?'
    ).bind(title, content, new Date().toISOString(), id).run();
    
    return jsonResponse({ success: true }, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

async function deleteArticle(request, env, id) {
  const user = await getSessionUser(request, env);
  if (!user || user.role !== 'sysadmin') {
    return jsonResponse({ error: 'Unauthorized' }, 403);
  }
  
  try {
    await env.DB.prepare('DELETE FROM articles WHERE id = ?').bind(id).run();
    return jsonResponse({ success: true }, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

// ===== USER HANDLERS =====

async function getUsers(request, env) {
  const user = await getSessionUser(request, env);
  if (!user || user.role !== 'sysadmin') {
    return jsonResponse({ error: 'Unauthorized' }, 403);
  }
  
  try {
    const users = await env.DB.prepare('SELECT username, role FROM users ORDER BY username').all();
    return jsonResponse(users.results || [], 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

async function grantAdmin(request, env, username) {
  const user = await getSessionUser(request, env);
  if (!user || user.role !== 'sysadmin') {
    return jsonResponse({ error: 'Unauthorized' }, 403);
  }
  
  try {
    await env.DB.prepare('UPDATE users SET role = ? WHERE username = ?').bind('sysadmin', username).run();
    return jsonResponse({ success: true }, 200);
  } catch (err) {
    return jsonResponse({ error: 'Internal error' }, 500);
  }
}

// ===== UTILITY FUNCTIONS =====

async function hashPassword(password) {
  const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
  return Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
}

function getSessionId(request) {
  const cookie = request.headers.get('Cookie') || '';
  return cookie.match(/session=([^;]+)/)?.[1] || null;
}

async function getSessionUser(request, env) {
  const sessionId = getSessionId(request);
  if (!sessionId) return null;
  
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
  if (!session || new Date(session.expires_at) < new Date()) return null;
  
  return await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
}

function jsonResponse(data, status, sessionId = null, clearCookie = false) {
  const headers = { 'Content-Type': 'application/json' };
  
  if (sessionId) {
    headers['Set-Cookie'] = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7*24*60*60}`;
  }
  
  if (clearCookie) {
    headers['Set-Cookie'] = `session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`;
  }
  
  return new Response(JSON.stringify(data), { status, headers });
}
