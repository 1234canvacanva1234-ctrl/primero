export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  
  // CORS headers
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*'
  };

  // ============================================
  // TEST - /api/test
  // ============================================
  if (url.pathname === '/api/test') {
    return new Response(JSON.stringify({ 
      status: 'OK', 
      message: 'API is working!'
    }), { headers });
  }

  // ============================================
  // SIGNUP - /api/auth/signup
  // ============================================
  if (url.pathname === '/api/auth/signup' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;
      
      if (!username || username.length < 3) {
        return new Response(JSON.stringify({ error: 'Username too short' }), { status: 400, headers });
      }
      if (!password || password.length < 8) {
        return new Response(JSON.stringify({ error: 'Password too short' }), { status: 400, headers });
      }
      
      // Check if user exists
      const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
      if (existing) {
        return new Response(JSON.stringify({ error: 'Username taken' }), { status: 409, headers });
      }
      
      // Hash password
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashHex = Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Create user
      await env.DB.prepare(
        'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
      ).bind(username, hashHex, 'user', new Date().toISOString()).run();
      
      // Create session
      const sessionId = crypto.randomUUID();
      await env.DB.prepare(
        'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
      ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();
      
      const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7*24*60*60}`;
      
      return new Response(JSON.stringify({ success: true, username }), { 
        headers: { ...headers, 'Set-Cookie': cookie }
      });
      
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // SIGNIN - /api/auth/signin
  // ============================================
  if (url.pathname === '/api/auth/signin' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;
      
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401, headers });
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
      
      return new Response(JSON.stringify({ success: true, username, role: user.role }), { 
        headers: { ...headers, 'Set-Cookie': cookie }
      });
      
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // AUTH STATUS - /api/auth/status
  // ============================================
  if (url.pathname === '/api/auth/status') {
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
      
      const user = await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
      return new Response(JSON.stringify({ authenticated: true, user }), { headers });
      
    } catch (err) {
      return new Response(JSON.stringify({ authenticated: false }), { headers });
    }
  }

  return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
}
