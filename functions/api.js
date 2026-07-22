export async function onRequest(context) {
  const { request, env } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // Log every request for debugging
  console.log('API Request:', path, request.method);

  // CORS headers
  const headers = {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
    'Access-Control-Allow-Credentials': 'true'
  };

  // Handle preflight
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers });
  }

  // ============================================
  // TEST ENDPOINT - Visit /api/test to verify it works
  // ============================================
  if (path === '/api/test') {
    return new Response(JSON.stringify({ 
      status: 'OK', 
      message: 'API is working!',
      timestamp: new Date().toISOString()
    }), { headers });
  }

  // ============================================
  // DATABASE TEST - Visit /api/db-test
  // ============================================
  if (path === '/api/db-test') {
    try {
      if (!env.DB) {
        return new Response(JSON.stringify({ 
          error: 'Database binding "DB" not found' 
        }), { status: 500, headers });
      }
      const result = await env.DB.prepare('SELECT 1 as test').first();
      return new Response(JSON.stringify({ 
        status: 'Database connected!',
        result: result 
      }), { headers });
    } catch (err) {
      return new Response(JSON.stringify({ 
        error: 'Database error: ' + err.message 
      }), { status: 500, headers });
    }
  }

  // ============================================
  // SIGNUP
  // ============================================
  if (path === '/api/auth/signup' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;
      
      console.log('Signup attempt:', username);
      
      // Validate
      if (!username || username.length < 3) {
        return new Response(JSON.stringify({ error: 'Username must be at least 3 characters' }), 
          { status: 400, headers });
      }
      if (!password || password.length < 8) {
        return new Response(JSON.stringify({ error: 'Password must be at least 8 characters' }), 
          { status: 400, headers });
      }
      
      // Check if user exists
      const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
      if (existing) {
        return new Response(JSON.stringify({ error: 'Username already taken' }), 
          { status: 409, headers });
      }
      
      // Hash password
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      // Create user
      await env.DB.prepare(
        'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
      ).bind(username, hashHex, 'user', new Date().toISOString()).run();
      
      // Create session
      const sessionId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      await env.DB.prepare(
        'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
      ).bind(sessionId, username, expiresAt).run();
      
      // Set cookie
      const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
      headers['Set-Cookie'] = cookie;
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: 'Account created successfully',
        username: username
      }), { headers });
      
    } catch (err) {
      console.error('Signup error:', err);
      return new Response(JSON.stringify({ 
        error: 'Signup failed: ' + err.message 
      }), { status: 500, headers });
    }
  }

  // ============================================
  // SIGNIN
  // ============================================
  if (path === '/api/auth/signin' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;
      
      console.log('Signin attempt:', username);
      
      if (!username || !password) {
        return new Response(JSON.stringify({ error: 'Username and password required' }), 
          { status: 400, headers });
      }
      
      // Get user
      const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
      if (!user) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), 
          { status: 401, headers });
      }
      
      // Verify password
      const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
      const hashArray = Array.from(new Uint8Array(hashBuffer));
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
      
      if (user.password_hash !== hashHex) {
        return new Response(JSON.stringify({ error: 'Invalid credentials' }), 
          { status: 401, headers });
      }
      
      // Create session
      const sessionId = crypto.randomUUID();
      const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
      await env.DB.prepare(
        'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
      ).bind(sessionId, username, expiresAt).run();
      
      // Set cookie
      const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
      headers['Set-Cookie'] = cookie;
      
      return new Response(JSON.stringify({ 
        success: true, 
        message: 'Signed in successfully',
        username: username,
        role: user.role
      }), { headers });
      
    } catch (err) {
      console.error('Signin error:', err);
      return new Response(JSON.stringify({ 
        error: 'Signin failed: ' + err.message 
      }), { status: 500, headers });
    }
  }

  // ============================================
  // AUTH STATUS
  // ============================================
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
      
      const user = await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
      return new Response(JSON.stringify({ authenticated: true, user }), { headers });
      
    } catch (err) {
      return new Response(JSON.stringify({ authenticated: false }), { headers });
    }
  }

  // ============================================
  // SIGNOUT
  // ============================================
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
      return new Response(JSON.stringify({ error: 'Signout failed' }), { status: 500, headers });
    }
  }

  // ============================================
  // NOT FOUND - Return JSON instead of HTML
  // ============================================
  return new Response(JSON.stringify({ 
    error: 'Not found',
    path: path,
    method: request.method
  }), { status: 404, headers });
}
