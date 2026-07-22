export async function onRequest(context) {
  const { request, env } = context;
  
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
  }
  
  try {
    const { username, password } = await request.json();
    
    if (!username || !password || password.length < 8) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 400 });
    }
    
    // Check if user exists
    const existing = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (existing) {
      return new Response(JSON.stringify({ error: 'Username already taken' }), { status: 409 });
    }
    
    // Hash password (simple hash - use bcrypt in production)
    const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashHex = Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Create user (default role: 'user')
    await env.DB.prepare(
      'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
    ).bind(username, hashHex, 'user', new Date().toISOString()).run();
    
    // Set session
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();
    
    const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7*24*60*60}`;
    
    return new Response(JSON.stringify({ success: true }), {
      headers: { 'Set-Cookie': cookie, 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
  }
}
