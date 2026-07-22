export async function onRequest(context) {
  const { request, env } = context;
  
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
  }
  
  try {
    const { username, password } = await request.json();
    
    if (!username || !password) {
      return new Response(JSON.stringify({ error: 'Missing credentials' }), { status: 400 });
    }
    
    const user = await env.DB.prepare('SELECT * FROM users WHERE username = ?').bind(username).first();
    if (!user) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
    }
    
    const hashed = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashHex = Array.from(new Uint8Array(hashed)).map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (user.password_hash !== hashHex) {
      return new Response(JSON.stringify({ error: 'Invalid credentials' }), { status: 401 });
    }
    
    // Create session
    const sessionId = crypto.randomUUID();
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, new Date(Date.now() + 7*24*60*60*1000).toISOString()).run();
    
    const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${7*24*60*60}`;
    
    return new Response(JSON.stringify({ success: true, role: user.role }), {
      headers: { 'Set-Cookie': cookie, 'Content-Type': 'application/json' }
    });
  } catch (err) {
    return new Response(JSON.stringify({ error: 'Internal server error' }), { status: 500 });
  }
}
