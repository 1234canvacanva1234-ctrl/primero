export async function onRequest(context) {
  const { request, env } = context;
  
  try {
    const cookie = request.headers.get('Cookie') || '';
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];
    
    if (!sessionId) {
      return new Response(JSON.stringify({ authenticated: false }), { 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
    
    const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
    if (!session || new Date(session.expires_at) < new Date()) {
      if (session) {
        await env.DB.prepare('DELETE FROM sessions WHERE session_id = ?').bind(sessionId).run();
      }
      return new Response(JSON.stringify({ authenticated: false }), { 
        headers: { 'Content-Type': 'application/json' } 
      });
    }
    
    const user = await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
    return new Response(JSON.stringify({ authenticated: true, user }), { 
      headers: { 'Content-Type': 'application/json' } 
    });
  } catch (err) {
    return new Response(JSON.stringify({ authenticated: false }), { status: 500 });
  }
}
