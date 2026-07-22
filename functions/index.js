export async function onRequest(context) {
  const { request, env } = context;
  
  // GET - list all articles (public)
  if (request.method === 'GET') {
    try {
      const articles = await env.DB.prepare(
        'SELECT id, title, content, author, created_at, updated_at FROM articles ORDER BY created_at DESC'
      ).all();
      return new Response(JSON.stringify(articles.results || []), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (err) {
      return new Response(JSON.stringify([]), { status: 500 });
    }
  }
  
  // POST - create article (sysadmin only)
  if (request.method === 'POST') {
    const session = await getSession(request, env);
    if (!session || session.role !== 'sysadmin') {
      return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 403 });
    }
    
    try {
      const { title, content } = await request.json();
      if (!title || !content) {
        return new Response(JSON.stringify({ error: 'Missing fields' }), { status: 400 });
      }
      
      const result = await env.DB.prepare(
        'INSERT INTO articles (title, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
      ).bind(title, content, session.username, new Date().toISOString(), new Date().toISOString()).run();
      
      return new Response(JSON.stringify({ success: true, id: result.meta.last_row_id }), {
        headers: { 'Content-Type': 'application/json' }
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500 });
    }
  }
  
  return new Response(JSON.stringify({ error: 'Method not allowed' }), { status: 405 });
}

async function getSession(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];
  if (!sessionId) return null;
  
  const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
  if (!session || new Date(session.expires_at) < new Date()) return null;
  
  const user = await env.DB.prepare('SELECT username, role FROM users WHERE username = ?').bind(session.username).first();
  return user;
}
