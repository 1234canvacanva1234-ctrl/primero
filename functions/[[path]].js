export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ============================================
  // ARTICLE PERMALINKS - ?article=slug
  //
  // Deliberately NOT path-based. A query param survives no matter what
  // base path this page is actually deployed under (root, /articlespace,
  // /blog, behind a proxy, etc) — there's nothing for a prefix regex to
  // get out of sync with. Any GET request (outside /api/*) that carries
  // ?article=slug is treated as a permalink request for the Articlespace
  // page, full stop.
  // ============================================
  if (request.method === 'GET' && !path.startsWith('/api/') && url.searchParams.has('article')) {
    return handleArticlePermalink(url.searchParams.get('article'), request, env, next);
  }

  // ============================================
  // IMPORTANT: ONLY handle /api/* routes
  // Everything else passes through to static files
  // ============================================
  if (!path.startsWith('/api/')) {
    return next();
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

  // ============================================
  // TEST - /api/test
  // ============================================
  if (path === '/api/test') {
    return new Response(JSON.stringify({ 
      status: 'OK', 
      message: 'API is working!'
    }), { headers });
  }

  // ============================================
  // SIGNUP - /api/auth/signup
  // ============================================
  if (path === '/api/auth/signup' && request.method === 'POST') {
    try {
      const body = await request.json();
      const { username, password } = body;
      
      if (!username || username.length < 3) {
        return new Response(JSON.stringify({ error: 'Username too short' }), { status: 400, headers });
      }
      if (!password || password.length < 8) {
        return new Response(JSON.stringify({ error: 'Password too short' }), { status: 400, headers });
      }
      
      const existing = await env.DB.prepare('SELECT username FROM users WHERE username = ?').bind(username).first();
      if (existing) {
        return new Response(JSON.stringify({ error: 'Username taken' }), { status: 409, headers });
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

  // ============================================
  // SIGNIN - /api/auth/signin
  // ============================================
  if (path === '/api/auth/signin' && request.method === 'POST') {
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
      headers['Set-Cookie'] = cookie;
      
      return new Response(JSON.stringify({ success: true, username, role: user.role }), { headers });
      
    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // AUTH STATUS - /api/auth/status
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
  // SIGNOUT - /api/auth/signout
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
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // ARTICLES - GET all
  // ============================================
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

  // ============================================
  // ARTICLES - POST (create)
  // ============================================
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

  // ============================================
  // SINGLE ARTICLE - GET /api/articles/:id
  // ============================================
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

  // ============================================
  // SINGLE ARTICLE - PUT /api/articles/:id (update)
  // ============================================
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

  // ============================================
  // SINGLE ARTICLE - DELETE /api/articles/:id
  // ============================================
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

  // ============================================
  // USERS - GET
  // ============================================
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

  // ============================================
  // USER GRANT - /api/users/username/grant
  // ============================================
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

  // ============================================
  // 404 - Return JSON
  // ============================================
  return new Response(JSON.stringify({ 
    error: 'Not found',
    path: path,
    method: request.method
  }), { status: 404, headers });
}

// ============================================
// Article permalink handler
// Any GET request (outside /api/*) carrying ?article=slug.
//
// It always fetches /articlespace.html as the shell — that's the one
// page this mechanism applies to — then:
//   1. Rewrites og:/twitter: meta tags to match the real article, so
//      link-preview bots (Discord, Twitter, etc.) see real content
//      instead of the generic homepage.
//   2. Embeds the resolved article directly as JSON in a <script> tag,
//      so the client never has to re-derive which article this URL
//      refers to — it just reads what the server already decided.
// ============================================
async function handleArticlePermalink(slug, request, env, next) {
  try {
    const shellRequest = new Request(new URL('/articlespace.html', request.url), request);
    const shellResponse = await env.ASSETS.fetch(shellRequest);

    if (!shellResponse.ok) {
      return shellResponse;
    }

    let html = await shellResponse.text();
    let article = null;

    try {
      const { results } = await env.DB.prepare(
        'SELECT id, title, content, author, created_at FROM articles ORDER BY created_at DESC'
      ).all();
      const articles = results || [];

      const slugify = (t) => (t || 'Untitled')
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');

      const slugs = articles.map((a, index) => {
        let s = slugify(a.title);
        const dupCount = articles.filter((art, idx) => idx < index && slugify(art.title) === s).length;
        if (dupCount > 0) s += '-' + (dupCount + 1);
        return s;
      });

      const idx = slugs.indexOf(slug);
      if (idx !== -1) article = articles[idx];
    } catch (err) {
      console.error('Permalink DB lookup failed:', err);
    }

    // Embed the resolved article (or null) as JSON the client reads on load.
    // Escaping every '<' prevents the JSON payload from ever being able to
    // break out of the <script> tag, even if an article's content contains
    // literal "</script>" text.
    const articleData = article ? {
      id: article.id,
      title: article.title,
      content: article.content,
      author: article.author,
      created_at: article.created_at,
      slug: slug
    } : null;

    const dataScript = '<script>window.__ARTICLE__ = ' +
      JSON.stringify(articleData).replace(/</g, '\\u003c') +
      ';</script>';

    html = html.includes('</head>')
      ? html.replace('</head>', dataScript + '</head>')
      : dataScript + html;

    if (!article) {
      // No matching article — still serve the shell (now telling the
      // client explicitly "checked, nothing here" via window.__ARTICLE__
      // = null) so it can show a clear not-found state rather than
      // silently falling back to the general list.
      return new Response(html, {
        status: 404,
        headers: { 'content-type': 'text/html;charset=UTF-8' },
      });
    }

    const title = article.title || 'Untitled';
    const rawDesc = (article.content || '').replace(/\s+/g, ' ').trim();
    const desc = rawDesc.length > 200 ? rawDesc.slice(0, 200) + '…' : rawDesc;

    const esc = (s) => String(s)
      .replace(/&/g, '&amp;')
      .replace(/"/g, '&quot;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

    const pageTitle = esc(title) + ' · SoraSys Articlespace';
    const ogTitle = esc(title);
    const ogDesc = esc(desc || 'Read this article on SoraSys Articlespace.');
    const ogUrl = esc(request.url);

    html = html
      .replace(/<title>.*?<\/title>/s, `<title>${pageTitle}</title>`)
      .replace(/<meta property="og:url" content=".*?">/, `<meta property="og:url" content="${ogUrl}">`)
      .replace(/<meta property="og:title" content=".*?">/, `<meta property="og:title" content="${ogTitle}">`)
      .replace(/<meta property="og:description" content=".*?">/, `<meta property="og:description" content="${ogDesc}">`)
      .replace(/<meta name="twitter:title" content=".*?">/, `<meta name="twitter:title" content="${ogTitle}">`)
      .replace(/<meta name="twitter:description" content=".*?">/, `<meta name="twitter:description" content="${ogDesc}">`);

    return new Response(html, {
      status: 200,
      headers: {
        'content-type': 'text/html;charset=UTF-8',
        'cache-control': 'public, max-age=60',
      },
    });

  } catch (err) {
    console.error('Article permalink handler failed:', err);
    return next();
  }
}

// ============================================
// Helper function
// ============================================
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
