export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ============================================
  // ARTICLE PERMALINKS - /articlespace?a=:slug
  // ============================================
  // Query-string based on purpose: /articlespace/:slug (a path segment)
  // was being collapsed/redirected by the platform's static-asset
  // canonicalization for the "articlespace" directory before this
  // function ever got a chance to run. Query strings are never
  // considered part of that path-canonicalization decision, so
  // /articlespace?a=slug and /articlespace are treated as the exact
  // same resource by everything upstream of this function — there's
  // no sub-path left for anything to "helpfully" redirect away.
  //
  // If this path is NOT /articlespace, or there's no ?a= param, we
  // don't touch it — next() lets it fall through to normal static
  // handling exactly like before (e.g. plain /articlespace list view).
  const isArticlespacePage = path === '/articlespace' || path === '/articlespace/';
  if (isArticlespacePage) {
    const slug = url.searchParams.get('a');
    if (slug) {
      return handleArticlePermalink(slug, request, env, next);
    }
    // No ?a= param: normal list view, just serve the static shell as-is.
    return next();
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
// GET /articlespace?a=:slug — serves the articlespace/index.html
// shell with:
//   1. og:/twitter: meta tags rewritten to match the real article.
//   2. The resolved article embedded directly as JSON in a
//      <script> tag, so the client never has to re-derive which
//      article this URL refers to.
//
// Slugs are <slugified-title>-<id>. We resolve the ID straight out
// of the slug and look the article up by primary key — a single
// deterministic query, no dependency on list ordering.
//
// Deliberately uses a query string (?a=slug) rather than a path
// segment (/articlespace/slug): a path segment under the
// "articlespace" static directory was getting canonicalized/redirected
// by the platform's static-asset resolution before this function ever
// ran. Query strings sit outside that decision entirely, so this
// request is treated as the same resource as plain /articlespace —
// nothing upstream has a reason to rewrite it.
// ============================================

const COPY_ICON_SVG = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>';

function escHtml(s) {
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// Renders the same markup structure the client uses for an expanded
// .article-card — but as real HTML in the initial response, so a
// visitor sees the full article immediately, centered near the top
// of the viewport, with zero dependency on JS running.
function renderHeroMarkup(article, slug, backHref, selfHref) {
  const title = escHtml(article.title || 'Untitled');
  const author = escHtml(article.author || 'Anonymous');
  const date = escHtml(new Date(article.created_at).toLocaleDateString());
  const content = escHtml(article.content || '');

  return '<div class="permalink-hero">' +
    '<div class="permalink-card-wrap">' +
      '<a class="back-to-all" href="' + escHtml(backHref) + '">↩ All articles</a>' +
      '<div class="article-card expanded" data-article-index="0" data-share="' + escHtml(slug) + '">' +
        '<div class="card-inner">' +
          '<div class="title-row">' +
            '<a class="title" href="' + escHtml(selfHref) + '">' + title + '</a>' +
            '<button class="copy-link-btn" type="button" data-share="' + escHtml(slug) + '" aria-label="Copy link to this article">' + COPY_ICON_SVG + '</button>' +
          '</div>' +
          '<div class="meta">' + date + ' · ' + author + '</div>' +
          '<div class="content full">' + content + '</div>' +
        '</div>' +
      '</div>' +
    '</div>' +
  '</div>';
}

async function handleArticlePermalink(slug, request, env, next) {
  try {
    // Fetch the shell from articlespace/index.html.
    const shellRequest = new Request(new URL('/articlespace/index.html', request.url), request);
    const shellResponse = await env.ASSETS.fetch(shellRequest);

    if (!shellResponse.ok) {
      return shellResponse;
    }

    let html = await shellResponse.text();
    let article = null;

    const idMatch = /-(\d+)$/.exec(slug);
    if (idMatch) {
      const id = parseInt(idMatch[1], 10);
      try {
        article = await env.DB.prepare(
          'SELECT id, title, content, author, created_at FROM articles WHERE id = ?'
        ).bind(id).first();
      } catch (err) {
        console.error('Permalink DB lookup failed:', err);
      }
    }

    // Embed the resolved article (or null) as JSON, so the client
    // knows whether the server found something.
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
      return new Response(html, {
        status: 404,
        headers: { 'content-type': 'text/html;charset=UTF-8' },
      });
    }

    // Server-render the expanded card directly into the container that
    // ships in the initial HTML.
    const backHref = '/articlespace';
    const selfHref = '/articlespace?a=' + encodeURIComponent(slug);
    const heroHtml = renderHeroMarkup(article, slug, backHref, selfHref);
    html = html.replace(
      /<div id="articles-container" class="articles-container">[\s\S]*?<\/div>\s*<\/div>/,
      '<div id="articles-container" class="articles-container">' + heroHtml + '</div>'
    );

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
