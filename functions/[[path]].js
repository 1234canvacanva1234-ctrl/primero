export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // ============================================
  // NOTE: Article permalinks now use a URL fragment (#slug), e.g.
  // /articlespace#my-article-title-12. Fragments are never sent to
  // the server as part of the HTTP request — the browser strips them
  // before making the request and only re-applies them client-side
  // after the page loads. That means there is nothing for this
  // function (or any Cloudflare routing/redirect layer) to see or act
  // on for the slug at all — every /articlespace request, permalink
  // or not, is just a plain request for the list page. All permalink
  // resolution (finding the article, expanding it, scrolling to it)
  // happens entirely in articlespace/index.html's client-side JS by
  // reading window.location.hash on load.
  //
  // Tradeoff: since the server never sees the slug, it can't render
  // article-specific og:/twitter: meta tags for link-preview bots —
  // shared links show the generic Articlespace preview instead of a
  // per-article one. Everything else (opening the link, expanding the
  // right article, scrolling to it, copy-link, back/forward) works
  // the same as before.
  // ============================================

  // ============================================
  // ROUTING
  // /api/*        -> JSON API (unchanged, see below)
  // everything else -> if it's an HTML navigation, resolve auth
  //                    server-side and inject the sidebar state
  //                    before the response ever reaches the browser.
  //                    Non-HTML static assets (css/js/images/fonts)
  //                    pass straight through untouched, no DB hit.
  // ============================================
  if (!path.startsWith('/api/')) {
    return handlePageRequest(context);
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

      // NOTE: now also returns avatar_url / bio so any page (nav avatars, etc.)
      // can use them straight off the status check without a second request.
      const user = await env.DB.prepare('SELECT username, role, avatar_url, bio FROM users WHERE username = ?').bind(session.username).first();
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
  // PROFILE - GET /api/profile  (own profile, requires auth)
  // ============================================
  if (path === '/api/profile' && request.method === 'GET') {
    try {
      const user = await getSessionUser(request, env);
      if (!user) {
        return new Response(JSON.stringify({ error: 'Unauthorized' }), { status: 401, headers });
      }

      const profile = await env.DB.prepare(
        'SELECT username, role, avatar_url, bio FROM users WHERE username = ?'
      ).bind(user.username).first();

      return new Response(JSON.stringify(profile), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // PROFILE - PUT /api/profile  (update own avatar_url / bio)
  // ============================================
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
        return new Response(JSON.stringify({ error: 'Image URL is too long (max 500 characters)' }), { status: 400, headers });
      }
      if (avatar_url && !/^https?:\/\/.+/i.test(avatar_url)) {
        return new Response(JSON.stringify({ error: 'Image URL must start with http:// or https://' }), { status: 400, headers });
      }
      if (bio.length > 1000) {
        return new Response(JSON.stringify({ error: 'Description is too long (max 1000 characters)' }), { status: 400, headers });
      }

      await env.DB.prepare(
        'UPDATE users SET avatar_url = ?, bio = ? WHERE username = ?'
      ).bind(avatar_url, bio, user.username).run();

      return new Response(JSON.stringify({ success: true, avatar_url, bio }), { headers });

    } catch (err) {
      return new Response(JSON.stringify({ error: err.message }), { status: 500, headers });
    }
  }

  // ============================================
  // PUBLIC PROFILE - GET /api/users/:username/profile
  // (no auth required — lets you show an author's avatar/bio
  // next to their articles, on a byline page, etc.)
  // ============================================
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

      return new Response(JSON.stringify(profile), { headers });

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
// PAGE (non-/api) REQUEST HANDLING
//
// Goal: for HTML navigations only, resolve the session server-side
// and rewrite the sidebar's auth block *before* the response leaves
// the edge, so the browser never paints "Sign In" for a signed-in
// user and then swaps it a moment later.
//
// Uses HTMLRewriter (streaming, no full-buffer needed) instead of a
// string replace, so it works regardless of exact file formatting
// and doesn't require loading the whole HTML doc into memory.
//
// ASSUMPTION (please confirm / adjust if wrong): the sidebar markup
// uses these ids, matching what you showed earlier:
//   #side-avatar-slot   -> <img>  (src = avatar)
//   #side-account-name  -> text   ("Sign In" or username)
//   #side-account-role  -> text, currently hidden via inline style
//   #side-account-bio   -> text, currently hidden via inline style
//   #side-account        -> the <a href="/initialization"> wrapper
// If your real ids/classes differ, the rewriter below just won't
// match anything and the page will silently fall back to the
// client-side JS swap (i.e. same as before, not broken) — so it's
// safe to test, but send me the real file if it doesn't take effect
// and I'll fix the selectors.
// ============================================

const FALLBACK_AVATAR = 'https://i.imgur.com/NGyCK6G.png';

async function handlePageRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // Only bother for likely HTML navigations: GET/HEAD requests with
  // no file extension (clean routes like /articlespace) or an
  // explicit .html extension. Everything else (styles, scripts,
  // images, fonts, json, etc.) passes straight through with zero
  // extra latency and zero DB hit.
  const isLikelyHtml =
    (request.method === 'GET' || request.method === 'HEAD') &&
    (path === '/' || /\.html$/i.test(path) || !/\.[a-zA-Z0-9]+$/.test(path));

  if (!isLikelyHtml) {
    return next();
  }

  const response = await next();

  const contentType = response.headers.get('Content-Type') || '';
  if (!contentType.includes('text/html')) {
    return response;
  }

  let user = null;
  try {
    user = await getSessionUserFull(request, env);
  } catch (err) {
    // If the session/DB lookup fails for any reason, fail open to
    // the default signed-out markup already baked into the static
    // file — never block or break page delivery over an auth check.
    console.log('Session lookup failed for page request:', err.message);
    return response;
  }

  // No session -> the static HTML's default "Sign In" state is
  // already correct. Nothing to rewrite.
  if (!user) {
    return response;
  }

  const avatarUrl = user.avatar_url && user.avatar_url.trim()
    ? user.avatar_url
    : FALLBACK_AVATAR;
  const roleLabel = user.role === 'sysadmin' ? 'sysadmin' : 'member';
  const bioText = user.bio && user.bio.trim() ? user.bio : '';

  const rewriter = new HTMLRewriter()
    // Swap the fallback/placeholder avatar for the real one.
    .on('#side-avatar-slot', {
      element(el) {
        if (el.tagName === 'img') {
          el.setAttribute('src', avatarUrl);
          el.setAttribute('alt', user.username);
        } else {
          // In case the static markup still uses a <span> fallback
          // instead of an <img>, replace it with a real image so
          // the signed-in avatar renders without a client-side swap.
          el.replace(
            `<img src="${escapeAttr(avatarUrl)}" alt="${escapeAttr(user.username)}" class="side-avatar side-avatar-fallback" id="side-avatar-slot" />`,
            { html: true }
          );
        }
      }
    })
    // Username / CTA line
    .on('#side-account-name', {
      element(el) {
        el.setInnerContent(user.username, { html: false });
      }
    })
    // Role line — unhide and fill in
    .on('#side-account-role', {
      element(el) {
        el.removeAttribute('style');
        el.setInnerContent(roleLabel, { html: false });
      }
    })
    // Bio line — unhide and fill in (only if there is a bio; otherwise
    // leave it hidden so an empty bio doesn't show a blank line)
    .on('#side-account-bio', {
      element(el) {
        if (bioText) {
          el.removeAttribute('style');
          el.setInnerContent(bioText, { html: false });
        }
      }
    })
    // Point the whole account block at the profile page instead of
    // the sign-in page, since the user is already signed in.
    .on('#side-account', {
      element(el) {
        el.setAttribute('href', '/profile-config');
      }
    })
    // Unlock the "Profile Configuration" nav link for any signed-in user.
    .on('a[data-gate="auth"]', {
      element(el) {
        el.removeAttribute('aria-disabled');
        el.attributes.forEach(([name]) => {
          if (name === 'class') {
            const cls = el.getAttribute('class') || '';
            el.setAttribute('class', cls.replace(/\blocked\b/g, '').trim());
          }
        });
      }
    })
    // Unlock the sysadmin-only "Control Panel" link only for sysadmins.
    .on('a[data-gate="sysadmin"]', {
      element(el) {
        if (user.role === 'sysadmin') {
          el.removeAttribute('aria-disabled');
          const cls = el.getAttribute('class') || '';
          el.setAttribute('class', cls.replace(/\blocked\b/g, '').trim());
        }
      }
    });

  return rewriter.transform(response);
}

function escapeAttr(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

// ============================================
// Helper functions
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

// Same as getSessionUser, but also pulls avatar_url/bio, needed for
// the server-side sidebar injection in handlePageRequest.
async function getSessionUserFull(request, env) {
  const cookie = request.headers.get('Cookie') || '';
  const sessionId = cookie.match(/session=([^;]+)/)?.[1];

  if (!sessionId) return null;

  const session = await env.DB.prepare('SELECT * FROM sessions WHERE session_id = ?').bind(sessionId).first();
  if (!session || new Date(session.expires_at) < new Date()) return null;

  return await env.DB.prepare(
    'SELECT username, role, avatar_url, bio FROM users WHERE username = ?'
  ).bind(session.username).first();
}
