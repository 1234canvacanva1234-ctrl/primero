export async function onRequest(context) {
  const { request, env, url } = context;
  
  // Enable CORS for all responses
  const corsHeaders = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Cookie',
    'Access-Control-Allow-Credentials': 'true'
  };

  // Handle preflight requests
  if (request.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    const path = new URL(request.url).pathname;
    console.log('Request path:', path);
    console.log('Request method:', request.method);

    // ===== AUTH ROUTES =====
    if (path === '/api/auth/signup' && request.method === 'POST') {
      return handleSignup(request, env, corsHeaders);
    }
    
    if (path === '/api/auth/signin' && request.method === 'POST') {
      return handleSignin(request, env, corsHeaders);
    }
    
    if (path === '/api/auth/signout' && request.method === 'POST') {
      return handleSignout(request, env, corsHeaders);
    }
    
    if (path === '/api/auth/status') {
      return handleStatus(request, env, corsHeaders);
    }

    // ===== ARTICLE ROUTES =====
    if (path === '/api/articles' && request.method === 'GET') {
      return getArticles(env, corsHeaders);
    }
    
    if (path === '/api/articles' && request.method === 'POST') {
      return createArticle(request, env, corsHeaders);
    }

    // Handle article by ID
    const articleMatch = path.match(/^\/api\/articles\/(\d+)$/);
    if (articleMatch) {
      const id = parseInt(articleMatch[1]);
      if (request.method === 'GET') {
        return getArticle(env, id, corsHeaders);
      }
      if (request.method === 'PUT') {
        return updateArticle(request, env, id, corsHeaders);
      }
      if (request.method === 'DELETE') {
        return deleteArticle(request, env, id, corsHeaders);
      }
    }

    // ===== USER ROUTES =====
    if (path === '/api/users' && request.method === 'GET') {
      return getUsers(request, env, corsHeaders);
    }

    const userMatch = path.match(/^\/api\/users\/(.+)\/grant$/);
    if (userMatch && request.method === 'POST') {
      const username = userMatch[1];
      return grantAdmin(request, env, username, corsHeaders);
    }

    // Test endpoint
    if (path === '/api/test') {
      return testEndpoint(env, corsHeaders);
    }

    // 404 - Route not found
    return jsonResponse({ 
      error: 'Not found', 
      path: path,
      method: request.method 
    }, 404, corsHeaders);

  } catch (error) {
    console.error('API Error:', error);
    return jsonResponse({ 
      error: 'Internal server error',
      details: error.message,
      stack: error.stack 
    }, 500, corsHeaders);
  }
}

// ============================================
// AUTH HANDLERS
// ============================================

async function handleSignup(request, env, corsHeaders) {
  try {
    const body = await request.json();
    console.log('Signup attempt:', { username: body.username });
    
    const { username, password } = body;
    
    // Validation
    if (!username || !password) {
      return jsonResponse({ error: 'Username and password required' }, 400, corsHeaders);
    }
    
    if (username.length < 3) {
      return jsonResponse({ error: 'Username must be at least 3 characters' }, 400, corsHeaders);
    }
    
    if (password.length < 8) {
      return jsonResponse({ error: 'Password must be at least 8 characters' }, 400, corsHeaders);
    }
    
    // Check if user exists
    const existing = await env.DB.prepare(
      'SELECT username FROM users WHERE username = ?'
    ).bind(username).first();
    
    if (existing) {
      return jsonResponse({ error: 'Username already taken' }, 409, corsHeaders);
    }
    
    // Hash password
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Create user
    const result = await env.DB.prepare(
      'INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)'
    ).bind(username, hashHex, 'user', new Date().toISOString()).run();
    
    console.log('User created:', username);
    
    // Create session
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, expiresAt).run();
    
    // Set cookie
    const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
    
    return jsonResponse({ 
      success: true, 
      message: 'User created successfully',
      username: username
    }, 200, corsHeaders, cookie);
    
  } catch (error) {
    console.error('Signup error:', error);
    return jsonResponse({ 
      error: 'Signup failed',
      details: error.message 
    }, 500, corsHeaders);
  }
}

async function handleSignin(request, env, corsHeaders) {
  try {
    const body = await request.json();
    console.log('Signin attempt:', { username: body.username });
    
    const { username, password } = body;
    
    if (!username || !password) {
      return jsonResponse({ error: 'Username and password required' }, 400, corsHeaders);
    }
    
    // Get user
    const user = await env.DB.prepare(
      'SELECT * FROM users WHERE username = ?'
    ).bind(username).first();
    
    if (!user) {
      return jsonResponse({ error: 'Invalid credentials' }, 401, corsHeaders);
    }
    
    // Verify password
    const hashBuffer = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(password));
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    
    if (user.password_hash !== hashHex) {
      return jsonResponse({ error: 'Invalid credentials' }, 401, corsHeaders);
    }
    
    // Create session
    const sessionId = crypto.randomUUID();
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
    
    await env.DB.prepare(
      'INSERT INTO sessions (session_id, username, expires_at) VALUES (?, ?, ?)'
    ).bind(sessionId, username, expiresAt).run();
    
    // Set cookie
    const cookie = `session=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${7 * 24 * 60 * 60}`;
    
    return jsonResponse({ 
      success: true, 
      message: 'Signed in successfully',
      username: username,
      role: user.role
    }, 200, corsHeaders, cookie);
    
  } catch (error) {
    console.error('Signin error:', error);
    return jsonResponse({ 
      error: 'Signin failed',
      details: error.message 
    }, 500, corsHeaders);
  }
}

async function handleSignout(request, env, corsHeaders) {
  try {
    const cookie = request.headers.get('Cookie') || '';
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];
    
    if (sessionId) {
      await env.DB.prepare(
        'DELETE FROM sessions WHERE session_id = ?'
      ).bind(sessionId).run();
    }
    
    return jsonResponse({ 
      success: true, 
      message: 'Signed out successfully' 
    }, 200, corsHeaders, null, true);
    
  } catch (error) {
    console.error('Signout error:', error);
    return jsonResponse({ error: 'Signout failed' }, 500, corsHeaders);
  }
}

async function handleStatus(request, env, corsHeaders) {
  try {
    const cookie = request.headers.get('Cookie') || '';
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];
    
    if (!sessionId) {
      return jsonResponse({ authenticated: false }, 200, corsHeaders);
    }
    
    // Check session
    const session = await env.DB.prepare(
      'SELECT * FROM sessions WHERE session_id = ?'
    ).bind(sessionId).first();
    
    if (!session) {
      return jsonResponse({ authenticated: false }, 200, corsHeaders);
    }
    
    // Check if session expired
    if (new Date(session.expires_at) < new Date()) {
      await env.DB.prepare(
        'DELETE FROM sessions WHERE session_id = ?'
      ).bind(sessionId).run();
      return jsonResponse({ authenticated: false }, 200, corsHeaders);
    }
    
    // Get user
    const user = await env.DB.prepare(
      'SELECT username, role FROM users WHERE username = ?'
    ).bind(session.username).first();
    
    if (!user) {
      return jsonResponse({ authenticated: false }, 200, corsHeaders);
    }
    
    return jsonResponse({ 
      authenticated: true, 
      user: user 
    }, 200, corsHeaders);
    
  } catch (error) {
    console.error('Status error:', error);
    return jsonResponse({ authenticated: false }, 500, corsHeaders);
  }
}

// ============================================
// ARTICLE HANDLERS
// ============================================

async function getArticles(env, corsHeaders) {
  try {
    const result = await env.DB.prepare(
      'SELECT id, title, content, author, created_at, updated_at FROM articles ORDER BY created_at DESC'
    ).all();
    
    return jsonResponse(result.results || [], 200, corsHeaders);
    
  } catch (error) {
    console.error('Get articles error:', error);
    return jsonResponse({ error: 'Failed to fetch articles' }, 500, corsHeaders);
  }
}

async function getArticle(env, id, corsHeaders) {
  try {
    const article = await env.DB.prepare(
      'SELECT * FROM articles WHERE id = ?'
    ).bind(id).first();
    
    if (!article) {
      return jsonResponse({ error: 'Article not found' }, 404, corsHeaders);
    }
    
    return jsonResponse(article, 200, corsHeaders);
    
  } catch (error) {
    console.error('Get article error:', error);
    return jsonResponse({ error: 'Failed to fetch article' }, 500, corsHeaders);
  }
}

async function createArticle(request, env, corsHeaders) {
  try {
    // Check authentication
    const user = await getSessionUser(request, env);
    if (!user) {
      return jsonResponse({ error: 'Authentication required' }, 401, corsHeaders);
    }
    
    if (user.role !== 'sysadmin') {
      return jsonResponse({ error: 'Admin access required' }, 403, corsHeaders);
    }
    
    const body = await request.json();
    const { title, content } = body;
    
    if (!title || !content) {
      return jsonResponse({ error: 'Title and content required' }, 400, corsHeaders);
    }
    
    const result = await env.DB.prepare(
      'INSERT INTO articles (title, content, author, created_at, updated_at) VALUES (?, ?, ?, ?, ?)'
    ).bind(title, content, user.username, new Date().toISOString(), new Date().toISOString()).run();
    
    return jsonResponse({ 
      success: true, 
      id: result.meta.last_row_id,
      message: 'Article created successfully' 
    }, 200, corsHeaders);
    
  } catch (error) {
    console.error('Create article error:', error);
    return jsonResponse({ error: 'Failed to create article' }, 500, corsHeaders);
  }
}

async function updateArticle(request, env, id, corsHeaders) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) {
      return jsonResponse({ error: 'Authentication required' }, 401, corsHeaders);
    }
    
    if (user.role !== 'sysadmin') {
      return jsonResponse({ error: 'Admin access required' }, 403, corsHeaders);
    }
    
    const body = await request.json();
    const { title, content } = body;
    
    if (!title || !content) {
      return jsonResponse({ error: 'Title and content required' }, 400, corsHeaders);
    }
    
    await env.DB.prepare(
      'UPDATE articles SET title = ?, content = ?, updated_at = ? WHERE id = ?'
    ).bind(title, content, new Date().toISOString(), id).run();
    
    return jsonResponse({ 
      success: true, 
      message: 'Article updated successfully' 
    }, 200, corsHeaders);
    
  } catch (error) {
    console.error('Update article error:', error);
    return jsonResponse({ error: 'Failed to update article' }, 500, corsHeaders);
  }
}

async function deleteArticle(request, env, id, corsHeaders) {
  try {
    const user = await getSessionUser(request, env);
    if (!user) {
      return jsonResponse({ error: 'Authentication required' }, 401, corsHeaders);
    }
    
    if (user.role !== 'sysadmin') {
      return jsonResponse({ error: 'Admin access required' }, 403, corsHeaders);
    }
    
    await env.DB.prepare(
      'DELETE FROM articles WHERE id = ?'
    ).bind(id).run();
    
    return jsonResponse({ 
      success: true, 
      message: 'Article deleted successfully' 
    }, 200, corsHeaders);
    
  } catch (error) {
    console.error('Delete article error:', error);
    return jsonResponse({ error: 'Failed to delete article' }, 500, corsHeaders);
  }
}

// ============================================
// USER HANDLERS
// ============================================

async function getUsers(request, env, corsHeaders) {
  try {
    const user = await getSessionUser(request, env);
    if (!user || user.role !== 'sysadmin') {
      return jsonResponse({ error: 'Admin access required' }, 403, corsHeaders);
    }
    
    const result = await env.DB.prepare(
      'SELECT username, role FROM users ORDER BY username'
    ).all();
    
    return jsonResponse(result.results || [], 200, corsHeaders);
    
  } catch (error) {
    console.error('Get users error:', error);
    return jsonResponse({ error: 'Failed to fetch users' }, 500, corsHeaders);
  }
}

async function grantAdmin(request, env, username, corsHeaders) {
  try {
    const user = await getSessionUser(request, env);
    if (!user || user.role !== 'sysadmin') {
      return jsonResponse({ error: 'Admin access required' }, 403, corsHeaders);
    }
    
    await env.DB.prepare(
      'UPDATE users SET role = ? WHERE username = ?'
    ).bind('sysadmin', username).run();
    
    return jsonResponse({ 
      success: true, 
      message: `Admin access granted to ${username}` 
    }, 200, corsHeaders);
    
  } catch (error) {
    console.error('Grant admin error:', error);
    return jsonResponse({ error: 'Failed to grant admin access' }, 500, corsHeaders);
  }
}

// ============================================
// TEST ENDPOINT
// ============================================

async function testEndpoint(env, corsHeaders) {
  try {
    // Test database connection
    const result = await env.DB.prepare('SELECT 1 as test').first();
    
    return jsonResponse({
      status: 'OK',
      database: 'Connected',
      test: result,
      timestamp: new Date().toISOString()
    }, 200, corsHeaders);
    
  } catch (error) {
    return jsonResponse({
      status: 'ERROR',
      database: 'Disconnected',
      error: error.message,
      timestamp: new Date().toISOString()
    }, 200, corsHeaders);
  }
}

// ============================================
// UTILITY FUNCTIONS
// ============================================

async function getSessionUser(request, env) {
  try {
    const cookie = request.headers.get('Cookie') || '';
    const sessionId = cookie.match(/session=([^;]+)/)?.[1];
    
    if (!sessionId) return null;
    
    const session = await env.DB.prepare(
      'SELECT * FROM sessions WHERE session_id = ?'
    ).bind(sessionId).first();
    
    if (!session) return null;
    if (new Date(session.expires_at) < new Date()) return null;
    
    const user = await env.DB.prepare(
      'SELECT username, role FROM users WHERE username = ?'
    ).bind(session.username).first();
    
    return user;
    
  } catch (error) {
    console.error('Get session user error:', error);
    return null;
  }
}

function jsonResponse(data, status = 200, corsHeaders = {}, cookie = null, clearCookie = false) {
  const headers = {
    'Content-Type': 'application/json',
    ...corsHeaders
  };
  
  if (cookie) {
    headers['Set-Cookie'] = cookie;
  }
  
  if (clearCookie) {
    headers['Set-Cookie'] = 'session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0';
  }
  
  return new Response(JSON.stringify(data), { status, headers });
}
