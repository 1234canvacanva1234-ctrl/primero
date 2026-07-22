function slugify(title) {
  return (title || 'Untitled')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '');
}

function escapeAttr(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

export async function onRequestGet(context) {
  const { params, request, env } = context;
  const slug = params.slug;

  // 1. Get the static articlespace.html shell via the built-in ASSETS binding
  const shellRequest = new Request(new URL('/articlespace.html', request.url), request);
  const shellResponse = await env.ASSETS.fetch(shellRequest);

  if (!shellResponse.ok) {
    return shellResponse;
  }

  let html = await shellResponse.text();

  // 2. Look up the article for this slug
  let article = null;
  try {
    const apiRes = await fetch(new URL('/api/articles', request.url));
    if (apiRes.ok) {
      const articles = await apiRes.json();
      const slugs = articles.map((a, index) => {
        let s = slugify(a.title);
        const dupCount = articles.filter((art, idx) => idx < index && slugify(art.title) === s).length;
        if (dupCount > 0) s += '-' + (dupCount + 1);
        return s;
      });
      const idx = slugs.indexOf(slug);
      if (idx !== -1) article = articles[idx];
    }
  } catch (err) {
    // If the API call fails, we just fall back to the generic shell meta tags
    console.error('Failed to fetch article for meta tags:', err);
  }

  // 3. Rewrite meta tags if we found a matching article
  if (article) {
    const title = article.title || 'Untitled';
    const rawDesc = (article.content || '').replace(/\s+/g, ' ').trim();
    const desc = rawDesc.length > 200 ? rawDesc.slice(0, 200) + '…' : rawDesc;
    const pageTitle = escapeAttr(title) + ' · SoraSys Articlespace';
    const ogTitle = escapeAttr(title);
    const ogDesc = escapeAttr(desc || 'Read this article on SoraSys Articlespace.');
    const ogUrl = request.url;

    html = html
      .replace(/<title>.*?<\/title>/s, `<title>${pageTitle}</title>`)
      .replace(/<meta property="og:url" content=".*?">/, `<meta property="og:url" content="${escapeAttr(ogUrl)}">`)
      .replace(/<meta property="og:title" content=".*?">/, `<meta property="og:title" content="${ogTitle}">`)
      .replace(/<meta property="og:description" content=".*?">/, `<meta property="og:description" content="${ogDesc}">`)
      .replace(/<meta name="twitter:title" content=".*?">/, `<meta name="twitter:title" content="${ogTitle}">`)
      .replace(/<meta name="twitter:description" content=".*?">/, `<meta name="twitter:description" content="${ogDesc}">`);
  }

  return new Response(html, {
    status: 200,
    headers: {
      'content-type': 'text/html;charset=UTF-8',
      // Don't let CDNs/browsers cache a stale per-article preview too long
      'cache-control': 'public, max-age=60',
    },
  });
}
