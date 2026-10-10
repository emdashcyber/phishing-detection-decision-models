import type { APIRoute } from 'astro';
import { ARTICLE_PATH, PUBLISHED, abs } from '../lib/site';

const urls = [
  { loc: abs(ARTICLE_PATH), lastmod: PUBLISHED },
];

export const GET: APIRoute = () =>
  new Response(
    `<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n${urls
      .map((u) => `  <url><loc>${u.loc}</loc><lastmod>${u.lastmod}</lastmod></url>`)
      .join('\n')}\n</urlset>\n`,
    { headers: { 'Content-Type': 'application/xml; charset=utf-8' } },
  );
