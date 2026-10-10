import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, existsSync } from 'node:fs';

const read = (p) => readFileSync(new URL(p, import.meta.url), 'utf8');
const SITE = 'https://emdashcyber.com';
const SLUG = 'phishing-detection-decision-models';
const ARTICLE = `../dist/${SLUG}/index.html`;
const textOf = (html) => html.replace(/<script[\s\S]*?<\/script>/g, ' ').replace(/<[^>]+>/g, ' ').replace(/&amp;/g, '&').replace(/\s+/g, ' ');

const [head, ...body] = read('../src/data/model_summary.csv').trim().split(/\r?\n/);
const cols = head.split(',');
const summary = body.map((r) => Object.fromEntries(r.split(',').map((v, i) => [cols[i], v])));
const records = read('../src/data/predictions.jsonl').trim().split('\n').map((l) => JSON.parse(l));

test('record counts, confusion matrices, Brier scores and 429s match the summary', () => {
  assert.equal(records.length, 5000);
  assert.equal(summary.length, 5);
  for (const s of summary) {
    const mine = records.filter((p) => p.model_id === s.model_id);
    assert.equal(mine.length, 1000);
    assert.ok(mine.every((p) => p.status === 'ok'));
    assert.equal(mine.filter((p) => p.dataset_label === 1).length, 500);
    const counts = {
      tp: (p) => p.dataset_label === 1 && p.predicted_label === 1,
      tn: (p) => p.dataset_label === 0 && p.predicted_label === 0,
      fp: (p) => p.dataset_label === 0 && p.predicted_label === 1,
      fn: (p) => p.dataset_label === 1 && p.predicted_label === 0,
    };
    for (const [field, pred] of Object.entries(counts)) assert.equal(mine.filter(pred).length, +s[field], field);
    assert.equal((+s.tp + +s.tn) / 1000, +s.accuracy);
    const brier = mine.reduce((n, p) => n + (p.p_phishing - p.dataset_label) ** 2, 0) / 1000;
    assert.ok(Math.abs(brier - +s.brier_score) < 1e-6);
    const n429 = mine.flatMap((p) => p.attempts).filter((a) => a.http_status === 429).length;
    const pairs429 = mine.filter((p) => p.attempts.some((a) => a.http_status === 429)).length;
    const isMs = s.model_id.startsWith('microsoft/');
    assert.equal(n429, isMs ? 41 : 0);
    assert.equal(pairs429, isMs ? 36 : 0);
  }
  const total = summary.reduce((n, s) => n + +s.total_cost_usd, 0);
  assert.ok(Math.abs(total - 0.366369) < 1e-8);
});

test('committed data matches ../results when present', () => {
  const src = new URL('../../results/model_summary.csv', import.meta.url);
  if (!existsSync(src)) return;
  assert.equal(readFileSync(src, 'utf8'), read('../src/data/model_summary.csv'));
});

test('article has key figures and caveats', () => {
  const text = textOf(read(ARTICLE));
  for (const v of ['99.2%', '97.4%', '377 ms', '$0.0297', '41 HTTP 429s', '36 emails', '$0.37', 'human_verified=false', 'not a paired test', 'lower bound', 'The labels weren']) {
    assert.ok(text.includes(v), v);
  }
});

test('editorial figures match recorded attempts, confidence and agreement', () => {
  assert.equal(records.reduce((n, p) => n + p.attempts.length, 0), 5041);
  const groups = Map.groupBy(records, (p) => p.sample_id);
  const histogram = [0, 0, 0, 0, 0, 0];
  let majority = 0;
  for (const group of groups.values()) {
    assert.equal(group.length, 5);
    histogram[group.filter((p) => p.matched_ground_truth).length]++;
    majority += Number((group.filter((p) => p.predicted_label === 1).length >= 3 ? 1 : 0) === group[0].dataset_label);
  }
  assert.deepEqual(histogram, [2, 0, 9, 12, 26, 951]);
  assert.equal(majority, 989);
  for (const [id, wrong, high] of [['cloudflare/clef-flash', 8, 0], ['openai/gpt-6-luna-decisions', 11, 7]]) {
    const errors = records.filter((p) => p.model_id === id && !p.matched_ground_truth);
    assert.equal(errors.length, wrong);
    assert.equal(errors.filter((p) => p.confidence >= 0.9).length, high);
  }
  const text = textOf(read(ARTICLE));
  for (const phrase of ['5,041 recorded HTTP attempts', '10 October 2026', 'review volume', 'population and attack mix', 'recorded cost of about']) assert.ok(text.includes(phrase), phrase);
});

test('public downloads exclude email text and request IDs', () => {
  const bundle = JSON.parse(read('../dist/data/reproducibility.json'));
  assert.equal(bundle.records.length, 5000);
  const forbidden = new Set(['sender', 'subject', 'body', 'request_id', 'email_sha256', 'error', 'api_key_present']);
  const visit = (v) => {
    if (v && typeof v === 'object') for (const [k, x] of Object.entries(v)) { assert.ok(!forbidden.has(k), k); visit(x); }
  };
  visit(bundle.records);
});

const meta = (html, attr, name) => html.match(new RegExp(`<meta[^>]*${attr}="${name}"[^>]*content="([^"]*)"`))?.[1];

test('article SEO: title, canonical, Open Graph, Twitter and robots', () => {
  const html = read(ARTICLE);
  const url = `${SITE}/${SLUG}/`;
  const title = 'I tested five decision models on 1,000 phishing and legitimate emails';
  assert.match(html, /<title>Phishing Email Detection with Decision Models: 5 Models Compared \| EmDash Cyber<\/title>/);
  assert.ok(html.includes(`<link rel="canonical" href="${url}"`));
  assert.equal(meta(html, 'property', 'og:url'), url);
  assert.equal(meta(html, 'property', 'og:type'), 'article');
  assert.equal(meta(html, 'property', 'og:title'), title);
  assert.equal(meta(html, 'property', 'og:image'), `${SITE}/social-preview.png`);
  assert.equal(meta(html, 'property', 'og:image:width'), '1200');
  assert.equal(meta(html, 'property', 'og:image:height'), '630');
  assert.ok(meta(html, 'property', 'og:image:alt'));
  assert.equal(meta(html, 'name', 'twitter:card'), 'summary_large_image');
  assert.equal(meta(html, 'name', 'twitter:image'), `${SITE}/social-preview.png`);
  assert.equal(meta(html, 'property', 'article:published_time'), '2026-10-10');
  const desc = meta(html, 'name', 'description');
  assert.ok(desc.length >= 100 && desc.length <= 160, `description length ${desc.length}`);
  assert.ok(title.length <= 80, 'headline fits HN limit');
  assert.ok(!html.includes('content="noindex"'));
  assert.equal([...html.matchAll(/<h1[\s>]/g)].length, 1);
  assert.ok(html.includes('<html lang="en">'));
  assert.ok(existsSync(new URL('../dist/social-preview.png', import.meta.url)));
});

test('JSON-LD parses and describes the article, breadcrumb and dataset', () => {
  const html = read(ARTICLE);
  const raw = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/)?.[1];
  assert.ok(raw, 'json-ld present');
  const graph = JSON.parse(raw)['@graph'];
  const types = graph.map((n) => n['@type']);
  for (const t of ['Organization', 'Person', 'TechArticle', 'BreadcrumbList', 'Dataset']) assert.ok(types.includes(t), t);
  const article = graph.find((n) => n['@type'] === 'TechArticle');
  assert.equal(article.url, `${SITE}/${SLUG}/`);
  assert.ok(article.headline.length <= 110);
  assert.equal(graph.find((n) => n['@type'] === 'Person').name, 'Gavin Eke');
});

test('home page is indexable with its own canonical and no article metadata', () => {
  const html = read('../dist/index.html');
  assert.ok(html.includes(`<link rel="canonical" href="${SITE}/"`));
  assert.equal(meta(html, 'property', 'og:type'), 'website');
  assert.ok(html.includes(`href="/${SLUG}/"`));
  assert.ok(!html.includes('article:published_time'));
  assert.match(html, /<h1 id="site-title">EmDash Cyber<\/h1>/);
  assert.match(html, /<h2 id="posts-title">Posts<\/h2>/);
});

test('header holds only the brand and theme toggle', () => {
  for (const file of ['../dist/index.html', ARTICLE, '../dist/404.html']) {
    const header = read(file).match(/<header class="site-header">([\s\S]*?)<\/header>/)[1];
    assert.ok(header.includes('EmDash Cyber'));
    assert.ok(!header.includes('<nav'), file);
    assert.equal([...header.matchAll(/<a /g)].length, 1, file);
  }
});

test('sitemap and robots list exactly the indexable pages', () => {
  const sitemap = read('../dist/sitemap.xml');
  assert.deepEqual([...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map((m) => m[1]), [`${SITE}/`, `${SITE}/${SLUG}/`]);
  assert.ok(read('../dist/robots.txt').includes(`Sitemap: ${SITE}/sitemap.xml`));
});

test('only the theme script and JSON-LD ship; no third-party requests', () => {
  for (const file of ['../dist/index.html', ARTICLE, '../dist/404.html']) {
    const html = read(file);
    const scripts = [...html.matchAll(/<script\b([^>]*)>/g)].map((m) => m[1]);
    for (const attrs of scripts) assert.ok(/src="\/theme\.js"/.test(attrs) || /application\/ld\+json/.test(attrs), attrs);
    assert.ok(!/(?:src|href)="https?:\/\/(?!huggingface\.co|zenodo\.org|doi\.org|emdashcyber\.com)/.test(html), file);
  }
  const js = read('../dist/theme.js');
  assert.ok(js.includes('emdash-theme') && js.length < 2000);
});

test('internal links and anchors resolve', () => {
  const html = read(ARTICLE);
  const ids = new Set([...html.matchAll(/\bid="([^"]+)"/g)].map((m) => m[1]));
  for (const m of html.matchAll(/href="#([^"]+)"/g)) assert.ok(ids.has(m[1]), `#${m[1]}`);
  for (const file of ['../dist/index.html', ARTICLE, '../dist/404.html']) {
    for (const m of read(file).matchAll(/(?:href|src)="(\/[^"#]*)(?:#[^"]*)?"/g)) {
      const p = m[1];
      const target = p.endsWith('/') ? `../dist${p}index.html` : `../dist${p}`;
      assert.ok(existsSync(new URL(target, import.meta.url)), p);
    }
  }
});

test('404 is noindex and carries no article metadata', () => {
  const missing = read('../dist/404.html');
  assert.ok(missing.includes('content="noindex"'));
  assert.ok(!missing.includes('rel="canonical"'));
  assert.ok(!missing.includes('og:type'));
  assert.ok(!missing.includes('property="og:image"'));
  assert.ok(missing.includes(`href="/${SLUG}/"`));
});

test('theme toggle exists, is hidden without script and is a labelled button', () => {
  const html = read(ARTICLE);
  assert.match(html, /<button id="theme-toggle"[^>]*aria-pressed="false"[^>]*hidden/);
  assert.ok(html.includes('class="skip" href="#main"'));
  assert.ok(html.includes('id="main"'));
});

const luminance = (hex) => {
  const c = [1, 3, 5].map((i) => parseInt(hex.slice(i, i + 2), 16) / 255).map((v) => (v <= 0.03928 ? v / 12.92 : ((v + 0.055) / 1.055) ** 2.4));
  return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2];
};
const ratio = (a, b) => {
  const [hi, lo] = [luminance(a), luminance(b)].sort((x, y) => y - x);
  return (hi + 0.05) / (lo + 0.05);
};

test('light and dark palettes meet WCAG contrast', () => {
  const css = read('../src/styles/global.css');
  const tokens = Object.fromEntries([...css.matchAll(/--([\w-]+):\s*light-dark\((#[0-9a-f]{6}),\s*(#[0-9a-f]{6})\)/g)].map((m) => [m[1], [m[2], m[3]]]));
  const pairs = [
    ['fg', 'bg', 4.5], ['fg', 'surface', 4.5], ['heading', 'bg', 4.5], ['muted', 'bg', 4.5], ['muted', 'surface', 4.5],
    ['accent', 'bg', 4.5], ['accent', 'surface', 4.5], ['accent-ink', 'accent', 4.5],
    ['miss', 'bg', 3], ['false-alarm', 'bg', 3], ['miss', 'surface', 3], ['false-alarm', 'surface', 3],
    ...['jev', 'openai', 'clef', 'flash', 'ms'].flatMap((k) => [[`c-${k}`, 'bg', 3], ['bg', `c-${k}`, 4.5]]),
  ];
  for (const [fgName, bgName, min] of pairs) {
    for (const [i, theme] of ['light', 'dark'].entries()) {
      const r = ratio(tokens[fgName][i], tokens[bgName][i]);
      assert.ok(r >= min, `${theme} ${fgName} on ${bgName}: ${r.toFixed(2)} < ${min}`);
    }
  }
});
