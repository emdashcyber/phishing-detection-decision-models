const configuredSite = import.meta.env.SITE ?? 'https://emdashcyber.com';
const configuredBase = import.meta.env.BASE_URL ?? '/';

export const SITE = configuredSite.replace(/\/+$/, '');
const normalizedBase = configuredBase.startsWith('/') ? configuredBase : `/${configuredBase}`;
export const BASE_URL = normalizedBase.endsWith('/') ? normalizedBase : `${normalizedBase}/`;
const BASE_PREFIX = BASE_URL === '/' ? '' : BASE_URL.replace(/\/$/, '');

export const withBase = (path: string) => {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  if (!BASE_PREFIX || normalizedPath === BASE_PREFIX || normalizedPath.startsWith(`${BASE_PREFIX}/`)) {
    return normalizedPath;
  }
  return `${BASE_PREFIX}${normalizedPath}`;
};

export const abs = (path: string) => new URL(withBase(path), `${SITE}/`).href;

export const SITE_NAME = 'EmDash Cyber';
export const AUTHOR = 'Gavin Eke';
export const ARTICLE_PATH = BASE_URL;
export const PUBLISHED = '2026-10-10';
export const OG_IMAGE = '/social-preview.png';

const siteRoot = `${SITE}/`;

export const organization = {
  '@type': 'Organization',
  '@id': `${siteRoot}#organization`,
  name: SITE_NAME,
  url: siteRoot,
  logo: { '@type': 'ImageObject', url: abs('/icon-512.png'), width: 512, height: 512 },
};

export const author = {
  '@type': 'Person',
  '@id': `${siteRoot}#author`,
  name: AUTHOR,
  worksFor: { '@id': organization['@id'] },
};
