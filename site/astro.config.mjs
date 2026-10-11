import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://emdashcyber.com',
  base: '/phishing-detection-decision-models',
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
  // Keeps page scripts as files so the meta CSP can use script-src 'self'.
  vite: { build: { assetsInlineLimit: 0 } },
});
