import { defineConfig } from 'astro/config';

export default defineConfig({
  site: 'https://emdashcyber.github.io',
  base: '/phishing-detection-decision-models',
  output: 'static',
  trailingSlash: 'always',
  build: { format: 'directory' },
});
