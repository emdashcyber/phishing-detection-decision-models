import { readFileSync, copyFileSync } from 'node:fs';
import sharp from 'sharp';

const pub = (f) => new URL(`../public/${f}`, import.meta.url);
const mark = readFileSync(pub('emdash-mark.svg'));
copyFileSync(pub('emdash-mark.svg'), pub('favicon.svg'));

// Full-bleed square for the apple-touch icon, since iOS fills transparency with black.
const fullBleed = Buffer.from(
  `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" fill="#0b3558"/><path d="M18 17v30M18 20h20M18 32h15M18 44h20M43 32h10" fill="none" stroke="#70bdff" stroke-width="6" stroke-linecap="round"/></svg>`,
);

await sharp(mark, { density: 600 }).resize(32, 32).png().toFile(pub('favicon-32.png').pathname);
await sharp(mark, { density: 600 }).resize(512, 512).png().toFile(pub('icon-512.png').pathname);
await sharp(fullBleed, { density: 600 }).resize(180, 180).png().toFile(pub('apple-touch-icon.png').pathname);
console.log('Wrote EmDash icons.');
