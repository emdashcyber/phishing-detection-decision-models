import { readFileSync } from 'node:fs';
import sharp from 'sharp';

const [head, ...lines] = readFileSync(new URL('../src/data/model_summary.csv', import.meta.url), 'utf8').trim().split('\n');
const cols = head.split(',');
const models = lines
  .map((line) => Object.fromEntries(line.split(',').map((v, i) => [cols[i], v])))
  .sort((a, b) => b.accuracy - a.accuracy);

const colours = {
  'typesafe/jev-1.13': '#e8a53a',
  'openai/gpt-6-luna-decisions': '#56b4e9',
  'cloudflare/clef': '#e58ac0',
  'cloudflare/clef-flash': '#3fcf9f',
  'microsoft/microsoft-decision-1': '#a99bff',
};
const lo = Math.min(...models.map((m) => +m.accuracy));
const hi = Math.max(...models.map((m) => +m.accuracy));
const pct = (v) => (v * 100).toFixed(1) + '%';

const rows = models
  .map((m, i) => {
    const y = 404 + i * 38;
    const name = m.model_name.replace(' (GPT-6 Luna Decisions)', '');
    const width = 40 + ((+m.accuracy - 0.96) / 0.04) * 400;
    return `<text x="64" y="${y}" fill="#9fb3c8" font-size="21">${name}</text><rect x="330" y="${y - 16}" width="${width}" height="16" rx="3" fill="${colours[m.model_id]}"/><text x="${344 + width}" y="${y}" fill="#ffffff" font-size="21" font-weight="700">${pct(+m.accuracy)}</text>`;
  })
  .join('');

const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630"><rect width="1200" height="630" fill="#0a1420"/>
<g font-family="Helvetica,Arial,sans-serif">
<rect x="64" y="52" width="56" height="56" rx="13" fill="#0b3558"/><path d="M76 66v28M76 69h18M76 80h13M76 91h18M99 80h9" fill="none" stroke="#70bdff" stroke-width="5.5" stroke-linecap="round"/>
<text x="136" y="88" fill="#70bdff" font-size="20" font-weight="700" letter-spacing="3">EMDASH CYBER / RESEARCH</text>
<text x="64" y="188" fill="#ffffff" font-size="56" font-weight="800" letter-spacing="-1.5">I tested five decision models on</text>
<text x="64" y="254" fill="#ffffff" font-size="56" font-weight="800" letter-spacing="-1.5">1,000 phishing and legitimate emails</text>
<text x="64" y="304" fill="#9fb3c8" font-size="24">Accuracy was ${pct(lo)} to ${pct(hi)}. The mistakes, confidence, latency and cost were not.</text>
<line x1="64" y1="336" x2="1136" y2="336" stroke="#28405a"/>
<text x="64" y="368" fill="#9fb3c8" font-size="15" letter-spacing="1.5">OBSERVED ACCURACY · BALANCED SAMPLE · UNVERIFIED LABELS · BARS START AT 96%</text>
${rows}
<text x="64" y="602" fill="#9fb3c8" font-size="17">emdashcyber.com/phishing-detection-decision-models</text>
<text x="1136" y="602" fill="#9fb3c8" font-size="17" text-anchor="end">10 OCT 2026 · 5,000 DECISIONS</text>
</g></svg>`;

await sharp(Buffer.from(svg)).png().toFile(new URL('../public/social-preview.png', import.meta.url).pathname);
console.log('Wrote EmDash social preview.');
