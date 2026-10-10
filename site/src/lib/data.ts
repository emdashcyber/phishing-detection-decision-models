import { readFileSync } from 'node:fs';
import { join } from 'node:path';

const dataDir = join(process.cwd(), 'src', 'data');

export interface Model {
  id: string;
  key: 'jev' | 'openai' | 'clef' | 'flash' | 'ms';
  name: string;
  short: string;
  provider: string;
  servedModel: string;
  validCalls: number;
  accuracy: number;
  accuracyCI: [number, number];
  precision: number;
  recall: number;
  f1: number;
  specificity: number;
  tp: number;
  tn: number;
  fp: number;
  fn: number;
  brier: number;
  medianMs: number;
  p95Ms: number;
  totalCost: number;
  costPerCorrect: number;
  costPer1k: number;
  listedInputPerM: number;
  meanInputTokens: number;
  meanOutputTokens: number;
  retryAttempts: number;
  unknownCostAttempts: number;
  rateLimitAttempts: number;
  rateLimitedPairs: number;
  pareto: boolean;
  meanConfidenceCorrect: number;
  meanConfidenceWrong: number;
  wrongHighConfidence: number;
  wrongTotal: number;
}

const KEYS: Record<string, { key: Model['key']; short: string }> = {
  'typesafe/jev-1.13': { key: 'jev', short: 'Jev' },
  'openai/gpt-6-luna-decisions': { key: 'openai', short: 'GPT-6 Luna Decisions' },
  'cloudflare/clef': { key: 'clef', short: 'Clef' },
  'cloudflare/clef-flash': { key: 'flash', short: 'Clef Flash' },
  'microsoft/microsoft-decision-1': { key: 'ms', short: 'Microsoft-Decision-1' },
};

function parseCsv(text: string): Record<string, string>[] {
  const [head, ...rows] = text.trim().split(/\r?\n/);
  const cols = head.split(',');
  return rows.map((r) => {
    const cells = r.split(',');
    if (cells.length !== cols.length) throw new Error(`Unexpected CSV row: ${r}`);
    return Object.fromEntries(cols.map((c, i) => [c, cells[i]]));
  });
}

export function wilson(k: number, n: number, z = 1.96): [number, number] {
  const p = k / n;
  const d = 1 + (z * z) / n;
  const c = p + (z * z) / (2 * n);
  const m = z * Math.sqrt((p * (1 - p)) / n + (z * z) / (4 * n * n));
  return [(c - m) / d, (c + m) / d];
}

interface Pred {
  sample_id: string;
  model_id: string;
  dataset_label: number;
  predicted_label: number;
  matched_ground_truth: boolean;
  confidence: number | null;
  input_tokens: number;
  output_tokens: number;
  provider: string;
  served_model: string;
  attempts: { http_status: number }[];
}

const preds: Pred[] = readFileSync(join(dataDir, 'predictions.jsonl'), 'utf8')
  .trim().split('\n').map((l) => JSON.parse(l));
export const metadata = JSON.parse(readFileSync(join(dataDir, 'run_metadata.json'), 'utf8'));
const summaryRows = parseCsv(readFileSync(join(dataDir, 'model_summary.csv'), 'utf8'));

const mean = (xs: number[]) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : NaN);
const confs = (ps: Pred[]) => ps.map((p) => p.confidence).filter((c): c is number => c != null);

export const models: Model[] = summaryRows.map((r) => {
  const mine = preds.filter((p) => p.model_id === r.model_id);
  const right = mine.filter((p) => p.matched_ground_truth);
  const wrong = mine.filter((p) => !p.matched_ground_truth);
  const n = Number(r.n_valid);
  const totalCost = Number(r.total_cost_usd);
  const attempts429 = (p: Pred) => p.attempts.filter((a) => a.http_status === 429).length;
  return {
    id: r.model_id,
    key: KEYS[r.model_id].key,
    name: r.model_name,
    short: KEYS[r.model_id].short,
    provider: mine[0].provider,
    servedModel: mine[0].served_model,
    validCalls: n,
    accuracy: Number(r.accuracy),
    accuracyCI: wilson(right.length, n),
    precision: Number(r.precision_phishing),
    recall: Number(r.recall_phishing),
    f1: Number(r.f1_phishing),
    specificity: Number(r.specificity),
    tp: Number(r.tp),
    tn: Number(r.tn),
    fp: Number(r.fp),
    fn: Number(r.fn),
    brier: Number(r.brier_score),
    medianMs: Number(r.median_latency_ms),
    p95Ms: Number(r.p95_latency_ms),
    totalCost,
    costPerCorrect: Number(r.cost_per_correct_usd),
    costPer1k: (totalCost / n) * 1000,
    listedInputPerM: Number(r.listed_input_per_million_usd),
    meanInputTokens: mean(mine.map((p) => p.input_tokens)),
    meanOutputTokens: mean(mine.map((p) => p.output_tokens)),
    retryAttempts: Number(r.retry_attempts),
    unknownCostAttempts: Number(r.unknown_cost_attempts),
    rateLimitAttempts: mine.reduce((s, p) => s + attempts429(p), 0),
    rateLimitedPairs: mine.filter((p) => attempts429(p) > 0).length,
    pareto: r.pareto_frontier === 'True',
    meanConfidenceCorrect: mean(confs(right)),
    meanConfidenceWrong: mean(confs(wrong)),
    wrongHighConfidence: confs(wrong).filter((c) => c >= 0.9).length,
    wrongTotal: wrong.length,
  };
});

export const byKey = Object.fromEntries(models.map((m) => [m.key, m])) as Record<Model['key'], Model>;

const bySample = new Map<string, Pred[]>();
for (const p of preds) {
  if (!bySample.has(p.sample_id)) bySample.set(p.sample_id, []);
  bySample.get(p.sample_id)!.push(p);
}

const histogram = [0, 0, 0, 0, 0, 0]; // index = number of models that were correct
const allWrongByLabel = { phishing: 0, benign: 0 };
const soleMiss: Record<string, number> = {};
let majorityCorrect = 0;
for (const group of bySample.values()) {
  const correct = group.filter((p) => p.matched_ground_truth).length;
  histogram[correct]++;
  const phishVotes = group.filter((p) => p.predicted_label === 1).length;
  if ((phishVotes * 2 > group.length ? 1 : 0) === group[0].dataset_label) majorityCorrect++;
  if (correct === 0) allWrongByLabel[group[0].dataset_label === 1 ? 'phishing' : 'benign']++;
  if (correct === group.length - 1) {
    const culprit = group.find((p) => !p.matched_ground_truth)!;
    soleMiss[culprit.model_id] = (soleMiss[culprit.model_id] ?? 0) + 1;
  }
}

export const agreement = {
  emails: bySample.size,
  histogram,
  unanimousCorrect: histogram[5],
  allWrong: histogram[0],
  allWrongByLabel,
  soleMiss,
  majorityCorrect,
};

const elig = metadata.eligible_row_counts_and_exclusions;
export const totals = {
  calls: preds.length,
  attempts: preds.reduce((n, p) => n + p.attempts.length, 0),
  reportedCost: models.reduce((a, m) => a + m.totalCost, 0),
  emails: bySample.size,
  rows: elig.rows as number,
  excluded: elig.missing_required_fields as number,
  seed: metadata.sampling_seed as number,
  sha256: metadata.dataset_file_sha256 as string,
};

export const fmt = {
  pct: (x: number, d = 1) => (x * 100).toFixed(d) + '%',
  ms: (x: number) => Math.round(x).toLocaleString('en-US') + ' ms',
  usd: (x: number, d = 4) => '$' + x.toFixed(d),
  int: (x: number) => Math.round(x).toLocaleString('en-US'),
};
