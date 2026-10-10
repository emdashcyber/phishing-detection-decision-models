import { readFileSync, writeFileSync, mkdirSync, copyFileSync, existsSync } from 'node:fs';

const source = new URL('../../results/', import.meta.url);
const dest = new URL('../src/data/', import.meta.url);
const publicDir = new URL('../public/data/', import.meta.url);

// Generated files are committed, so builds still work when ../results is absent.
if (!existsSync(new URL('predictions.jsonl', source))) {
  console.log('No ../results found; using committed sanitized data.');
  process.exit(0);
}

mkdirSync(dest, { recursive: true });
mkdirSync(publicDir, { recursive: true });

const pick = (obj, keys) => Object.fromEntries(keys.filter((k) => k in obj).map((k) => [k, obj[k]]));

const recordKeys = [
  'sample_id', 'model_id', 'dataset_label', 'predicted_label', 'matched_ground_truth',
  'confidence', 'p_phishing', 'p_benign', 'human_verified', 'latency_ms', 'cost_usd',
  'status', 'input_tokens', 'output_tokens', 'provider', 'served_model',
];
const attemptKeys = ['http_status', 'latency_ms', 'cost_usd', 'cost_source'];
const metaKeys = [
  'benchmark', 'created_at_utc', 'dataset_id', 'dataset_file', 'dataset_file_sha256',
  'sampling_seed', 'sample_per_class', 'expected_sample_count', 'expected_logical_calls',
  'eligible_row_counts_and_exclusions', 'model_ids', 'request_state_fields',
  'human_review_performed', 'latency_definition', 'request_policy',
];

const records = readFileSync(new URL('predictions.jsonl', source), 'utf8')
  .trim().split('\n').map((l) => JSON.parse(l))
  .map((p) => ({ ...pick(p, recordKeys), attempts: p.attempts.map((a) => pick(a, attemptKeys)) }));
const metadata = pick(JSON.parse(readFileSync(new URL('run_metadata.json', source), 'utf8')), metaKeys);

writeFileSync(new URL('predictions.jsonl', dest), records.map((r) => JSON.stringify(r)).join('\n') + '\n');
writeFileSync(new URL('run_metadata.json', dest), JSON.stringify(metadata, null, 2));
copyFileSync(new URL('model_summary.csv', source), new URL('model_summary.csv', dest));
copyFileSync(new URL('model_summary.csv', source), new URL('model_summary.csv', publicDir));
writeFileSync(new URL('reproducibility.json', publicDir), JSON.stringify({ metadata, records }));
console.log('Prepared sanitized benchmark data.');
