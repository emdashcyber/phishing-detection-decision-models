# Email phishing decision-model benchmark

This benchmark compares five structured decision models through OpenRouter on a reproducible, balanced sample from AURA's `Nazario_5.csv` corpus.

## Dataset and privacy

- Dataset: [AURA Phishing Email Corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus), file `Nazario_5.csv`.
- Original dataset citation: Champa, Rabbi, and Zibran (2023), [Phishing Email Curated Datasets](https://doi.org/10.5281/zenodo.8339691), CC BY 4.0.
- The runner samples 500 rows for label 1 (phishing) and 500 for label 0 (legitimate), using seed `20261010` by default. It excludes rows with a blank sender, subject, or body.
- Model requests contain only `sender`, `subject`, and `body`. Any URL text already in the body is retained. The separate `urls` column, receiver, date, label, source row number, and other dataset fields are not sent.
- This public historical corpus can contain real names and email addresses. The selected sender, subject, and body are transmitted to the model providers through OpenRouter. Result artifacts omit the email text.

## Models

| Model | OpenRouter model ID |
|---|---|
| Jev 1.13 | `typesafe/jev-1.13` |
| OpenAI Decisions (GPT-6 Luna Decisions) | `openai/gpt-6-luna-decisions` |
| Clef | `cloudflare/clef` |
| Clef Flash | `cloudflare/clef-flash` |
| Microsoft-Decision-1 | `microsoft/microsoft-decision-1` |

Laya is excluded. Listed rates and the exact model/provider returned are captured in `results/run_metadata.json` and individual results.

## Run

Python 3.10+ is sufficient; the runner uses the standard library only. Set `OPENROUTER_API_KEY` in the environment, then run:

```sh
python3 run_benchmark.py
```

To validate the dataset and prepare the manifest without making model calls:

```sh
python3 run_benchmark.py --prepare-only
```

The default execution sends one request per email/model pair (5,000 logical decisions), with the five model calls for each email run in parallel. Transient network errors and HTTP 429/5xx responses are retried at most twice within an invocation. Successful results are appended after every email batch; rerunning with the same sample skips already successful pairs and can retry pairs that previously failed. Before summaries are written, repeated invocations for a pair are consolidated into one JSONL record with the full attempt history.

## Output files

- `results/sample_manifest.csv`: sample order, dataset row numbers, labels, hashes, and seed; no email content.
- `results/predictions.jsonl`: one record per model/email decision with ground truth, prediction, correctness, probabilities, confidence, latency, token usage, cost, request/provider IDs, retry attempts, and `human_verified=false`; no email content.
- `results/model_summary.csv`: accuracy, balanced accuracy, phishing precision/recall/F1, specificity, confusion counts, Brier score, coverage, latency, and cost.
- `results/report.md`: readable comparison, per-metric leaders, and Pareto frontier.
- `results/run_metadata.json`: dataset checksum, counts/exclusions, sampling settings, endpoint, model IDs, price snapshot, and protocol.

Latency is client-observed end-to-end time and includes retries and retry waits within the invocation that produced the final decision. Cost uses OpenRouter's response usage when available; if omitted, it is estimated from token counts and the captured model price. Error attempts without usage are counted and flagged as unknown-cost attempts. The report shows separate leaders for accuracy, speed, and cost rather than a weighted overall score.
