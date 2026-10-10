# Email phishing decision-model benchmark

Generated: 2026-10-10T03:17:30.072+00:00

## Dataset and protocol

- Dataset: `kudzaiprichard/aura-phishing-email-corpus` / `Nazario_5.csv`.
- Sample: 500 phishing and 500 benign emails, random seed `20261010`.
- Model input contains only `sender`, `subject`, and `body`; URLs inside body text remain. The separate `urls` column and ground-truth labels are not sent.
- Human review was not performed. AURA contains historical messages and identifies some real names and addresses in its source corpora.
- Latency is client-observed wall time from first request to final response within the invocation that produced the decision, including retries and retry waits in that invocation. Failed attempts from earlier resumptions remain in attempt history but are not added to latency.
- Cost uses OpenRouter usage when present; otherwise the recorded price snapshot and token count are used as an estimate.
- The JSONL is consolidated to one row per model/email pair. Retry and rate-limit attempts are retained in each row; unsuccessful attempts without usage data have unknown charges.

## Results

| Model | Coverage | Accuracy | Balanced accuracy | Phishing precision | Phishing recall | F1 | Specificity | Brier | Median ms | P95 ms | Total cost USD | Cost / correct USD | Pareto |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|:---:|
| Jev 1.13 | 1000/1000 (100.0%) | 0.9820 | 0.9820 | 0.9879 | 0.9760 | 0.9819 | 0.9880 | 0.0142 | 482.1 | 638.4 | 0.041479 | 0.00004224 | yes |
| OpenAI Decisions (GPT-6 Luna Decisions) | 1000/1000 (100.0%) | 0.9890 | 0.9890 | 0.9900 | 0.9880 | 0.9890 | 0.9900 | 0.0091 | 376.7 | 590.5 | 0.074198 | 0.00007502 | yes |
| Clef | 1000/1000 (100.0%) | 0.9760 | 0.9760 | 0.9577 | 0.9960 | 0.9765 | 0.9560 | 0.0168 | 672.2 | 1810.8 | 0.190778 | 0.00019547 | no |
| Clef Flash | 1000/1000 (100.0%) | 0.9920 | 0.9920 | 0.9862 | 0.9980 | 0.9920 | 0.9860 | 0.0105 | 640.5 | 1393.1 | 0.030207 | 0.00003045 | yes |
| Microsoft-Decision-1 | 1000/1000 (100.0%) | 0.9740 | 0.9740 | 0.9665 | 0.9820 | 0.9742 | 0.9660 | 0.0181 | 564.0 | 1310.6 | 0.029707 | 0.00003050 | yes |

## Leaders by metric

- Highest accuracy: Clef Flash.
- Fastest median latency: OpenAI Decisions (GPT-6 Luna Decisions).
- Lowest total cost: Microsoft-Decision-1.
- Pareto-efficient models: Jev 1.13, OpenAI Decisions (GPT-6 Luna Decisions), Clef Flash, Microsoft-Decision-1.
- No combined winner is calculated because no weights were set for accuracy, speed, and price.

## Per-model error and confidence detail

| Model | TP | TN | FP | FN | Final failed pairs | Probability rows for Brier |
|---|---:|---:|---:|---:|---:|---:|
| Jev 1.13 | 488 | 494 | 6 | 12 | 0 | 1000 |
| OpenAI Decisions (GPT-6 Luna Decisions) | 494 | 495 | 5 | 6 | 0 | 1000 |
| Clef | 498 | 478 | 22 | 2 | 0 | 1000 |
| Clef Flash | 499 | 493 | 7 | 1 | 0 | 1000 |
| Microsoft-Decision-1 | 491 | 483 | 17 | 9 | 0 | 1000 |

## Request reliability and rate snapshot

| Model | Listed input USD / 1M tokens | Request attempts | Retry attempts | Failed attempts | Pairs with retries | Unknown-cost attempts |
|---|---:|---:|---:|---:|---:|---:|
| Jev 1.13 | 0.042000 | 1000 | 0 | 0 | 0 | 0 |
| OpenAI Decisions (GPT-6 Luna Decisions) | 0.100000 | 1000 | 0 | 0 | 0 | 0 |
| Clef | 0.240000 | 1000 | 0 | 0 | 0 | 0 |
| Clef Flash | 0.038000 | 1000 | 0 | 0 | 0 | 0 |
| Microsoft-Decision-1 | 0.042000 | 1041 | 41 | 41 | 36 | 41 |

## Artifacts

- `results/sample_manifest.csv`: sampled dataset row numbers, labels, and hashes; no email content.
- `results/predictions.jsonl`: one logical result per model and email, including confidence/probabilities, attempts, latency, usage, and cost; no email content.
- `results/model_summary.csv`: metric table.
- `results/run_metadata.json`: dataset checksum, seed, model price snapshot, and protocol.
