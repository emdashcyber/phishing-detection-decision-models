Email phishing decision-model benchmark

## Summary

- Use `Nazario_5.csv` from the [AURA Phishing Email Corpus](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus). It has separate `sender`, `subject`, `body`, and `label` fields, with 1,565 phishing and 1,500 legitimate emails—enough to randomly sample 500 of each. 
- Send only sender, subject, and body to the models. Keep URL text that appears in the body, as requested; exclude the separate URL field and other metadata. AURA notes that its historical emails can contain real names and addresses and date from 1995–2022, so results should be read as performance on this corpus, not as a measure of current phishing prevalence. [AURA dataset details](https://huggingface.co/datasets/kudzaiprichard/aura-phishing-email-corpus)

## Implementation

Run one typed binary decision per model for each of the 1,000 sampled emails: **5,000 calls total**. Use the same question and label definitions for every model, without examples or ground-truth labels in the request. Pin Jev to version 1.13 for reproducibility.

| Model | OpenRouter ID | Listed input price per 1M tokens* |
|---|---|---:|
| Jev 1.13 | `typesafe/jev-1.13` | $0.042 [source](https://openrouter.ai/typesafe/jev-1.13) |
| OpenAI Decisions (GPT-6 Luna Decisions) | `openai/gpt-6-luna-decisions` | $0.10 [source](https://openrouter.ai/openai/gpt-6-luna-decisions) |
| Clef | `cloudflare/clef` | $0.24 [source](https://openrouter.ai/cloudflare/clef) |
| Clef Flash | `cloudflare/clef-flash` | $0.038 [source](https://openrouter.ai/cloudflare/clef-flash) |
| Microsoft-Decision-1 | `microsoft/microsoft-decision-1` | $0.042 [source](https://openrouter.ai/microsoft/microsoft-decision-1) |

\*Prices are the current model-page rates; capture the rate snapshot and actual per-call charges during the run. 

## Recorded results and report

- Sample 500 emails per label with a fixed random seed. Save the sample manifest and original labels.
- For every model/email result, record the dataset label, predicted label, match flag, phishing and benign probabilities, confidence for the predicted label, end-to-end latency, token usage, actual cost, model ID, status/errors, and `human_verified=false`.
- Save per-call records to `results/predictions.jsonl`, aggregate metrics to `results/model_summary.csv`, and a comparison to `results/report.md`. Report accuracy, phishing precision/recall/F1, specificity, confusion matrix, Brier score, median and p95 latency, total cost, and cost per correct classification.
- Show the highest-accuracy, fastest, and lowest-cost models separately, plus the Pareto frontier; don’t invent an overall weighted winner without agreed weights.

## Validation and assumptions

- Confirm the sample has exactly 500 phishing and 500 legitimate emails with all three input fields present. Verify requests contain no label, recipient, date, separate URL field, or other dataset metadata.
- Run each email’s five model calls in parallel with a consistent concurrency limit; measure latency from request start to response receipt. Retry transient failures at most twice, recording every attempt and its cost; report coverage if any calls still fail.
- Confidence comes from each model’s returned probability for its selected label. Human verification is not performed; the field records that explicitly.
