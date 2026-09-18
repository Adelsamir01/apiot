# Sanitized run summaries

Per-run outputs supporting the paper's artifact release.

## Per run (when available)

| File | Contents |
|---|---|
| `run_result.json` | Outcome, protocol, topology, model, overseer/impairment/blind flags, turns, tool-call counts |
| `attack_log.json` | Tool outcomes and payload metadata (secrets redacted) |
| `token_summary.json` | Per-event token_count logs for inspecting token use |

## Excluded

- Raw SQLite memory.db files and host session logs
- API keys, credentials, and environment-specific secrets

## Inventory

See `../tables/run_index.csv` and `../tables/batch_summary.csv`.

This directory contains the sanitized inspection set released with the artifact (mission outcomes, tool logs, and token-use summaries). Aggregate results in the manuscript are computed over the full evaluation programme described there.
