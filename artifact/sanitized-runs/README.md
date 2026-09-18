# Sanitized run summaries

Per-run outputs supporting the paper’s artifact release.

## Per run (when available)

| File | Contents |
|---|---|
| `run_result.json` | Outcome, protocol, topology, model, overseer/impairment/blind flags, turns, tool-call counts |
| `attack_log.json` | Tool outcomes and payload metadata (secrets redacted) |
| `token_summary.json` | Per-event `token_count` logs for inspecting token use (from evaluation-host session DBs) |

## Excluded

- Raw SQLite `memory.db` files and host session logs  
- API keys, credentials, and environment-specific secrets  

## Inventory

- `91` runs with `token_summary.json`  
- See [`../tables/run_index.csv`](../tables/run_index.csv) for the full index  

These sanitized summaries are the released inspection set for what the model could call, how missions ended, and how token use was logged.
