# Sanitized run summaries

These directories contain **sanitized** per-run outputs from the evaluation campaigns described in the paper.

Included per run (when available):
- `run_result.json` — outcome, protocol, topology, model, overseer/impairment/blind flags, turn and tool-call counts
- `attack_log.json` — tool outcomes and payload metadata (secrets redacted)

Excluded:
- SQLite `memory.db` session databases
- Host session logs
- API keys and credentials

**Runs packaged:** 91 `run_result.json`, 89 `attack_log.json`

Index: [`../tables/run_index.csv`](../tables/run_index.csv)

## Coverage note

This package includes every `run_result.json` available on the evaluation host snapshot used to build the artifact (**91 runs** across capability, overseer ablation, impairment, cross-session, and model-sensitivity folders). The manuscript reports a larger total evaluation programme (360 runs); additional raw databases remain on the private evaluation host and can be regenerated with `scripts/run_experiment.py`.
