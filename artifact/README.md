# APIOT artifact package

This folder is the reviewer-facing package for the *Computers & Security* submission on **APIOT (Autonomous Purple-teaming for Industrial OT)**.

## Contents

| Path | What reviewers get |
|---|---|
| [`prompts/`](prompts/) | Guided and blind system prompts (plain text) |
| [`schemas/`](schemas/) | The 21 JSON tool schemas exposed to the model |
| [`sanitized-runs/`](sanitized-runs/) | Sanitized per-run summaries (`run_result.json`, `attack_log.json`) |
| [`tables/`](tables/) | Run index and batch-level success summary (CSV) |
| [`analysis-notes/`](analysis-notes/) | Written summaries of evaluation campaigns |
| [`EXPERIMENT_RUNNER.md`](EXPERIMENT_RUNNER.md) | How `scripts/run_experiment.py` configures blind mode and overseer arms |
| [`ETHICS_AND_ISOLATION.md`](ETHICS_AND_ISOLATION.md) | Isolation constraints matching the paper’s ethics section |

Implementation sources remain in the repository root (`core/`, `toolkit/`, `tests/`). Companion testbed: [iot_vlab](https://github.com/Adelsamir01/iot_vlab) (IoT Virtual Lab).

## Suggested reading order

1. `prompts/` and `schemas/` — what the model saw and could call  
2. `tables/run_index.csv` — inventory of packaged runs  
3. `sanitized-runs/` — inspect individual outcomes  
4. `core/oversight.py` and `core/compaction.py` — governance and context management  
5. `scripts/analysis/` — scripts used to aggregate metrics from run summaries  
