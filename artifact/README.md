# APIOT artifact package

Reviewer package for the *Computers & Security* submission on **APIOT (Autonomous Purple-teaming for Industrial OT)**.

## Artifact release contents (as stated in the paper)

| Claimed content | Location |
|---|---|
| APIOT code | Repository root (`core/`, `toolkit/`, `tests/`, …) |
| IoT Virtual Lab configuration | [`iot-virtual-lab/`](iot-virtual-lab/) |
| Prompt definitions | [`prompts/`](prompts/) |
| JSON tool schemas | [`schemas/`](schemas/) |
| Analysis scripts | [`../scripts/analysis/`](../scripts/analysis/) |
| Sanitized run summaries | [`sanitized-runs/`](sanitized-runs/) (incl. token summaries) |

Excluded: API keys, local host credentials, and environment-specific secrets.

## Suggested inspection order

1. `prompts/` and `schemas/` — what the model saw and could call  
2. `sanitized-runs/*/token_summary.json` — token-use logs  
3. `sanitized-runs/*/run_result.json` — mission outcomes  
4. `core/oversight.py`, `core/compaction.py` — governance and context management  
5. `iot-virtual-lab/` — lab configuration used with the companion testbed  

Companion full lab repository: https://github.com/Adelsamir01/iot_vlab
