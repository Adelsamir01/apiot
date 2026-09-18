# Paper ↔ artifact transparency

This document corresponds to the manuscript appendix on prompt, tool, and artifact transparency.

## Path convention

Appendix paths of the form `apiot/<file>` refer to `<file>` at this repository’s root (the GitHub repository *is* the `apiot` package). Examples:

| Paper path | Path in this repository |
|---|---|
| `apiot/core/agent.py` | `core/agent.py` |
| `apiot/core/tools/registry.py` | `core/tools/registry.py` |
| `apiot/core/compaction.py` | `core/compaction.py` |
| `apiot/core/oversight.py` | `core/oversight.py` |
| `scripts/run_experiment.py` | `scripts/run_experiment.py` |

Plain-text / JSON copies for inspection also live under `artifact/`.

## Methodological map

| Methodological claim | Concrete location |
|---|---|
| Guided prompt | `SYSTEM_PROMPT` in `core/agent.py` (= `artifact/prompts/guided_system_prompt.txt`) |
| Blind prompt | `BLIND_SYSTEM_PROMPT` in `core/agent.py` (= `artifact/prompts/blind_system_prompt.txt`) |
| Blind-mode switch | `APIOT_BLIND_MODE` via `scripts/run_experiment.py` |
| Tool schemas (21) | `TOOL_SCHEMAS` in `core/tools/registry.py` (= `artifact/schemas/tools.json`) |
| Context compaction (70% trigger; keep system + last 8; truncate tool output to 2,000 chars) | `core/compaction.py` + trigger in `core/agent.py` |
| Runtime governance / Overseer | `core/oversight.py` |
| Experiment runner | `scripts/run_experiment.py` |
| Analysis scripts | `scripts/analysis/` |
| Sanitized run summaries (incl. token use) | `artifact/sanitized-runs/` |
| IoT Virtual Lab configuration | `artifact/iot-virtual-lab/` (full lab: https://github.com/Adelsamir01/iot_vlab) |

Both prompt conditions share the same mission lifecycle, safety constraints, termination tokens, verification requirements, and tool roster. The blind prompt removes protocol-specific exploit examples only.
