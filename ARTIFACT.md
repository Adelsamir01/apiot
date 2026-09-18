# Paper ↔ artifact transparency

This document corresponds to the manuscript appendix on prompt, tool, and artifact transparency.

| Methodological claim | Concrete location |
|---|---|
| Guided prompt | `core/agent.py` → `SYSTEM_PROMPT`; plain-text copy in `artifact/prompts/guided_system_prompt.txt` |
| Blind prompt | `core/agent.py` → `BLIND_SYSTEM_PROMPT`; plain-text copy in `artifact/prompts/blind_system_prompt.txt` |
| Blind-mode switch | `APIOT_BLIND_MODE=1` via `scripts/run_experiment.py` |
| Tool schemas (21) | `core/tools/registry.py` → `TOOL_SCHEMAS`; JSON copy in `artifact/schemas/tools.json` |
| Context compaction | `core/compaction.py` |
| Runtime governance / Overseer | `core/oversight.py` |
| Experiment runner | `scripts/run_experiment.py` |
| Analysis scripts | `scripts/analysis/` |
| Sanitized run summaries | `artifact/sanitized-runs/` (+ `artifact/tables/run_index.csv`) |
| IoT Virtual Lab | Companion repository https://github.com/Adelsamir01/iot_vlab |

Both prompt conditions share the same mission lifecycle, safety constraints, termination tokens, verification requirements, and tool roster. The blind prompt removes protocol-specific exploit examples only.
