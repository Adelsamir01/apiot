# Experiment runner

The paper’s appendix refers to `scripts/run_experiment.py` as the parameterised driver for individual evaluation runs.

## Role

For each run the driver records configuration and outcomes into a results directory, including:

- protocol, topology, run id  
- overseer mode (`off` / `guards-only` / `full`)  
- impairment profile  
- blind-mode flag (`APIOT_BLIND_MODE`)  
- model identifier  
- mission success / turns / tool-call counts  

## Blind prompt condition

Blind runs set `APIOT_BLIND_MODE=1`, which selects `BLIND_SYSTEM_PROMPT` in `core/agent.py` instead of `SYSTEM_PROMPT`. Tool schemas are unchanged.

## Overseer arms

| Arm | Effect |
|---|---|
| `off` | No deterministic guards; no advisory steering |
| `guards-only` | Deterministic guards only |
| `full` | Guards plus optional LLM advisory steering |

## Companion lab

Live execution expects IoT Virtual Lab as a sibling checkout (`../iot_vlab`) or `IOT_VLAB_ROOT` pointing at that repository. APIOT does not manage lab device lifecycle.
