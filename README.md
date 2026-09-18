# APIOT

**Autonomous Purple-teaming for Industrial OT**

Research artifact accompanying the manuscript submitted to *Computers & Security*.

APIOT is an LLM agent that performs an autonomous discovery → exploitation → network-level mitigation → verification cycle against bare-metal industrial OT targets in a controlled virtual laboratory. The agent operates through protocol primitives rather than named exploit shortcuts, with an Overseer providing runtime governance.

## Start here

| Document | Purpose |
|---|---|
| **[artifact/README.md](artifact/README.md)** | Full artifact package index |
| **[ARTIFACT.md](ARTIFACT.md)** | Paper ↔ source map (appendix transparency) |
| **[artifact/prompts/](artifact/prompts/)** | Guided and blind prompts |
| **[artifact/schemas/](artifact/schemas/)** | 21 JSON tool schemas |
| **[artifact/sanitized-runs/](artifact/sanitized-runs/)** | Sanitized run summaries from the evaluation |
| **[artifact/tables/run_index.csv](artifact/tables/run_index.csv)** | Inventory of packaged runs |

Companion testbed (**IoT Virtual Lab**): https://github.com/Adelsamir01/iot_vlab

## Repository layout

```
apiot/
  artifact/          Reviewer package (prompts, schemas, sanitized runs, tables)
  core/              Agent, prompts, overseer, tools, compaction, memory
  toolkit/           Protocol helpers and verification utilities
  scripts/           Experiment runner and analysis scripts
  tests/             Isolation, guardrail, and overseer tests
  config/            Scenario configuration
  docs/              Supplementary notes
```

## Licence

MIT — see [LICENSE](LICENSE).
