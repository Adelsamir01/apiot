# Experiments Overview

This folder contains the detailed experimental design for the APIOT study paper submission. Each file corresponds to one or more Research Questions (RQs) and documents: what the experiment does, how to run it, what it outputs, and exactly how it contributes to the paper.

---

## Folder Contents

| File | RQ(s) | What it covers |
|---|---|---|
| `RQ1_RQ2_capability_and_behaviour.md` | RQ1, RQ2 | Baseline capability + full behavioural characterisation across protocols and topologies |
| `RQ3_oversight_ablation.md` | RQ3 | With-vs-without Overseer ablation — the mechanism insight |
| `RQ4_cross_session_memory.md` | RQ4 | Cross-session learning via persistent memory |
| `RQ5_topology_complexity.md` | RQ5 | Topology scaling analysis (derived from RQ1/RQ2 data, no new runs) |
| `RQ6_impairment_robustness.md` | RQ6 | Agent robustness under realistic network impairments |

---

## How the Experiments Fit Together

```
                        48 total unique runs
                               │
          ┌────────────────────┼────────────────────┐
          │                    │                    │
   18 runs (RQ1+RQ2)     12 runs (RQ4)       12 new runs (RQ6)
   2 protocols ×          Session 1+2 ×       2 impairment levels ×
   3 topologies ×         2 protocols ×       2 protocols ×
   3 runs each            3 runs each         3 runs each
          │                    │                    │
          └────────┬───────────┘                    │
                   │                                │
        RQ5 derived from                   RQ3 uses 6 new runs
        RQ1/RQ2 data                       (OFF condition only;
        (0 new runs)                        ON reuses RQ1/RQ2 T1)
```

### Shared data strategy

- **RQ1/RQ2 T1 runs** (flat star, overseer ON) are reused as the "overseer ON" baseline for **RQ3** and the "no impairment" baseline for **RQ6**. This avoids redundant compute.
- **RQ5** is a re-analysis of RQ1/RQ2 data sliced by topology — no new runs needed.
- All runs feed into the **RQ2 behavioural characterisation** (turn-by-turn analysis uses every run in the dataset).

---

## Unified Narrative for the Paper

The experiments collectively answer one overarching question:

> *Can an autonomous LLM agent reliably attack and remediate bare-metal MCU devices running industrial IoT protocols — and what design choices determine whether it succeeds or fails?*

| Section of paper | Driven by |
|---|---|
| §Introduction / motivation | All RQs framed as open questions |
| §System design (APIOT + iot_vlab) | Prerequisite — not an RQ |
| §RQ1: Capability | RQ1 results: success rates per protocol/topology |
| §RQ2: Behaviour profile | RQ2 results: tool distributions, failure taxonomy, stall analysis |
| §RQ3: Why it works | RQ3 results: overseer ablation delta |
| §RQ4: Cross-session learning | RQ4 results: memory efficiency gains |
| §RQ5: Scalability limits | RQ5 results: topology complexity vs. success rate |
| §RQ6: Real-world robustness | RQ6 results: impairment degradation curves |
| §Discussion | Synthesis: what makes autonomous IoT agents succeed/fail |

---

## Compute Budget

| Experiment | Runs | Est. duration/run | Total compute |
|---|---|---|---|
| RQ1 + RQ2 | 18 | 30 min | 9 hours |
| RQ3 (new runs only) | 6 | 30 min | 3 hours |
| RQ4 | 12 (6 new, 6 reuse RQ1/RQ2 T1) | 30 min | 3 hours |
| RQ5 | 0 | — | 0 |
| RQ6 (new runs only) | 12 | 30 min | 6 hours |
| **Total** | **48 (42 new runs)** | | **~21 hours** |

With the experiment runner automating setup/teardown, 24 hours of compute is achievable over 2–3 nights of unattended execution.

---

## Key System Extensions Required Before Experiments

1. `--no-overseer` flag in `apiot/core/agent.py` (for RQ3)
2. Software MCU simulators — Python Modbus TCP server + CoAP server (for multi-device topologies)
3. `scripts/run_experiment.py` — parameterised experiment runner
4. Per-turn logging enrichment in `tool_history` (turn number, overseer flag, token count)
5. Analysis + visualisation scripts (`scripts/analyse_results.py`)
6. Impairment integration in experiment runner (for RQ6)

See `paper_brainstorm.md` in `raid_docs/` for full context on paper positioning and RQ rationale.
See `../sys_exten/` for detailed specs of each system extension.

---

## Action Plan: What to Do and Why

This is your step-by-step guide to getting from today (March 11) to a submitted paper (April 16). Every step has a reason — nothing here is busywork.

### Week 1 (Mar 11–17): Build the infrastructure

**Why first:** You cannot run a single experiment until the extensions are built. The experiment runner, logging enrichment, and simulators are the foundation everything else rests on. Building them first means the remaining weeks are pure data collection and writing — no context-switching back into code.

**What to do:**

1. **Build EXT4 first (logging enrichment)** — it touches `memory_store.py` and `agent.py`. Do this before anything else because EXT3 (runner) depends on the enriched schema, and running experiments without it means your data is incomplete and un-repairable after the fact.
   - Add `turn_number`, `overseer_flag`, `token_count`, `mission_phase` to `tool_history`
   - Update `agent.py` to pass these fields
   - Update `oversight.py` to return the flag string

2. **Build EXT1 (no-overseer flag)** in parallel — small change, one day, blocks RQ3.
   - Add `--no-overseer` to `agent.py` arg parser
   - Guard the three Overseer call sites

3. **Build EXT2 (software MCU simulators)** — Modbus TCP echo server + CoAP UDP server.
   - These must crash correctly when given overflow payloads (matching real Zephyr behaviour)
   - Test manually: send `modbus_mbap_overflow` payload → confirm server exits → port closed

4. **Build EXT3 (experiment runner)** — once EXT1, EXT2, EXT4 are done.
   - Parameterised `run_experiment.py` + batch `run_all_experiments.sh`
   - Verify with one dry run: RQ1/RQ2, CoAP, T1, run 1, overseer on

5. **Build EXT6 (impairment integration)** — 0.5 days, wire `impairment_manager.py` into runner.

6. **Start EXT5 (analysis scripts) skeleton** — create the loader and empty analysis scripts. You don't need results yet; just make sure the scripts can read `run_result.json` and `memory.db`.

**End of Week 1 goal:** One clean end-to-end experiment run completes successfully, outputs saved correctly, dry-run analysis script reads the output without errors.

---

### Week 2 (Mar 18–24): Run experiments (nights) + begin writing (days)

**Why parallel:** Experiments run unattended overnight (automated by the batch runner). Days are freed for writing. Waiting until all results are in before writing a single word is how papers miss deadlines.

**What to run (nights, unattended):**

- Night 1–2: RQ1/RQ2 — 18 runs (9 hours). Launch `run_all_experiments.sh` with the RQ1/RQ2 block before bed. Check `results/` in the morning.
- Night 3: RQ3 OFF condition — 6 runs (3 hours). Quick overnight.
- Night 4–5: RQ4 — 6 new runs / 3 hours (Session 1 reuses RQ1/RQ2 T1 data).

**What to write (days):**

Start writing sections that don't depend on results:
- §1 Introduction (problem statement, why MCUs, why LLMs, why this matters for RAID)
- §2 Background (bare-metal IoT, CoAP/Modbus protocols, LLM agents, prior work)
- §3 System Design (APIOT + iot_vlab architecture — you know this cold)
- §4 Methodology (experimental setup, topologies, metrics definitions — maps directly to the RQ docs)

**Why write these now:** They are fully writable without results. Getting them done in Week 2 means Week 4 is exclusively results + discussion + polish.

**End of Week 2 goal:** RQ1/RQ2, RQ3, RQ4 runs complete. Sections 1–4 drafted (rough is fine).

---

### Week 3 (Mar 25–31): Run remaining experiments + analyse results

**What to run (nights):**

- Night 1–2: RQ6 — 12 new runs (6 hours). Medium + heavy impairment conditions.

**What to do (days):**

- Run analysis scripts on completed RQ1/RQ2, RQ3, RQ4 data → produce all figures and tables for those RQs
- Write §5.1 (RQ1 capability), §5.2 (RQ2 behaviour profile), §5.3 (RQ3 oversight ablation), §5.4 (RQ4 memory)
- RQ5 analysis is free — re-slice RQ1/RQ2 data by topology → write §5.5

**Why this order:** RQ5 costs nothing extra. Doing it in Week 3 while RQ1/RQ2 data is fresh means you don't need to re-read results later.

**End of Week 3 goal:** All 48 runs complete. All figures generated. §5.1–5.5 drafted.

---

### Week 4 (Apr 1–10): Write, polish, submit

**What to do:**

- Run RQ6 analysis → produce figures → write §5.6 (impairment robustness)
- Write §6 Discussion: synthesise all six RQs into a coherent answer to the overarching question
- Write §7 Conclusion: contributions, limitations, future work
- (Related work is folded into §2 Background & Related Work — no standalone section)
- Polish: consistent figures, tables formatted for LNCS, references checked
- Ethics section: IRB/responsible disclosure statement (required by RAID)
- Verify anonymisation: strip all author references, check for identifying metadata in figures
- Final check against RAID formatting requirements: 20 pages max excl. references, Springer LNCS template
- **Submit by April 16 AoE**

**Buffer:** April 10 target gives you 6 days of buffer before the hard deadline. Use it.

---

## Timeline at a Glance

| Week | Nights (experiments) | Days (writing/analysis) |
|---|---|---|
| Mar 11–17 | Dry-run validation | Build all 6 extensions |
| Mar 18–24 | RQ1+RQ2 (18 runs), RQ3 (6 runs), RQ4 (6 new runs, 6 reuse RQ1/RQ2 T1) | §1, §2, §3, §4 |
| Mar 25–31 | RQ6 (12 runs) | Analyse RQ1–5, write §5.1–5.5 |
| Apr 1–10 | — | Analyse RQ6, write §5.6, §6, §7, polish |
| Apr 10–16 | — | Buffer + final checks + submit |
