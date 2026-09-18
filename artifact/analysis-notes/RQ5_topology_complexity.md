# RQ5: Topology Complexity Scaling

## Research Question

**RQ5 — Topology complexity:** How does network complexity (flat star → Purdue segmented → Edge-Fog-Cloud three-tier) affect mission success rate and agent decision quality?

---

## Why This Is a Free Result

**RQ5 requires zero new experiment runs.** It is a re-analysis of the RQ1/RQ2 dataset, sliced along the topology dimension. Since RQ1/RQ2 already runs 2 protocols × 3 topologies × 3 runs, the topology comparison is embedded in that data. RQ5 is the analytical frame that extracts the topology signal.

This makes RQ5 high value at near-zero additional cost — it answers an important question (does the agent scale to complex networks?) using data already collected.

---

## Topology Configurations (Defined in RQ1/RQ2)

| Config | Label | Description | Complexity |
|---|---|---|---|
| T1 | Flat star | 1 QEMU MCU + 1–2 software simulators, direct br0 access | Low |
| T2 | Purdue segmented | MCU on br_internal behind multi-homed ARM gateway | Medium |
| T3 | Edge-Fog-Cloud | MCU in edge zone behind 2 fog gateways + 2 cloud routers | High |

### What changes as complexity increases

| Property | T1 | T2 | T3 |
|---|---|---|---|
| Subnets | 1 (br0) | 2 (br0 + br_internal) | 3+ |
| Hops to MCU | 0 | 1 (gateway) | 2–3 |
| Devices visible from br0 | MCU directly | Gateway + MCU (after pivot) | Cloud routers only |
| Lateral movement required | No | Yes (one pivot) | Yes (multi-hop) |
| Attack surface visible to nmap | All | Partial (gateway blocks br_internal) | Minimal |

---

## Analysis Approach

### Primary comparison (from RQ1/RQ2 data)

For each metric collected in RQ1/RQ2, compute mean ± std across the 3 runs per (protocol, topology) cell, then compare across T1 → T2 → T3:

| Metric | T1 | T2 | T3 | Expected trend |
|---|---|---|---|---|
| Mission success rate | baseline | ↓ | ↓↓ | Drops with complexity |
| Turns to first exploit | baseline | ↑ | ↑↑ | More turns needed to reach MCU |
| Turns to mission completion | baseline | ↑ | ↑↑ | Scales with hops |
| Stall events per mission | baseline | ↑ | ↑↑ | More confusion at higher complexity |
| Abort rate | baseline | ↑ | ↑↑ | Infrastructure failures more likely |
| Redundant call rate | baseline | ? | ? | Unclear — may increase if agent repeats scans |
| Tool call distribution | — | pivot tools appear | pivot tools dominate | `run_command` / `inspect_lab` usage changes |

### Topology-specific behavioural signals

**T2 — Does the agent discover the gateway and attempt to pivot?**
- Look for `run_command` calls attempting to probe `br_internal` range (192.168.200.x)
- Look for `inspect_lab` calls attempting to enumerate devices behind gateway
- If the agent never reaches `br_internal`, it missed the lateral movement opportunity entirely

**T3 — Does the agent correctly identify the multi-hop structure?**
- Look for sequential recon → pivot → recon pattern in tool_history
- Look for `get_network_state` updates showing progressive discovery (cloud → fog → edge)
- If the agent stalls on cloud routers without pivoting down to edge MCU devices, that's a failure mode

### Complexity scaling curve

Fit a simple trend line across T1/T2/T3 for the primary metrics. If success rate drops linearly, the agent has predictable scalability limits. If it drops sharply at T2 (first segmentation boundary), that suggests the gateway pivot is the key challenge, not total complexity.

---

## Outputs

### Tables
- **Primary results table** — 2 protocols × 3 topologies matrix with: success rate, turns to first exploit, turns to completion, stall events
- **Tool call distribution by topology** — how tool usage shifts from T1 to T3 (recon-heavy in T2/T3, exploit-heavy in T1)

### Figures
1. **Success rate vs. topology complexity** — line plot: x=topology, y=success rate, two lines (CoAP, Modbus)
2. **Turns to completion vs. topology** — box plots per topology per protocol
3. **Tool distribution shift** — stacked bar: tool usage % per topology, showing pivot-related tools growing in T2/T3
4. **Lateral movement success rate** — T2 and T3 only: % of runs where agent successfully reached and exploited MCU in internal zone

---

## Paper Contribution

### RQ5 answers:
- Whether autonomous IoT agents scale beyond flat networks to realistic segmented industrial topologies
- Where the agent hits its limits (flat → segmented is likely the key inflection point)
- Which topological features most challenge LLM reasoning (segmentation, multi-hop, limited initial visibility)
- Provides guidance for practitioners: "autonomous agents work well up to X complexity; beyond Y, human-in-the-loop guidance is needed"

### In the paper:
- RQ5 results → §5.5 "Scalability Under Network Complexity"
- Anchors the claim that APIOT is not only a lab toy — it functions in realistic IIoT segmentation models
- If T2/T3 success rates are low, this is an honest limitation that motivates future work
- If T2/T3 success rates are reasonable, this is a strong positive result that elevates the paper

### The claim this enables (optimistic case):
> *"APIOT maintains >X% mission success rate in Purdue-model segmented topologies, demonstrating that autonomous agents can navigate industrial network segmentation without human guidance."*

### The claim this enables (conservative/honest case):
> *"Mission success rate drops from X% in flat networks to Y% in Purdue-segmented topologies, with the primary failure mode being agent inability to initiate lateral movement through multi-homed gateways — a concrete direction for future work."*

Either way, it's a publishable finding.

---

## Dependencies

- **Zero new runs** — reuses RQ1/RQ2 data entirely
- System extension 5: Analysis scripts must support topology-sliced aggregation
- iot_vlab topology configurations must be correctly set up for T2 and T3 (multi-homed gateway, internal bridge)
- Software MCU simulators must be deployable on `br_internal` for T2/T3 (not just `br0`)
