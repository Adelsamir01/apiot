# RQ6: Impairment Robustness

## Research Question

**RQ6 — Impairment robustness:** How robust is the agent under realistic industrial network conditions — packet loss, latency jitter, and background HMI traffic?

---

## Why This Matters

Industrial IoT networks are not clean lab environments. Real OT networks exhibit packet loss from aging hardware, high latency from serial-to-IP converters, jitter from shared network segments, and constant background traffic from SCADA/HMI polling cycles. An autonomous security agent that works perfectly on a clean virtual network may degrade significantly in these conditions.

iot_vlab already has the infrastructure to simulate these conditions (`impair_network.sh` + `industrial_hmi_sim.py`). RQ6 measures how much these conditions degrade APIOT's performance — and whether the degradation is graceful or catastrophic.

This also adds significant practical credibility to the paper: it moves the claim from "works in a clean lab" to "robust to realistic industrial network conditions."

---

## Experimental Conditions

| Dimension | Values |
|---|---|
| Impairment level | None · Medium (5% loss + 50ms latency + 20ms jitter) · Heavy (10% loss + 100ms latency + 50ms jitter + HMI background traffic) |
| Protocol | CoAP (UDP :5683), Modbus/TCP (:502) |
| Topology | T1 only (flat star — isolates impairment as the variable) |
| Overseer | ON throughout |
| Runs per condition | 3 |
| **New runs needed** | **12** (Medium + Heavy conditions × 2 protocols × 3 runs; None reuses RQ1/RQ2 T1 data) |

### Why impairment hits CoAP and Modbus differently

**CoAP (UDP):** CoAP has no built-in retransmission guarantee at the transport layer (relies on CoAP CON/ACK at application layer). Packet loss directly affects whether exploit payloads are delivered and whether responses are received. The `coap_option_overflow` exploit sends a malformed UDP packet — if it drops, the agent sees no crash confirmation and may retry or stall.

**Modbus/TCP:** Modbus runs over TCP, which handles retransmission. However, high latency inflates the time for TCP handshakes and response windows. The `modbus_mbap_overflow` exploit may appear to time out even when the device crashes, causing `verify_crash` to incorrectly report failure. This is a particularly interesting failure mode: the device is actually exploited, but the agent doesn't know it.

This asymmetry between UDP (CoAP) and TCP (Modbus) under impairment is a genuine research finding, not just a footnote.

---

## Impairment Configuration Details

Applied via `impair_network.sh` to `br0` before each run. Cleared after each run.

**None (baseline):**
```bash
# No tc rules applied
# Reuses RQ1/RQ2 T1 data
```

**Medium:**
```bash
sudo tc qdisc add dev br0 root netem loss 5% delay 50ms 20ms
```

**Heavy:**
```bash
sudo tc qdisc add dev br0 root netem loss 10% delay 100ms 50ms
# Also runs industrial_hmi_sim.py in background (Poisson-distributed Modbus + CoAP polling noise)
```

The HMI simulator in the Heavy condition adds background legitimate traffic that the agent must distinguish from its own exploit attempts and responses. This tests whether the agent's protocol parsing is robust to ambient noise.

---

## Outputs Per Run

### Primary impairment metrics

| Metric | None | Medium | Heavy | Expected trend |
|---|---|---|---|---|
| Mission success rate | baseline | ↓? | ↓↓? | Uncertain — key finding |
| Exploit success rate | baseline | ↓ | ↓↓ | Packet loss → missed payloads |
| False negative crash rate | baseline | ↑ | ↑↑ | verify_crash fails even when device is down |
| Patch verification rate | baseline | ↓? | ↓? | Replay attack may not land under loss |
| Turns to mission completion | baseline | ↑ | ↑↑ | More retries, more stalls |
| Stall events per mission | baseline | ↑ | ↑↑ | Network failures look like stalls |
| Abort rate | baseline | ↑ | ↑↑ | Infrastructure timeouts trigger TASK_ABORTED |

### Protocol-specific metrics

| Metric | CoAP | Modbus | What it shows |
|---|---|---|---|
| Exploit delivery success under loss | ↓↓ (UDP, no retry) | ↓ (TCP retransmits) | UDP more sensitive to loss |
| False negative crash rate | high | lower | Modbus TCP masks loss better |
| Response parse error rate | ↑ | ↑ (HMI noise) | Agent confuses HMI polling with exploit response |

### HMI traffic interference (Heavy condition only)

- Count tool calls where agent response parsing was confused by HMI background traffic
- Identifiable from: `execute_exploit` returning ambiguous response that matches legitimate HMI polling pattern
- This is the most interesting finding in the Heavy condition: does the LLM correctly reason "this response looks like legitimate Modbus polling, not my exploit response"?

---

## Graceful Degradation Analysis

The key question for RQ6 is not just "does it break?" but "how does it break?"

**Graceful degradation** — Success rate drops proportionally to impairment level. Agent retries, adapts timeout assumptions, and completes missions with more turns but same outcome. This is the ideal result.

**Catastrophic degradation** — Success rate drops sharply at a threshold (e.g., 5% loss causes 80% mission abort rate). Agent gets stuck in verify loops, cannot recover from false negative crash reports, and aborts. This is an honest limitation that motivates future work (adaptive timeout handling, packet loss awareness in tool implementations).

**No degradation** — Success rate unchanged. This would mean APIOT's exploit primitives are robust to the tested impairment levels. Unlikely for CoAP/UDP at 10% loss, but possible for Modbus/TCP.

Plotting the degradation curve (success rate vs. impairment level) as a line plot per protocol is the core figure for this RQ.

---

## Paper Contribution

### RQ6 answers:
- First measurement of autonomous LLM security agent robustness under realistic industrial network impairments
- Reveals the asymmetric sensitivity of the agent to UDP (CoAP) vs. TCP (Modbus) packet loss
- Identifies whether false negative crash detection is a significant problem under impairment
- Establishes practical deployment bounds: "the agent maintains reliable operation up to X% packet loss and Y ms latency"

### In the paper:
- RQ6 results → §5.6 "Robustness Under Realistic Network Conditions"
- Positions APIOT as tested against realistic ICS/OT network conditions, not just a clean testbed
- The CoAP vs. Modbus asymmetry finding → directly motivates a future extension: CoAP CON message support for reliable delivery

### The claim this enables:
> *"Under medium industrial network impairment (5% loss, 50ms latency), APIOT maintains X% mission success rate. Under heavy impairment (10% loss + HMI background traffic), success degrades to Y%, with the primary failure mode being false-negative crash verification on UDP-based CoAP targets — a protocol-level limitation rather than an agent reasoning failure."*

---

## Figures to Produce

1. **Degradation curve** — line plot: x=impairment level, y=mission success rate, two lines (CoAP, Modbus)
2. **False negative crash rate bar chart** — per impairment level per protocol
3. **Turn overhead chart** — how many additional turns does the agent need under Medium vs. Heavy vs. None (box plots)
4. **HMI interference analysis** — Heavy condition only: frequency of HMI-confused tool responses per protocol

---

## Dependencies

- System extension 3: Experiment runner (applies/clears impairments before/after each run, launches HMI simulator for Heavy condition)
- System extension 6: Impairment integration (wire `impair_network.sh` into runner, manage `industrial_hmi_sim.py` process lifecycle)
- System extension 5: Analysis scripts (impairment-level slicing, false negative detection from session logs)
- RQ1/RQ2 T1 data: reused as None (baseline) condition
