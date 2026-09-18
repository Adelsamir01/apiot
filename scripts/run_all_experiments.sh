#!/usr/bin/env bash
# run_all_experiments.sh — Batch runner for APIOT full 42-run suite
#
# Runs all experiment conditions sequentially (not parallel — agent uses sudo
# and exclusive network resources). Expects to be run from the repo root.
#
# Prerequisites:
#   1. iot_vlab lab_api.py running:  sudo python3 iot_vlab/lab_api.py
#   2. .env configured in apiot/:    OPENROUTER_API_KEY and LLM_MODEL
#   3. Network bridge set up:        sudo ./iot_vlab/setup_network.sh
#   4. Root/sudo access for agent and impairment scripts
#
# Usage:
#   sudo bash scripts/run_all_experiments.sh          # full suite
#   sudo bash scripts/run_all_experiments.sh RQ1_RQ2  # one batch only
#
# Progress: each completed run writes run_result.json to results/<batch>/<condition>/
# Resume: if a run_result.json already exists, that run is skipped automatically.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
RUNNER="python3 ${SCRIPT_DIR}/run_experiment.py"
RESULTS_ROOT="${REPO_ROOT}/results"
BATCH_FILTER="${1:-all}"  # optional: run only one batch

log() { echo "[$(date '+%H:%M:%S')] $*"; }

run_if_needed() {
    local out_dir="$1"
    shift
    if [[ -f "${out_dir}/run_result.json" ]]; then
        log "SKIP (already done): ${out_dir}"
        return 0
    fi
    log "START: ${out_dir}"
    $RUNNER "$@" --output-dir "${out_dir}" || log "WARN: run exited non-zero for ${out_dir}"
    log "DONE:  ${out_dir}"
}

# ── RQ1/RQ2: capability + behaviour baseline (18 runs) ────────────────
# 2 protocols × 3 topologies × 3 replicates, overseer ON
if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "RQ1_RQ2" ]]; then
    log "=== RQ1/RQ2: Capability + Behaviour Baseline (18 runs) ==="
    for PROTOCOL in coap modbus; do
        for TOPOLOGY in T1 T2 T3; do
            for RUN in 1 2 3; do
                OUT="${RESULTS_ROOT}/RQ1_RQ2/${PROTOCOL}_${TOPOLOGY}_run${RUN}"
                run_if_needed "$OUT" \
                    --rq RQ1_RQ2 \
                    --protocol "$PROTOCOL" \
                    --topology "$TOPOLOGY" \
                    --run-id "$RUN" \
                    --overseer full \
                    --impairment none \
                    --session 1
            done
        done
    done
fi

# ── RQ3: Overseer ablation (6 new runs — OFF condition) ───────────────
# 2 protocols × T1 × 3 replicates, overseer OFF
# (ON condition data comes from RQ1/RQ2 T1 runs)
if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "RQ3" ]]; then
    log "=== RQ3: Overseer Ablation — OFF condition (6 runs) ==="
    for PROTOCOL in coap modbus; do
        for RUN in 1 2 3; do
            OUT="${RESULTS_ROOT}/RQ3/${PROTOCOL}_T1_no_overseer_run${RUN}"
            run_if_needed "$OUT" \
                --rq RQ3 \
                --protocol "$PROTOCOL" \
                --topology T1 \
                --run-id "$RUN" \
                --overseer off \
                --impairment none \
                --session 1
        done
    done
fi

# ── RQ4: Cross-session memory (12 runs) ──────────────────────────────
# 2 protocols × T1 × 3 replicates, session 1 (blind) then session 2 (memory-informed)
# Session 2 uses the memory.db produced by the corresponding session-1 run
if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "RQ4" ]]; then
    # Session 1 reuses RQ1/RQ2 T1 data — copy memory.db from those runs
    log "=== RQ4: Linking session-1 data from RQ1/RQ2 T1 runs ==="
    for PROTOCOL in coap modbus; do
        for RUN in 1 2 3; do
            SRC="${RESULTS_ROOT}/RQ1_RQ2/${PROTOCOL}_T1_run${RUN}/memory.db"
            DST_DIR="${RESULTS_ROOT}/RQ4/${PROTOCOL}_T1_s1_run${RUN}"
            if [[ -f "$SRC" ]]; then
                mkdir -p "$DST_DIR"
                cp -n "$SRC" "$DST_DIR/memory.db" 2>/dev/null || true
                log "Linked S1 memory.db for RQ4/${PROTOCOL}_T1_run${RUN}"
            else
                log "WARN: RQ1_RQ2 T1 data not found for ${PROTOCOL} run${RUN} — run RQ1_RQ2 first"
            fi
        done
    done

    log "=== RQ4: Cross-session Memory — Session 2 (6 new runs) ==="
    for PROTOCOL in coap modbus; do
        for RUN in 1 2 3; do
            S1_DB="${RESULTS_ROOT}/RQ4/${PROTOCOL}_T1_s1_run${RUN}/memory.db"
            OUT="${RESULTS_ROOT}/RQ4/${PROTOCOL}_T1_s2_run${RUN}"
            run_if_needed "$OUT" \
                --rq RQ4 \
                --protocol "$PROTOCOL" \
                --topology T1 \
                --run-id "$RUN" \
                --overseer full \
                --impairment none \
                --session 2 \
                --memory-db "$S1_DB"
        done
    done
fi

# ── RQ6: Network impairment robustness (12 runs) ─────────────────────
# 2 protocols × T1 × {medium, heavy} impairment × 2 replicates
# ("none" baseline reused from RQ1/RQ2 T1 data)
if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "RQ6" ]]; then
    log "=== RQ6: Network Impairment Robustness (12 runs) ==="
    for PROTOCOL in coap modbus; do
        for IMPAIRMENT in medium heavy; do
            for RUN in 1 2 3; do
                OUT="${RESULTS_ROOT}/RQ6/${PROTOCOL}_T1_${IMPAIRMENT}_run${RUN}"
                run_if_needed "$OUT" \
                    --rq RQ6 \
                    --protocol "$PROTOCOL" \
                    --topology T1 \
                    --run-id "$RUN" \
                    --overseer full \
                    --impairment "$IMPAIRMENT" \
                    --session 1
            done
        done
    done
fi

# ── RQ1/RQ2 MQTT: capability baseline for hard protocol (6 new runs) ─
# mqtt × T1 × 3 replicates, overseer ON (multi-step MQTT attack chain)
if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "RQ1_RQ2_MQTT" ]]; then
    log "=== RQ1/RQ2 MQTT: Hard Protocol Baseline (6 runs — QEMU broker required) ==="
    for RUN in 1 2 3; do
        OUT="${RESULTS_ROOT}/RQ1_RQ2/mqtt_T1_run${RUN}"
        run_if_needed "$OUT" \
            --rq RQ1_RQ2 \
            --protocol mqtt \
            --topology T1 \
            --run-id "$RUN" \
            --overseer full \
            --impairment none \
            --session 1
    done

    log "=== RQ3 MQTT: Overseer Ablation — OFF condition (3 runs) ==="
    for RUN in 1 2 3; do
        OUT="${RESULTS_ROOT}/RQ3/mqtt_T1_no_overseer_run${RUN}"
        run_if_needed "$OUT" \
            --rq RQ3 \
            --protocol mqtt \
            --topology T1 \
            --run-id "$RUN" \
            --overseer off \
            --impairment none \
            --session 1
    done
fi

# ── Model sensitivity: 3 conditions × 4 models × 3 runs = 36 runs ────
#
# Conditions:
#   easy  — CoAP T1, guided system prompt   (is capability model-specific?)
#   hard  — MQTT T1, guided                 (multi-step reasoning — where do models diverge?)
#   blind — CoAP T1, no protocol hints      (can the model discover the exploit from first principles?)
#
# Models: gemini-3.1-pro-preview, claude-sonnet-4.6, gpt-5.4, glm-5
#
# Usage: sudo bash scripts/run_all_experiments.sh MODEL_SENS
#        (or include in 'all')
#
MODEL_HANDLES=(
    "google/gemini-3.1-pro-preview"
    "anthropic/claude-sonnet-4-6"
    "openai/gpt-5.4"
    "z-ai/glm-5"
)

# Slugify a model handle for use as a directory name (replace / with _)
slugify() { echo "$1" | tr '/' '_'; }

if [[ "$BATCH_FILTER" == "all" || "$BATCH_FILTER" == "MODEL_SENS" ]]; then

    # MODEL_SENS easy/blind: 400K token budget (CoAP ~10-20 turns, well within limit)
    # MODEL_SENS hard (MQTT): 1.2M token budget — MQTT requires 22-41 turns;
    # Claude-sonnet uses ~810-830K per successful run; 800K budget caused borderline
    # budget-exceeded failures at 808K and 823K. 1.2M gives 50% headroom.
    # Easy/blind timeout: 1800s. Hard MQTT timeout: 3600s (broker boot ~5min + long runs).
    MODEL_SENS_TIMEOUT=1800
    MODEL_SENS_MAX_TOKENS=400000
    MODEL_SENS_HARD_TIMEOUT=3600
    MODEL_SENS_HARD_MAX_TOKENS=1200000

    # ── Condition 1: Easy (CoAP T1, guided) ──────────────────────────
    log "=== MODEL_SENS Easy: CoAP T1 guided (12 runs) ==="
    for MODEL in "${MODEL_HANDLES[@]}"; do
        SLUG=$(slugify "$MODEL")
        for RUN in 1 2 3; do
            OUT="${RESULTS_ROOT}/MODEL_SENS/easy/${SLUG}/coap_T1_run${RUN}"
            run_if_needed "$OUT" \
                --rq RQ1_RQ2 \
                --protocol coap \
                --topology T1 \
                --run-id "$RUN" \
                --overseer full \
                --impairment none \
                --session 1 \
                --model "$MODEL" \
                --timeout "$MODEL_SENS_TIMEOUT" \
                --max-tokens "$MODEL_SENS_MAX_TOKENS"
        done
    done

    # ── Condition 2: Hard (MQTT T1, guided) ──────────────────────────
    log "=== MODEL_SENS Hard: MQTT T1 guided (12 runs — QEMU broker required) ==="
    for MODEL in "${MODEL_HANDLES[@]}"; do
        SLUG=$(slugify "$MODEL")
        for RUN in 1 2 3; do
            OUT="${RESULTS_ROOT}/MODEL_SENS/hard/${SLUG}/mqtt_T1_run${RUN}"
            run_if_needed "$OUT" \
                --rq RQ1_RQ2 \
                --protocol mqtt \
                --topology T1 \
                --run-id "$RUN" \
                --overseer full \
                --impairment none \
                --session 1 \
                --model "$MODEL" \
                --timeout "$MODEL_SENS_HARD_TIMEOUT" \
                --max-tokens "$MODEL_SENS_HARD_MAX_TOKENS"
        done
    done

    # ── Condition 3: Blind (CoAP T1, no protocol hints) ──────────────
    log "=== MODEL_SENS Blind: CoAP T1 blind (12 runs) ==="
    for MODEL in "${MODEL_HANDLES[@]}"; do
        SLUG=$(slugify "$MODEL")
        for RUN in 1 2 3; do
            OUT="${RESULTS_ROOT}/MODEL_SENS/blind/${SLUG}/coap_T1_run${RUN}"
            run_if_needed "$OUT" \
                --rq RQ1_RQ2 \
                --protocol coap \
                --topology T1 \
                --run-id "$RUN" \
                --overseer full \
                --impairment none \
                --session 1 \
                --model "$MODEL" \
                --timeout "$MODEL_SENS_TIMEOUT" \
                --max-tokens "$MODEL_SENS_MAX_TOKENS" \
                --blind
        done
    done

fi

# ── Final summary ─────────────────────────────────────────────────────
log "=== Batch complete. Checking results... ==="
python3 "${SCRIPT_DIR}/check_results.py" --results-dir "$RESULTS_ROOT" 2>/dev/null || true
log "=== All done. ==="
