#!/usr/bin/env python3
"""rq_model_sensitivity.py — Analysis for §5.6: Model Sensitivity (RQ-MS)

Compares four frontier LLMs across three conditions:
  easy  — CoAP T1, guided system prompt   (baseline capability)
  hard  — MQTT T1, guided                 (multi-step, requires topic discovery)
  blind — CoAP T1, blind (no protocol hints)  (first-principles reasoning)

Produces:
  RMS.1  raid_paper/figures/rms_success_heatmap.{pdf,eps}
         results/rms_success_rates.csv
  RMS.2  raid_paper/figures/rms_efficiency_bars.{pdf,eps}
         results/rms_efficiency.csv

Run after all MODEL_SENS experiments:
    python3 scripts/analysis/rq_model_sensitivity.py
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from scripts.analysis.loader import (
    load_run_results, apply_task_abandonment,
    success_rate, mean, stdev,
    save_figure, save_csv, RESULTS_ROOT,
)

# ── Model display names (handle → short label) ────────────────────────
MODEL_LABELS = {
    "google/gemini-3.1-pro-preview": "Gemini 3.1 Pro",
    "anthropic/claude-sonnet-4-6":   "Claude Sonnet 4.6",
    "openai/gpt-5.4":                "GPT-5.4",
    "z-ai/glm-5":                    "GLM-5",
    # minimax primary baseline
    "minimax/minimax-m2.5":          "MiniMax M2.5\n(primary)",
}

CONDITIONS = ["easy", "hard", "blind"]
CONDITION_LABELS = {
    "easy":  "Easy\n(CoAP guided)",
    "hard":  "Hard\n(MQTT guided)",
    "blind": "Blind\n(CoAP no hints)",
}

MODELS = [
    "google/gemini-3.1-pro-preview",
    "anthropic/claude-sonnet-4-6",
    "openai/gpt-5.4",
    "z-ai/glm-5",
]


def _load_sens_runs() -> dict[tuple[str, str], list[dict]]:
    """Load MODEL_SENS runs grouped by (model, condition).

    Also injects the minimax baseline as the 'easy' condition
    using existing RQ1_RQ2 CoAP T1 runs (guided, minimax).
    """
    groups: dict[tuple[str, str], list[dict]] = {}

    # Load MODEL_SENS results
    sens_root = RESULTS_ROOT / "MODEL_SENS"
    for cond in CONDITIONS:
        for model in MODELS:
            slug = model.replace("/", "_")
            runs = []
            for run_id in [1, 2, 3]:
                proto = "mqtt" if cond == "hard" else "coap"
                p = sens_root / cond / slug / f"{proto}_T1_run{run_id}" / "run_result.json"
                if p.exists():
                    try:
                        import json
                        data = json.loads(p.read_text())
                        data["_path"] = str(p.parent)
                        data["_model"] = model
                        data["_condition"] = cond
                        from scripts.analysis.loader import augment_from_db
                        data = augment_from_db(data)
                        runs.append(data)
                    except Exception:
                        pass
            apply_task_abandonment(runs)
            groups[(model, cond)] = runs

    # Inject minimax baseline: easy = RQ1_RQ2 CoAP T1 runs
    minimax = "minimax/minimax-m2.5"
    baseline_runs = [
        r for r in load_run_results(rq="RQ1_RQ2", batch="RQ1_RQ2")
        if r.get("protocol") == "coap" and r.get("topology") == "T1"
           and not r.get("model_override")
    ]
    for r in baseline_runs:
        r["_model"] = minimax
        r["_condition"] = "easy"
    groups[(minimax, "easy")] = baseline_runs

    # Load MiniMax hard/blind runs from MODEL_SENS filesystem (same layout as other models)
    slug = minimax.replace("/", "_")
    for cond in ["hard", "blind"]:
        proto = "mqtt" if cond == "hard" else "coap"
        runs = []
        for run_id in [1, 2, 3]:
            p = sens_root / cond / slug / f"{proto}_T1_run{run_id}" / "run_result.json"
            if p.exists():
                try:
                    import json
                    data = json.loads(p.read_text())
                    data["_path"] = str(p.parent)
                    data["_model"] = minimax
                    data["_condition"] = cond
                    from scripts.analysis.loader import augment_from_db
                    data = augment_from_db(data)
                    runs.append(data)
                except Exception:
                    pass
        apply_task_abandonment(runs)
        if runs:
            groups[(minimax, cond)] = runs

    return groups


# ── RMS.1 — Success rate heatmap ──────────────────────────────────────

def make_rms1_heatmap(groups: dict) -> None:
    all_models = MODELS + ["minimax/minimax-m2.5"]

    # Build matrix: rows = models, cols = conditions
    matrix = np.full((len(all_models), len(CONDITIONS)), np.nan)
    for i, model in enumerate(all_models):
        for j, cond in enumerate(CONDITIONS):
            runs = groups.get((model, cond), [])
            if runs:
                matrix[i, j] = success_rate(runs) * 100

    fig, ax = plt.subplots(figsize=(7, 4.5))
    # Mask NaN cells (no data yet)
    masked = np.ma.masked_invalid(matrix)
    im = ax.imshow(masked, cmap="RdYlGn", vmin=0, vmax=100, aspect="auto")

    ax.set_xticks(range(len(CONDITIONS)))
    ax.set_xticklabels([CONDITION_LABELS[c] for c in CONDITIONS], fontsize=9)
    ax.set_yticks(range(len(all_models)))
    ax.set_yticklabels([MODEL_LABELS.get(m, m) for m in all_models], fontsize=9)

    # Annotate cells
    for i in range(len(all_models)):
        for j in range(len(CONDITIONS)):
            val = matrix[i, j]
            if not np.isnan(val):
                runs = groups.get((all_models[i], CONDITIONS[j]), [])
                n = len(runs)
                ax.text(j, i, f"{val:.0f}%\n(n={n})",
                        ha="center", va="center", fontsize=8,
                        color="black" if 30 < val < 80 else "white",
                        fontweight="bold")
            else:
                ax.text(j, i, "N/A", ha="center", va="center",
                        fontsize=7, color="gray", style="italic")

    plt.colorbar(im, ax=ax, label="Mission success rate (%)")
    ax.set_title("RMS.1 — Model Sensitivity: Success Rate by Model × Condition",
                 fontsize=10, pad=10)
    plt.tight_layout()
    save_figure(fig, "rms_success_heatmap")
    plt.close(fig)

    # CSV
    csv_rows = []
    for i, model in enumerate(all_models):
        row = {"model": MODEL_LABELS.get(model, model)}
        for j, cond in enumerate(CONDITIONS):
            row[cond] = f"{matrix[i, j]:.0f}" if not np.isnan(matrix[i, j]) else "N/A"
        csv_rows.append(row)
    save_csv(csv_rows, "rms_success_rates")
    print("RMS.1 done.")


# ── RMS.2 — Efficiency comparison bar chart ───────────────────────────

def make_rms2_efficiency(groups: dict) -> None:
    """Side-by-side bars: mean turns + redundant call rate per model, per condition."""
    all_models = MODELS + ["minimax/minimax-m2.5"]
    n_models = len(all_models)
    n_conds = len(CONDITIONS)

    fig, axes = plt.subplots(1, 2, figsize=(13, 5))

    x = np.arange(n_models)
    width = 0.22
    cond_colors = ["#1976D2", "#E53935", "#7B1FA2"]

    for ax_idx, (metric_key, ax, ylabel, title_suffix) in enumerate([
        ("total_turns",        axes[0], "Mean turns to completion",   "Mean Turns"),
        ("redundant_call_rate", axes[1], "Redundant call rate (0–1)",  "Redundant Call Rate"),
    ]):
        for ci, cond in enumerate(CONDITIONS):
            vals = []
            errs = []
            for model in all_models:
                runs = groups.get((model, cond), [])
                v = [r.get(metric_key, 0) or 0 for r in runs if r.get("mission_success")]
                vals.append(mean(v) if v else 0)
                errs.append(stdev(v) if len(v) > 1 else 0)

            offset = (ci - 1) * width
            bars = ax.bar(x + offset, vals, width,
                          label=CONDITION_LABELS[cond].replace("\n", " "),
                          color=cond_colors[ci], alpha=0.85,
                          yerr=errs, capsize=3, error_kw={"linewidth": 0.8})

        ax.set_xticks(x)
        ax.set_xticklabels([MODEL_LABELS.get(m, m).replace("\n", " ")
                            for m in all_models], fontsize=7.5, rotation=15, ha="right")
        ax.set_ylabel(ylabel, fontsize=9)
        ax.set_title(f"RMS.2{'a' if ax_idx==0 else 'b'} — {title_suffix} by Model", fontsize=10)
        ax.legend(fontsize=8)

    plt.suptitle("RMS.2 — Model Efficiency: Turns and Redundant Calls Across Conditions",
                 fontsize=10, y=1.01)
    plt.tight_layout()
    save_figure(fig, "rms_efficiency_bars")
    plt.close(fig)

    # CSV
    csv_rows = []
    for model in all_models:
        for cond in CONDITIONS:
            runs = groups.get((model, cond), [])
            success_runs = [r for r in runs if r.get("mission_success")]
            csv_rows.append({
                "model": MODEL_LABELS.get(model, model),
                "condition": cond,
                "n_runs": len(runs),
                "n_success": len(success_runs),
                "success_rate_pct": round(success_rate(runs) * 100, 1),
                "mean_turns": round(mean([r.get("total_turns", 0) or 0
                                          for r in success_runs]), 1),
                "mean_redundant_rate": round(mean([r.get("redundant_call_rate", 0) or 0
                                                    for r in success_runs]), 3),
            })
    save_csv(csv_rows, "rms_efficiency")
    print("RMS.2 done.")


def main():
    print("=== rq_model_sensitivity.py — generating RMS.1–RMS.2 ===")
    groups = _load_sens_runs()

    # Summary of loaded data
    loaded = sum(len(v) for v in groups.values())
    print(f"Loaded {loaded} runs across {len(groups)} (model, condition) groups")
    for (model, cond), runs in sorted(groups.items(), key=lambda x: (x[0][1], x[0][0])):
        label = MODEL_LABELS.get(model, model)
        print(f"  {cond:5s}  {label:<22}  {len(runs)} run(s)  "
              f"success={sum(1 for r in runs if r.get('mission_success'))}")

    make_rms1_heatmap(groups)
    make_rms2_efficiency(groups)
    print("Done. Figures written to raid_paper/figures/")


if __name__ == "__main__":
    main()
