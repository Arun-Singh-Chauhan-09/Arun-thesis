#!/usr/bin/env python3
"""
Per-manifest reporting.

analyse.py answers the research questions in aggregate. This script answers a
different question: for every single generated manifest, did it pass or fail,
and how far up the ladder did it get before stopping?

It produces the same content in three forms so the same numbers can be read,
seen and inspected:

    text   a per-manifest table and a set of summaries, printed
    charts PNG bar charts, one per view
    excel  a workbook whose first sheet is the full per-manifest grid

Nothing here recomputes a verdict. Everything is read from results/*.json
exactly as evaluate.py wrote it.

Usage:
    python3 scripts/report.py                      # text only
    python3 scripts/report.py --excel report.xlsx  # + workbook
    python3 scripts/report.py --charts figures/    # + PNG charts
    python3 scripts/report.py --all                # all three
    python3 scripts/report.py --model M3 --condition P2   # filter
"""
import argparse
import collections
import glob
import json
import math
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
RESULTS = ROOT / "results"

KPIS = ["K1", "K2", "K3", "K4", "K5", "K6"]

KPI_NAMES = {
    "K1": "Syntactic Validity",
    "K2": "Schema Conformance",
    "K3": "Cluster Admission",
    "K4": "Workload Readiness",
    "K5": "Functional Intent",
    "K6": "Security Posture",
}

MODEL_NAMES = {
    "M1": "Llama 3.3 70B",
    "M2": "DeepSeek Chat",
    "M3": "Claude Sonnet 5",
}

SCENARIO_NAMES = {
    "S01": "Stateless-Web",       "S02": "RBAC-Reader",
    "S03": "ConfigMap-Mount",     "S04": "Secret-Env",
    "S05": "Stateful-DB",         "S06": "CronJob-Backup",
    "S07": "Job-Migration",       "S08": "Ingress",
    "S09": "NetworkPolicy",       "S10": "DaemonSet",
    "S11": "Autoscaler",          "S12": "Health-Probes",
    "S13": "Resource-Limits",     "S14": "Sidecar-Logs",
    "S15": "ResourceQuota",       "S16": "Init-Container",
    "S17": "StatefulSet-Headless","S18": "Topology-Spread",
    "S19": "Node-Affinity",       "S20": "NodePort",
}

CONDITION_NAMES = {
    "P0": "Zero-Shot",
    "P1": "Non-Plausible",
    "P2": "Plausible",
    "P3": "Plausible Pair",
}

FAMILY = {
    "S01": "workload", "S02": "policy", "S03": "workload", "S04": "workload",
    "S05": "workload", "S06": "batch", "S07": "batch", "S08": "workload",
    "S09": "policy", "S10": "workload", "S11": "workload", "S12": "workload",
    "S13": "workload", "S14": "workload", "S15": "policy", "S16": "workload",
    "S17": "workload", "S18": "workload", "S19": "workload", "S20": "workload",
}

# Two Trivy rules were absent from the severity register when the batch ran and
# were recorded under their raw identifiers. They duplicate faults already
# counted semantically; merging here keeps the fault counts honest without
# re-evaluating the corpus.
FAULT_ALIASES = {
    "KSV-0118": "no_security_context",
    "KSV-0004": "capabilities_not_dropped",
    "KSV-0013": "image_tag_not_fixed",
    "no-anti-affinity": "no_pod_anti_affinity",
}


def cell(v):
    """Render one KPI verdict for a table."""
    if v is True:
        return "pass"
    if v is False:
        return "FAIL"
    if isinstance(v, str) and v.upper() == "N/A":
        return "n/a"
    return "-"          # never reached


def reached(verdict):
    """
    The highest rung this manifest got to.

    A rung counts as reached if it produced any verdict at all, including
    N/A - the check ran and concluded that it did not apply. A rung the
    ladder never got to is left as None by evaluate.py.
    """
    got = [k for k in KPIS if verdict.get(k) is not None]
    return got[-1] if got else "-"


def first_failure(verdict):
    return next((k for k in KPIS if verdict.get(k) is False), None)


def wilson(k, n, z=1.96):
    if n == 0:
        return 0.0, 0.0, 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, c - h), min(1.0, c + h)


def load(a):
    rows = []
    for f in sorted(glob.glob(str(RESULTS / "*.json"))):
        try:
            d = json.loads(pathlib.Path(f).read_text())
        except json.JSONDecodeError:
            continue
        gid = d.get("generation_id", "")
        if "MUT" in gid:
            continue
        parts = gid.split("_")
        if len(parts) != 4:
            continue
        s, c, m, r = parts
        if a.model and m not in a.model:
            continue
        if a.condition and c not in a.condition:
            continue
        if a.scenario and s not in a.scenario:
            continue
        v = d.get("verdict", {})
        rows.append({
            "gen_id": gid, "scenario": s, "condition": c, "model": m,
            "sample": r, "family": FAMILY.get(s, "?"),
            "classification": d.get("classification", "?"),
            "verdict": v, "detail": d.get("detail", {}),
            "findings": d.get("findings", []),
            "reached": reached(v),
            "failed_at": first_failure(v),
        })
    return rows


# ---------------------------------------------------------------- text
def print_per_manifest(rows, limit):
    print(f"\nPER-MANIFEST OUTCOME  ({len(rows)} manifests)")
    print("=" * 108)
    head = f"{'generation':22} {'model':16} "
    head += " ".join(f"{k:>5}" for k in KPIS)
    head += f"  {'reached':>8}  {'outcome':14}  why"
    print(head)
    print("-" * 108)

    shown = rows if limit == 0 else rows[:limit]
    for r in shown:
        line = f"{r['gen_id']:22} {MODEL_NAMES.get(r['model'], r['model']):16} "
        line += " ".join(f"{cell(r['verdict'].get(k)):>5}" for k in KPIS)
        why = ""
        if r["failed_at"]:
            why = (r["detail"].get(r["failed_at"], "") or "").split("\n")[0][:34]
        line += f"  {r['reached']:>8}  {r['classification']:14}  {why}"
        print(line)

    if limit and len(rows) > limit:
        print(f"... {len(rows) - limit} more (use --limit 0 to print all, "
              f"or --excel for the full grid)")


def print_summaries(rows):
    n = len(rows)

    print(f"\nHOW FAR EACH MANIFEST GOT")
    print("-" * 74)
    print(f"{'rung':4} {'name':22} {'stopped here':>13} {'share':>8}   "
          f"per model")
    models = sorted({r["model"] for r in rows})
    for k in KPIS:
        stopped = [r for r in rows if r["failed_at"] == k]
        per = "  ".join(
            f"{m}:{sum(1 for r in stopped if r['model'] == m)}" for m in models)
        print(f"{k:4} {KPI_NAMES[k]:22} {len(stopped):>13} "
              f"{100*len(stopped)/n:>7.1f}%   {per}")
    passed = [r for r in rows if r["failed_at"] is None]
    per = "  ".join(
        f"{m}:{sum(1 for r in passed if r['model'] == m)}" for m in models)
    print(f"{'--':4} {'passed every rung':22} {len(passed):>13} "
          f"{100*len(passed)/n:>7.1f}%   {per}")

    print(f"\nPASS AND FAIL BY MODEL")
    print("-" * 74)
    print(f"{'model':18} {'n':>5} {'pass':>6} {'fail':>6} {'pass rate':>10}   "
          f"{'95% CI':>16}")
    for m in models:
        sub = [r for r in rows if r["model"] == m]
        ok = sum(1 for r in sub if r["classification"] == "CLEAN")
        p, lo, hi = wilson(ok, len(sub))
        print(f"{MODEL_NAMES.get(m, m):18} {len(sub):>5} {ok:>6} "
              f"{len(sub)-ok:>6} {100*p:>9.1f}%   "
              f"[{100*lo:>5.1f}, {100*hi:>5.1f}]")

    print(f"\nPASS AND FAIL BY MODEL AND CONDITION")
    print("-" * 74)
    print(f"{'model':18} {'condition':20} {'n':>5} {'pass':>6} {'rate':>8}")
    for m in models:
        for c in ("P0", "P1", "P2", "P3"):
            sub = [r for r in rows if r["model"] == m and r["condition"] == c]
            if not sub:
                continue
            ok = sum(1 for r in sub if r["classification"] == "CLEAN")
            label = f"{CONDITION_NAMES.get(c, '')}"
            print(f"{MODEL_NAMES.get(m, m):18} {label:20} {len(sub):>5} "
                  f"{ok:>6} {100*ok/len(sub):>7.1f}%")
        print()


def fault_counts(rows):
    faults, sev = collections.Counter(), {}
    for r in rows:
        seen = set()
        for f in r["findings"]:
            cf = FAULT_ALIASES.get(f.get("canonical_fault", "?"),
                                   f.get("canonical_fault", "?"))
            if cf in seen:
                continue
            seen.add(cf)
            faults[cf] += 1
            sev[cf] = f.get("severity", "?")
    return faults, sev


# -------------------------------------------------------------- charts
def fault_counts_for(rows, model=None, condition=None):
    """Canonical fault counts for a slice of the corpus."""
    sub = rows
    if model is not None:
        sub = [r for r in sub if r["model"] == model]
    if condition is not None:
        sub = [r for r in sub if r["condition"] == condition]
    return fault_counts(sub), len(sub)


def make_charts(rows, outdir):
    """
    Create eight thesis-oriented charts in the required report order.

    The underlying data and calculations are unchanged from the original
    reporting logic.  This version improves readability by:
      * using question-style titles,
      * adding direct value labels,
      * using clearer condition/model names,
      * focusing the fault chart on the most frequent faults,
      * and adding a short key-findings text image for the Charts sheet.
    """
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("\nmatplotlib not installed - skipping charts")
        print("  pip install matplotlib --break-system-packages")
        return []

    outdir = pathlib.Path(outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    # Remove stale PNGs from previous report generations.
    for old in outdir.glob("*.png"):
        try:
            old.unlink()
        except OSError:
            pass
    models = sorted({r["model"] for r in rows})
    written = []

    # Consistent thesis-report colour mapping for model comparisons.
    # These are used only because the user requested distinct model colours.
    MODEL_COLORS = {
        "M2": "#4472C4",  # DeepSeek Chat
        "M3": "#ED7D31",  # Claude Sonnet 5
        "M1": "#70AD47",  # Llama 3.3 70B
    }

    def save(fig, name):
        path = outdir / name
        fig.tight_layout()
        fig.savefig(path, dpi=220, bbox_inches="tight")
        plt.close(fig)
        written.append(path)

    # 1 - where manifests stop, by model
    labels = [f"{k}\n{KPI_NAMES[k]}" for k in KPIS] + ["Passed\nall stages"]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    width = 0.8 / max(1, len(models))

    for i, m in enumerate(models):
        sub = [r for r in rows if r["model"] == m]
        counts = [sum(1 for r in sub if r["failed_at"] == k) for k in KPIS]
        counts.append(sum(1 for r in sub if r["failed_at"] is None))
        x = [j + i * width - 0.4 + width / 2 for j in range(len(labels))]
        bars = ax.bar(
            x, counts, width,
            label=MODEL_NAMES.get(m, m),
            color=MODEL_COLORS.get(m),
        )

        for bar, value in zip(bars, counts):
            if value:
                ax.text(
                    bar.get_x() + bar.get_width() / 2,
                    value + max(1, max(counts) * 0.015),
                    str(value),
                    ha="center",
                    va="bottom",
                    fontsize=8,
                )

    ax.set_xticks(range(len(labels)))
    ax.set_xticklabels(labels, fontsize=8)
    ax.set_ylabel("Number of manifests")
    ax.set_title(
        "Where do generated manifests fail?",
        fontsize=13,
        fontweight="bold",
        pad=10,
    )
    ax.legend(frameon=False, loc="upper right")
    ax.spines[["top", "right"]].set_visible(False)
    fig.text(
        0.5, 0.005,
        "Each manifest is counted at its first failed evaluation rung.",
        ha="center", va="bottom", fontsize=8.5
    )
    save(fig, "01_stopped_at_rung.png")

    # 2 - pass rate by model and condition
    conds = ["P0", "P1", "P2", "P3"]
    fig, ax = plt.subplots(figsize=(10, 5.2))
    width = 0.8 / max(1, len(models))

    for i, m in enumerate(models):
        rates = []
        for c in conds:
            sub = [
                r for r in rows
                if r["model"] == m and r["condition"] == c
            ]
            ok = sum(1 for r in sub if r["classification"] == "CLEAN")
            rates.append(100 * ok / len(sub) if sub else 0)

        x = [j + i * width - 0.4 + width / 2 for j in range(len(conds))]
        bars = ax.bar(
            x, rates, width,
            label=MODEL_NAMES.get(m, m),
            color=MODEL_COLORS.get(m),
        )

        for bar, value in zip(bars, rates):
            ax.text(
                bar.get_x() + bar.get_width() / 2,
                value + 2.0,
                f"{value:.1f}%",
                ha="center",
                va="bottom",
                fontsize=8,
            )

    ax.set_xticks(range(len(conds)))
    ax.set_xticklabels(
        [f"{c}\n{CONDITION_NAMES[c].title()}" for c in conds],
        fontsize=9,
    )
    ax.set_ylabel("Pass rate (%)")
    ax.set_ylim(0, 100)
    ax.set_title(
        "Does prompting improve manifest quality?",
        fontsize=13,
        fontweight="bold",
        pad=10,
    )
    ax.legend(frameon=False, loc="upper left")
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "02_pass_rate_by_condition.png")

    # 3 - clean manifests per model
    fig, ax = plt.subplots(figsize=(8, 4.8))
    model_labels = [MODEL_NAMES.get(m, m) for m in models]
    clean_counts = [
        sum(
            1 for r in rows
            if r["model"] == m and r["classification"] == "CLEAN"
        )
        for m in models
    ]

    bars = ax.bar(
        model_labels,
        clean_counts,
        color=[MODEL_COLORS.get(m) for m in models],
    )
    for bar, value in zip(bars, clean_counts):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            value + max(1, max(clean_counts) * 0.02),
            str(value),
            ha="center",
            va="bottom",
            fontsize=10,
            fontweight="bold",
        )

    ax.set_ylabel("Clean manifests")
    ax.set_title(
        "Which model produced more clean manifests?",
        fontsize=13,
        fontweight="bold",
        pad=10,
    )
    ax.spines[["top", "right"]].set_visible(False)
    fig.text(
        0.5, 0.005,
        "Colours identify models. Clean = passed all six evaluation stages.",
        ha="center", va="bottom", fontsize=8.5
    )
    save(fig, "03_clean_manifests_by_model.png")

    conds = ["P0", "P1", "P2", "P3"]
    COND_COLORS = {"P0": "#BDBDBD", "P1": "#F4B183",
                   "P2": "#4472C4", "P3": "#2E7D32"}
    # 4 - pass rate across all conditions and models
    # ---- combined: all conditions x models ----
    fig, ax = plt.subplots(figsize=(11, 5.6))
    gap = 0.19
    for i, c in enumerate(conds):
        xs, ys = [], []
        for j, m in enumerate(models):
            sub = [r for r in rows if r["model"] == m and r["condition"] == c]
            if not sub:
                continue
            ok = sum(1 for r in sub if r["classification"] == "CLEAN")
            xs.append(j + i * gap - 1.5 * gap); ys.append(100 * ok / len(sub))
        bars = ax.bar(xs, ys, gap, label=CONDITION_NAMES[c],
                      color=COND_COLORS[c], edgecolor="white", linewidth=0.5)
        for b, v in zip(bars, ys):
            ax.text(b.get_x() + b.get_width() / 2, v + 1.2, f"{v:.0f}",
                    ha="center", va="bottom", fontsize=7.5)
    ax.set_xticks(range(len(models)))
    ax.set_xticklabels([MODEL_NAMES.get(m, m) for m in models], fontsize=10)
    ax.set_ylim(0, 100); ax.set_ylabel("Pass rate (%)")
    ax.set_title("Pass rate across all conditions and models",
                 fontsize=14, fontweight="bold", pad=12)
    ax.legend(frameon=False, ncol=4, loc="upper center",
              bbox_to_anchor=(0.5, -0.10), fontsize=9)
    ax.spines[["top", "right"]].set_visible(False)
    save(fig, "04_combined_all_conditions.png")

    # 5 - most frequent faults
    faults, sev = fault_counts(rows)
    top = faults.most_common(10)[::-1]

    if top:
        fig, ax = plt.subplots(figsize=(11, 6.2))
        names = [
            f"{f.replace('_', ' ').title()}  [{sev.get(f, '?')}]"
            for f, _ in top
        ]
        values = [c for _, c in top]
        bars = ax.barh(names, values)

        for bar, value in zip(bars, values):
            ax.text(
                value + max(2, max(values) * 0.01),
                bar.get_y() + bar.get_height() / 2,
                f"{value} ({100 * value / len(rows):.1f}%)",
                va="center",
                fontsize=8,
            )

        ax.set_xlabel("Manifests affected")
        ax.set_xlim(0, max(values) * 1.18)
        ax.set_title(
            "What are the most common configuration and security faults?",
            fontsize=14,
            fontweight="bold",
            pad=12,
        )
        ax.tick_params(axis="y", labelsize=9)
        ax.spines[["top", "right"]].set_visible(False)
        save(fig, "05_top_faults.png")

    # ---- faults by model & by technique ----
    fa, fsev = fault_counts(rows)
    topf = [f for f, _ in fa.most_common(10)]
    if topf:
        for mode, keys, palette, title, fname in [
            ("model", models, MODEL_COLORS,
             "Most common faults, by model", "06_faults_by_model.png"),
            ("cond", conds, COND_COLORS,
             "Most common faults, by technique", "07_faults_by_technique.png")]:
            fig, ax = plt.subplots(figsize=(12, 6))
            y = range(len(topf)); h = 0.8 / len(keys)
            for i, k in enumerate(keys):
                if mode == "model":
                    (fc, _), n = fault_counts_for(rows, model=k)
                    lab = MODEL_NAMES.get(k, k); col = palette.get(k)
                else:
                    (fc, _), n = fault_counts_for(rows, condition=k)
                    lab = CONDITION_NAMES[k]; col = palette[k]
                vals = [100 * fc.get(f, 0) / n if n else 0 for f in topf]
                offs = [yy + i * h - 0.4 + h / 2 for yy in y]
                ax.barh(offs, vals, h, label=lab, color=col)
            ax.set_yticks(list(y))
            ax.set_yticklabels([f.replace("_", " ").title() for f in topf],
                               fontsize=9)
            ax.invert_yaxis(); ax.set_xlabel("Manifests affected (%)")
            ax.set_title(title, fontsize=14, fontweight="bold", pad=10)
            ax.legend(frameon=False, loc="lower right", fontsize=9)
            ax.spines[["top", "right"]].set_visible(False)
            save(fig, fname)

    # 5 - key findings panel
    # This is intentionally a simple PNG so it can be embedded in the
    # existing Excel Charts sheet without changing the workbook structure.
    n = len(rows)
    clean = sum(1 for r in rows if r["classification"] == "CLEAN")
    clean_pct = 100 * clean / n if n else 0

    # Find the dominant first-failure rung.
    rung_counts = {
        k: sum(1 for r in rows if r["failed_at"] == k)
        for k in KPIS
    }
    dominant_rung = max(rung_counts, key=rung_counts.get) if n else "-"
    dominant_count = rung_counts.get(dominant_rung, 0)
    dominant_name = KPI_NAMES.get(dominant_rung, dominant_rung)

    # Best model/condition combination.
    best = None
    for m in models:
        for c in ("P0", "P1", "P2", "P3"):
            sub = [r for r in rows if r["model"] == m and r["condition"] == c]
            if not sub:
                continue
            ok = sum(1 for r in sub if r["classification"] == "CLEAN")
            rate = 100 * ok / len(sub)
            candidate = (rate, MODEL_NAMES.get(m, m), c, CONDITION_NAMES[c])
            if best is None or candidate[0] > best[0]:
                best = candidate

    mutation_note = None
    # The reporting corpus deliberately excludes MUT records in load().
    # If a mutation result is present in the ordinary rows, do not invent
    # a value; therefore the dashboard only states findings supported by rows.
    if best:
        best_text = (
            f"Best model/condition: {best[1]} + {best[3].title()} "
            f"({best[0]:.1f}% pass rate)."
        )
    else:
        best_text = "Best model/condition: not available."

    fig, ax = plt.subplots(figsize=(11, 3.7))
    ax.axis("off")
    ax.text(
        0.02, 0.88, "KEY FINDINGS",
        fontsize=17, fontweight="bold", transform=ax.transAxes,
    )
    findings = [
        f"{n} Kubernetes manifests were evaluated.",
        f"{clean} manifests ({clean_pct:.1f}%) passed every evaluation rung.",
        f"The largest first-failure point was {dominant_rung} – {dominant_name} "
        f"({dominant_count} manifests).",
        best_text,
    ]
    y = 0.70
    for item in findings:
        ax.text(
            0.04, y, "• " + item,
            fontsize=11, transform=ax.transAxes, va="top",
        )
        y -= 0.17

    ax.text(
        0.02, 0.03,
        "Use the detailed workbook sheets for the underlying per-manifest and fault-level evidence.",
        fontsize=8.5, transform=ax.transAxes,
    )
    save(fig, "08_key_findings.png")


    print(f"\nwrote {len(written)} chart(s) to {outdir}/")
    for p in written:
        print(f"  {p.name}")
    return written


# --------------------------------------------------------------- excel
def make_excel(rows, path, charts):
    try:
        from openpyxl import Workbook
        from openpyxl.drawing.image import Image as XLImage
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        print("\nopenpyxl not installed - skipping workbook")
        return

    HEAD = Font(name="Arial", size=11, bold=True)
    BODY = Font(name="Arial", size=10)
    HDRB = PatternFill("solid", fgColor="DCE6F1")
    OK = PatternFill("solid", fgColor="C6EFCE")
    BAD = PatternFill("solid", fgColor="FFC7CE")
    NA = PatternFill("solid", fgColor="EDEDED")
    OKF = Font(name="Arial", size=10, bold=True, color="006100")
    BADF = Font(name="Arial", size=10, bold=True, color="9C0006")

    wb = Workbook()

    # ---- sheet 1: the per-manifest grid ------------------------------
    ws = wb.active
    ws.title = "Per manifest"
    headers = (["Generation", "ID", "Scenario", "Condition", "Model", "Family"]
               + [f"{k} {KPI_NAMES[k]}" for k in KPIS]
               + ["Reached", "Outcome", "Failed at", "Reason"])
    for c, h in enumerate(headers, start=1):
        x = ws.cell(row=1, column=c, value=h)
        x.font = HEAD
        x.fill = HDRB
        x.alignment = Alignment(wrap_text=True, vertical="center")

    for i, r in enumerate(rows, start=2):
        readable = (f"{SCENARIO_NAMES.get(r['scenario'], r['scenario'])} \u00b7 "
                    f"{CONDITION_NAMES.get(r['condition'], r['condition'])} \u00b7 "
                    f"{MODEL_NAMES.get(r['model'], r['model'])} \u00b7 "
                    f"iteration{r['sample'].replace('r', '')}")
        vals = [readable, r["gen_id"],
                f"{r['scenario']} {SCENARIO_NAMES.get(r['scenario'], '')}",
                CONDITION_NAMES.get(r["condition"], r["condition"]),
                MODEL_NAMES.get(r["model"], r["model"]), r["family"]]
        for c, v in enumerate(vals, start=1):
            x = ws.cell(row=i, column=c, value=v)
            x.font = BODY

        for j, k in enumerate(KPIS):
            v = r["verdict"].get(k)
            text = cell(v)
            x = ws.cell(row=i, column=6 + j, value=text)
            x.alignment = Alignment(horizontal="center")
            if v is True:
                x.font, x.fill = OKF, OK
            elif v is False:
                x.font, x.fill = BADF, BAD
            else:
                x.font, x.fill = BODY, NA

        failed = r["failed_at"]
        reason = (r["detail"].get(failed, "") or "").split("\n")[0] if failed else ""
        tail = [r["reached"], r["classification"],
                f"{failed} {KPI_NAMES[failed]}" if failed else "-", reason[:120]]
        for c, v in enumerate(tail, start=12):
            x = ws.cell(row=i, column=c, value=v)
            x.font = BODY
            if c == 13:
                x.font = OKF if v == "CLEAN" else BADF

    widths = [40, 22, 22, 16, 16, 10] + [9] * 6 + [10, 16, 26, 60]
    for c, w in enumerate(widths, start=1):
        ws.column_dimensions[ws.cell(row=1, column=c).column_letter].width = w
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions

    # ---- helper for the summary sheets -------------------------------
    def sheet(name, headers, data, widths):
        s = wb.create_sheet(name)
        for c, h in enumerate(headers, start=1):
            x = s.cell(row=1, column=c, value=h)
            x.font = HEAD
            x.fill = HDRB
        for i, row in enumerate(data, start=2):
            for c, v in enumerate(row, start=1):
                x = s.cell(row=i, column=c, value=v)
                x.font = BODY
        for c, w in enumerate(widths, start=1):
            s.column_dimensions[s.cell(row=1, column=c).column_letter].width = w
        s.freeze_panes = "A2"
        return s

    models = sorted({r["model"] for r in rows})

    # Summary values used by the "Stopped at rung" sheet.
    stopped = {
        k: sum(1 for r in rows if r["failed_at"] == k)
        for k in KPIS
    }
    model_stopped = {
        m: {k: sum(1 for r in rows
                   if r["model"] == m and r["failed_at"] == k)
            for k in KPIS}
        for m in models
    }
    passed_all = sum(1 for r in rows if r["failed_at"] is None)
    model_passed_all = {
        m: sum(1 for r in rows
               if r["model"] == m and r["failed_at"] is None)
        for m in models
    }

    sheet("Stopped at rung",
          ["Evaluation", "Name", "Total YAML files", "Manifests stopped here", "Share %"] + models,
          [[k, KPI_NAMES[k], len(rows), stopped[k], round(100 * stopped[k] / len(rows), 1)] +
           [model_stopped[m][k] for m in models]
           for k in KPIS] +
          [["--", "passed every rung", len(rows), passed_all, round(100 * passed_all / len(rows), 1)] +
           [model_passed_all[m] for m in models]],
          [12, 28, 16, 22, 10] + [18] * len(models))

       # ---- Pass by condition -------------------------------------------
    data = []
    for m in models:
        for c in ["P0", "P1", "P2", "P3"]:
            sub = [
                r for r in rows
                if r["model"] == m and r["condition"] == c
            ]
            if not sub:
                continue

            passed = sum(
                1 for r in sub
                if r["classification"] == "CLEAN"
            )
            total = len(sub)
            failed = total - passed
            rate = round(100 * passed / total, 1) if total else 0

            data.append([
                MODEL_NAMES.get(m, m),
                CONDITION_NAMES.get(c, c),
                total,
                passed,
                failed,
                rate,
            ])

    sheet(
        "Pass by condition",
        ["Model", "Condition", "n", "Pass", "Fail", "Pass rate %"],
        data,
        [20, 22, 7, 7, 7, 13],
    )

    faults, sev = fault_counts(rows)
    sheet("Faults",
          ["Canonical fault", "Severity", "Total YAML files", "Manifests", "Share %"],
          [[f, sev.get(f, "?"), len(rows), n, round(100 * n / len(rows), 1)]
           for f, n in faults.most_common()],
          [36, 12, 16, 12, 10])

    order = [f for f, _ in faults.most_common()]
    # ---- Faults by MODEL ----
    mc, mn = {}, {}
    for m in models:
        (fc, _), n = fault_counts_for(rows, model=m)
        mc[m], mn[m] = fc, n
    hdr = ["Canonical fault", "Severity"]
    for m in models:
        hdr += [f"{MODEL_NAMES.get(m, m)} n", f"{MODEL_NAMES.get(m, m)} %"]
    data = []
    for f in order:
        row = [f, sev.get(f, "?")]
        for m in models:
            cnt = mc[m].get(f, 0)
            row += [cnt, round(100 * cnt / mn[m], 1) if mn[m] else 0]
        data.append(row)
    sheet("Faults by model", hdr, data, [34, 10] + [13, 8] * len(models))

    # ---- Faults by TECHNIQUE ----
    cc, cn = {}, {}
    for c in ["P0", "P1", "P2", "P3"]:
        (fc, _), n = fault_counts_for(rows, condition=c)
        cc[c], cn[c] = fc, n
    hdr = ["Canonical fault", "Severity"]
    for c in ["P0", "P1", "P2", "P3"]:
        hdr += [f"{CONDITION_NAMES[c]} n", f"{CONDITION_NAMES[c]} %"]
    data = []
    for f in order:
        row = [f, sev.get(f, "?")]
        for c in ["P0", "P1", "P2", "P3"]:
            cnt = cc[c].get(f, 0)
            row += [cnt, round(100 * cnt / cn[c], 1) if cn[c] else 0]
        data.append(row)
    sheet("Faults by technique", hdr, data, [34, 10] + [16, 8] * 4)

    # ---- charts embedded, if they were generated ---------------------
    if charts:
        cs = wb.create_sheet("Charts")
        cs.column_dimensions["A"].width = 4

        # Place each chart below the previous one with enough vertical
        # space for the actual rendered image.  The old fixed "row += 26"
        # could make large PNGs overlap because Excel row height is much
        # smaller than image height.
        row = 1
        for p in charts:
            try:
                img = XLImage(str(p))

                scale = 0.62
                img.width = int(img.width * scale)
                img.height = int(img.height * scale)

                cs.add_image(img, f"A{row}")

                # Excel's default row height is about 20 pixels.  Convert
                # the image height into a safe number of worksheet rows
                # and add a small safety margin.
                rows_needed = max(1, int((img.height / 20) + 3))
                row += rows_needed
            except Exception:
                pass

    out = ROOT / path
    wb.save(out)
    print(f"\nwrote {out}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", nargs="+", help="restrict to these model labels")
    ap.add_argument("--condition", nargs="+", help="restrict to these conditions")
    ap.add_argument("--scenario", nargs="+", help="restrict to these scenarios")
    ap.add_argument("--limit", type=int, default=25,
                    help="rows to print; 0 prints all")
    ap.add_argument("--excel", nargs="?", const="report.xlsx",
                    help="also write a workbook")
    ap.add_argument("--charts", nargs="?", const="figures",
                    help="also write PNG charts to this directory")
    ap.add_argument("--all", action="store_true",
                    help="text, charts and workbook")
    a = ap.parse_args()

    if a.all:
        a.excel = a.excel or "report.xlsx"
        a.charts = a.charts or "figures"

    rows = load(a)
    if not rows:
        raise SystemExit("no results found - has the batch run?")

    by_model = collections.Counter(r["model"] for r in rows)
    print(f"manifests: {len(rows)}   "
          + "   ".join(f"{MODEL_NAMES.get(k, k)}: {v}"
                       for k, v in sorted(by_model.items())))

    print_per_manifest(rows, a.limit)
    print_summaries(rows)

    charts = make_charts(rows, a.charts) if a.charts else []
    if a.excel:
        make_excel(rows, a.excel, charts)


if __name__ == "__main__":
    main()