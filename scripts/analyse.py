#!/usr/bin/env python3
"""
Stage 6 - analysis.

Reads every results/*.json and produces the tables the research questions ask
for. Works on partial data, so it can be run while a batch is still going.

    RQ1  which model produces more secure manifests   -> SDR by model
    RQ2  does the reference example change anything   -> SDR by condition
    RQ3  what goes wrong                              -> canonical fault counts

SDR (Secure Deployment Rate) = CLEAN / all generations attempted. INVALID
generations stay in the denominator: failing to produce valid YAML is itself
a result, not a sample to discard.

Proportions carry Wilson 95% intervals rather than the normal approximation,
which misbehaves badly at the extremes - and with SDRs near 0 or 1 the normal
interval would run outside [0, 1] and imply precision that is not there.

Results are also split by resource family, because policy manifests (RBAC,
NetworkPolicy, ResourceQuota) create no Pods and are therefore exempt from
most of the K6 container checks by construction. Pooling them with workload
scenarios would make SDR move with the scenario mix rather than with the
model or the prompt, which is not what the research questions are asking.

Usage:
    python3 scripts/analyse.py                  # print the tables
    python3 scripts/analyse.py -o analysis.xlsx # also write a workbook
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
CLASSES = ["CLEAN", "MISCONFIGURED", "INVALID"]

# which family each scenario belongs to - must match build_prompts.py
FAMILY = {
    "S01": "workload", "S02": "policy", "S03": "workload", "S04": "workload",
    "S05": "workload", "S06": "batch", "S07": "batch", "S08": "workload",
    "S09": "policy", "S10": "workload", "S11": "workload", "S12": "workload",
    "S13": "workload", "S14": "workload", "S15": "policy", "S16": "workload",
    "S17": "workload", "S18": "workload", "S19": "workload", "S20": "workload",
}

# --------------------------------------------------------------------------
# Post-hoc canonical fault aliases.
#
# Two Trivy rules were absent from severity_register.csv when the batch ran,
# so evaluate.py fell back to using the raw rule id as the canonical fault.
# They are duplicates of faults already counted under a semantic name, which
# inflates the RQ3 distribution: KSV-0118 fired on 309 manifests alongside
# no_security_context on 310, and KSV-0004 on 304 alongside
# capabilities_not_dropped on 304.
#
# The register has since been corrected, so re-running the batch would not
# need this. Merging here avoids re-evaluating 487 manifests to fix a
# reporting artefact. K6 verdicts are unaffected either way: both rules
# already carried HIGH severity and gated correctly.
# --------------------------------------------------------------------------
FAULT_ALIASES = {
    "KSV-0118": "no_security_context",
    "KSV-0004": "capabilities_not_dropped",
}

KPI_NAMES = {
    "K1": "Syntactic Validity",
    "K2": "Schema Conformance",
    "K3": "Cluster Admission",
    "K4": "Workload Readiness",
    "K5": "Functional Intent",
    "K6": "Security Posture",
}

KPI_WHAT = {
    "K1": "Parses as YAML (PyYAML)",
    "K2": "Valid Kubernetes object (kubeconform, v1.31)",
    "K3": "Accepted by the cluster (kubectl apply)",
    "K4": "Pods reach Ready within 180 s (kubectl wait)",
    "K5": "Does what the scenario asked (per-scenario probe)",
    "K6": "No HIGH/CRITICAL fault (Checkov, Trivy, kube-linter)",
}

MODEL_NAMES = {
    "M1": "third model, pending",
    "M2": "DeepSeek Chat",
    "M3": "Claude Sonnet 5",
}


def wilson(successes, n, z=1.96):
    """Wilson score interval for a binomial proportion."""
    if n == 0:
        return (0.0, 0.0, 0.0)
    p = successes / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return p, max(0.0, centre - half), min(1.0, centre + half)


def load():
    """Every non-mutation result, as a list of flat records."""
    out = []
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
        out.append({
            "gen_id": gid, "scenario": s, "condition": c, "model": m,
            "sample": r, "family": FAMILY.get(s, "?"),
            "classification": d.get("classification", "?"),
            "verdict": d.get("verdict", {}),
            "findings": d.get("findings", []),
        })
    return out


def sdr_row(rows):
    n = len(rows)
    clean = sum(1 for r in rows if r["classification"] == "CLEAN")
    p, lo, hi = wilson(clean, n)
    return n, clean, p, lo, hi


def table(title, groups, order=None):
    """groups: {label: [rows]}"""
    print(f"\n{title}")
    print("-" * 74)
    print(f"{'':22} {'n':>5} {'clean':>6} {'SDR':>7}   {'95% CI (Wilson)':>18}")
    keys = order or sorted(groups)
    for k in keys:
        rows = groups.get(k, [])
        if not rows:
            continue
        n, clean, p, lo, hi = sdr_row(rows)
        print(f"{str(k):22} {n:>5} {clean:>6} {100*p:>6.1f}%   "
              f"[{100*lo:>5.1f}%, {100*hi:>5.1f}%]")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", help="also write an xlsx workbook")
    a = ap.parse_args()

    rows = load()
    if not rows:
        raise SystemExit("no results found - has the batch run?")

    print(f"generations analysed: {len(rows)}")
    by_model = collections.Counter(r["model"] for r in rows)
    print("per model: " + ", ".join(f"{k}={v}" for k, v in sorted(by_model.items())))

    # ---- overall classification -------------------------------------
    cls = collections.Counter(r["classification"] for r in rows)
    print("\noverall outcome")
    print("-" * 74)
    for c in CLASSES:
        n = cls.get(c, 0)
        print(f"{c:22} {n:>5}  {100*n/len(rows):>5.1f}%")

    # ---- RQ1: by model -----------------------------------------------
    g = collections.defaultdict(list)
    for r in rows:
        g[f"{r['model']} {MODEL_NAMES.get(r['model'], '')}".strip()].append(r)
    table("RQ1 - SDR by model", g)

    # ---- RQ2: by condition -------------------------------------------
    g = collections.defaultdict(list)
    for r in rows:
        g[r["condition"]].append(r)
    table("RQ2 - SDR by prompting condition", g, order=["P0", "P1", "P2", "P3"])

    # ---- model x condition -------------------------------------------
    g = collections.defaultdict(list)
    for r in rows:
        g[f"{r['model']} / {r['condition']}"].append(r)
    table("Model x condition", g)

    # ---- by family ----------------------------------------------------
    g = collections.defaultdict(list)
    for r in rows:
        g[r["family"]].append(r)
    table("SDR by resource family", g, order=["workload", "batch", "policy"])
    print("\n  policy manifests create no Pods, so most K6 container checks")
    print("  do not apply to them - read their SDR separately, not pooled.")

    # ---- workload-only: the comparison the RQs actually rest on -------
    # Policy manifests create no Pods and pass K6 by having nothing to
    # harden, so pooling them lets SDR move with the scenario mix rather
    # than with the model or the prompt. Restricting to workload isolates
    # the cases where container security is actually at stake.
    wl = [r for r in rows if r["family"] == "workload"]
    if wl:
        g = collections.defaultdict(list)
        for r in wl:
            g[f"{r['model']} / {r['condition']}"].append(r)
        table(f"WORKLOAD FAMILY ONLY - SDR by model and condition "
              f"(n={len(wl)})", g)

        # Pooled: does the model respond to a hardened exemplar at all?
        # P0 shows no example and P1 shows an unhardened one, so neither
        # demonstrates the properties K6 checks; P2 and P3 both do. Pooling
        # in those two pairs doubles the cell size and asks the question
        # directly, rather than splitting it across four thin conditions.
        print("\nWORKLOAD FAMILY - weak or absent example (P0+P1) "
              "vs hardened example (P2+P3)")
        print("-" * 74)
        print(f"{'':22} {'n':>5} {'clean':>6} {'SDR':>7}   "
              f"{'95% CI (Wilson)':>18}")
        for m in sorted({r["model"] for r in wl}):
            for label, conds in (("weak (P0+P1)", ("P0", "P1")),
                                 ("hardened (P2+P3)", ("P2", "P3"))):
                sub = [r for r in wl
                       if r["model"] == m and r["condition"] in conds]
                if not sub:
                    continue
                n, clean, pr, lo, hi = sdr_row(sub)
                name = f"{m} {label}"
                print(f"{name:22} {n:>5} {clean:>6} {100*pr:>6.1f}%   "
                      f"[{100*lo:>5.1f}%, {100*hi:>5.1f}%]")
            print()

    # ---- where the ladder breaks --------------------------------------
    print("\nKPI failures")
    print("-" * 86)
    print(f"{'KPI':4} {'name':22} {'failed':>7} {'of':>6}  {'rate':>7}   "
          f"first failure for")
    for k in KPIS:
        failed = [r for r in rows if r["verdict"].get(k) is False]
        n_ran = sum(1 for r in rows if r["verdict"].get(k) is not None)
        first = sum(1 for r in rows
                    if next((x for x in KPIS if r["verdict"].get(x) is False),
                            None) == k)
        rate = f"{100*len(failed)/n_ran:.1f}%" if n_ran else "-"
        print(f"{k:4} {KPI_NAMES[k]:22} {len(failed):>7} {n_ran:>6}  "
              f"{rate:>7}   {first}")

    # ---- RQ3: canonical fault distribution ----------------------------
    faults = collections.Counter()
    fault_sev = {}
    for r in rows:
        seen = set()
        for f in r["findings"]:
            cf = f.get("canonical_fault", "?")
            cf = FAULT_ALIASES.get(cf, cf)
            if cf in seen:
                continue          # already deduped per manifest, but be safe
            seen.add(cf)
            faults[cf] += 1
            fault_sev[cf] = f.get("severity", "?")

    print(f"\nRQ3 - canonical faults, most common first "
          f"(n={len(rows)} manifests)")
    if FAULT_ALIASES:
        merged = ", ".join(f"{k} -> {v}" for k, v in FAULT_ALIASES.items())
        print(f"  merged post hoc: {merged}")
    print("-" * 74)
    print(f"{'fault':34} {'severity':10} {'count':>6} {'% of manifests':>15}")
    for cf, n in faults.most_common(20):
        print(f"{cf:34} {fault_sev.get(cf, '?'):10} {n:>6} "
              f"{100*n/len(rows):>14.1f}%")

    # ---- model comparison table (professor item 8) --------------------
    print("\nModel comparison")
    print("-" * 74)
    models = sorted({r["model"] for r in rows})
    print(f"{'':24} " + "".join(f"{MODEL_NAMES.get(m, m)[:16]:>18}"
                                for m in models))
    metrics = []
    for m in models:
        mr = [r for r in rows if r["model"] == m]
        n, clean, p, lo, hi = sdr_row(mr)
        inv = sum(1 for r in mr if r["classification"] == "INVALID")
        k6f = sum(1 for r in mr if r["verdict"].get("K6") is False)
        k6n = sum(1 for r in mr if r["verdict"].get("K6") is not None)
        avg = (sum(len(r["findings"]) for r in mr) / len(mr)) if mr else 0
        metrics.append((n, clean, p, inv, k6f, k6n, avg))
    labels = ["generations", "clean", "SDR", "invalid",
              "K6 failures", "faults per manifest"]
    for i, lab in enumerate(labels):
        line = f"{lab:24} "
        for n, clean, p, inv, k6f, k6n, avg in metrics:
            v = [n, clean, f"{100*p:.1f}%", inv,
                 f"{k6f}/{k6n}", f"{avg:.1f}"][i]
            line += f"{str(v):>18}"
        print(line)

    if not a.out:
        print("\n(pass -o analysis.xlsx to also write a workbook)")
        return

    # ---- workbook -----------------------------------------------------
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill
    except ImportError:
        print("\nopenpyxl not installed - skipping workbook")
        return

    HEAD = Font(name="Arial", size=11, bold=True)
    BODY = Font(name="Arial", size=11)
    HDRB = PatternFill("solid", fgColor="DCE6F1")

    wb = Workbook()

    def sheet(name, headers, data, widths):
        ws = wb.create_sheet(name)
        for c, h in enumerate(headers, start=1):
            cell = ws.cell(row=1, column=c, value=h)
            cell.font = HEAD
            cell.fill = HDRB
        for r, row in enumerate(data, start=2):
            for c, v in enumerate(row, start=1):
                cell = ws.cell(row=r, column=c, value=v)
                cell.font = BODY
                cell.alignment = Alignment(vertical="top", wrap_text=(c == 1))
        for col, w in zip("ABCDEFGH", widths):
            ws.column_dimensions[col].width = w
        ws.freeze_panes = "A2"
        return ws

    wb.remove(wb.active)

    def sdr_sheet(name, keyfn, order=None):
        g = collections.defaultdict(list)
        for r in rows:
            g[keyfn(r)].append(r)
        data = []
        for k in (order or sorted(g)):
            if k not in g:
                continue
            n, clean, p, lo, hi = sdr_row(g[k])
            data.append([str(k), n, clean, round(100 * p, 1),
                         round(100 * lo, 1), round(100 * hi, 1)])
        sheet(name, ["group", "n", "clean", "SDR %", "CI low %", "CI high %"],
              data, [26, 8, 8, 10, 11, 11])

    sdr_sheet("By model", lambda r: r["model"])
    sdr_sheet("By condition", lambda r: r["condition"], ["P0", "P1", "P2", "P3"])
    sdr_sheet("Model x condition", lambda r: f"{r['model']} / {r['condition']}")
    sdr_sheet("By family", lambda r: r["family"], ["workload", "batch", "policy"])

    # workload-only sheets: the tables the write-up quotes
    wl = [r for r in rows if r["family"] == "workload"]
    if wl:
        g = collections.defaultdict(list)
        for r in wl:
            g[f"{r['model']} / {r['condition']}"].append(r)
        data = []
        for k in sorted(g):
            n, clean, pr, lo, hi = sdr_row(g[k])
            data.append([k, n, clean, round(100 * pr, 1),
                         round(100 * lo, 1), round(100 * hi, 1)])
        sheet("Workload only",
              ["model / condition", "n", "clean", "SDR %",
               "CI low %", "CI high %"], data, [26, 8, 8, 10, 11, 11])

        data = []
        for m in sorted({r["model"] for r in wl}):
            for label, conds in (("weak (P0+P1)", ("P0", "P1")),
                                 ("hardened (P2+P3)", ("P2", "P3"))):
                sub = [r for r in wl
                       if r["model"] == m and r["condition"] in conds]
                if not sub:
                    continue
                n, clean, pr, lo, hi = sdr_row(sub)
                data.append([f"{m} {label}", n, clean, round(100 * pr, 1),
                             round(100 * lo, 1), round(100 * hi, 1)])
        sheet("Weak vs hardened",
              ["model / example", "n", "clean", "SDR %",
               "CI low %", "CI high %"], data, [26, 8, 8, 10, 11, 11])

    sheet("KPI ladder",
          ["KPI", "name", "what it checks", "failed", "evaluated",
           "failure rate %", "first failure for"],
          [[k, KPI_NAMES[k], KPI_WHAT[k],
            sum(1 for r in rows if r["verdict"].get(k) is False),
            sum(1 for r in rows if r["verdict"].get(k) is not None),
            round(100 * sum(1 for r in rows if r["verdict"].get(k) is False)
                  / max(1, sum(1 for r in rows
                               if r["verdict"].get(k) is not None)), 1),
            sum(1 for r in rows
                if next((x for x in KPIS if r["verdict"].get(x) is False),
                        None) == k)]
           for k in KPIS],
          [8, 24, 44, 10, 12, 15, 18])

    sheet("Faults",
          ["canonical fault", "severity", "manifests", "% of manifests"],
          [[cf, fault_sev.get(cf, "?"), n, round(100 * n / len(rows), 1)]
           for cf, n in faults.most_common()],
          [36, 12, 12, 15])

    sheet("Per generation",
          ["generation", "scenario", "condition", "model", "family",
           "classification", "first failure"],
          [[r["gen_id"], r["scenario"], r["condition"], r["model"],
            r["family"], r["classification"],
            (lambda k: f"{k} {KPI_NAMES[k]}" if k else "-")(
                next((k for k in KPIS if r["verdict"].get(k) is False), None))]
           for r in rows],
          [26, 10, 11, 8, 11, 16, 13])

    out = ROOT / a.out
    wb.save(out)
    print(f"\nwrote {out}")


if __name__ == "__main__":
    main()