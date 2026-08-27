#!/usr/bin/env python3
"""
Simplified KPI Ladder Tester (K1 - K6)

Takes a manifest, runs it through the K1-K6 evaluation ladder,
and outputs a clean Excel table with the results.

Usage:
    python3 scripts/mutation_test.py --base runs/S01_P0_M1_manual/manifest.yaml
    python3 scripts/mutation_test.py -o kpi_test_results.xlsx
"""
import argparse
import json
import pathlib
import subprocess
import sys

# --- CONSTANTS ---
ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
RESULTS = ROOT / "results"
KPIS = ["K1", "K2", "K3", "K4", "K5", "K6"]
KPI_QUESTIONS = {
    "K1": "Parseable YAML (PyYAML)",
    "K2": "Valid Kubernetes schema (kubeconform)",
    "K3": "Cluster accepts it (kubectl apply)",
    "K4": "Becomes ready (kubectl wait, 180s)",
    "K5": "Does what was asked (intent probe)",
    "K6": "No HIGH/CRITICAL faults (Checkov/Trivy/kube-linter)",
}

def run_eval(manifest_path):
    """Run evaluate.py and return the JSON result."""
    r = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "evaluate.py"), "--manifest", str(manifest_path)],
        capture_output=True, text=True, cwd=ROOT,
    )
    out = RESULTS / f"temp_result.json"
    if out.exists():
        return json.loads(out.read_text())
    return None

def dig(obj, key):
    """Recursively find a key in nested dicts/lists."""
    if isinstance(obj, dict):
        if key in obj:
            return obj[key]
        for v in obj.values():
            f = dig(v, key)
            if f is not None:
                return f
    elif isinstance(obj, list):
        for v in obj:
            f = dig(v, key)
            if f is not None:
                return f
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True, help="Path to the manifest to test")
    ap.add_argument("-o", "--out", default="kpi_test_results.xlsx")
    a = ap.parse_args()

    base_path = pathlib.Path(a.base)
    if not base_path.exists():
        sys.exit(f"Error: Manifest not found at {base_path}")

    print(f"Testing manifest: {base_path}")

    # Run the evaluator
    rec = run_eval(base_path)
    if rec is None:
        sys.exit("Error: evaluate.py did not produce a results JSON file.")

    verdict = rec.get("verdict", {})
    details = rec.get("detail", {})
    classification = dig(rec, "classification") or "?"

    # ----------------------------------------------------- EXCEL GENERATION
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Alignment, Font, PatternFill, Border, Side
    except ImportError:
        print("(openpyxl not installed - skipping workbook)")
        return

    # Styles
    HEAD = Font(name="Calibri", size=11, bold=True)
    BODY = Font(name="Calibri", size=11)
    OKF = Font(name="Calibri", size=11, color="006100")
    BADF = Font(name="Calibri", size=11, color="9C0006")
    OKB = PatternFill("solid", fgColor="C6EFCE")
    BADB = PatternFill("solid", fgColor="FFC7CE")
    SKIPB = PatternFill("solid", fgColor="EDEDED")
    HDRB = PatternFill("solid", fgColor="DCE6F1")
    BORDER = Border(left=Side(style='thin'), right=Side(style='thin'), top=Side(style='thin'), bottom=Side(style='thin'))

    wb = Workbook()
    ws = wb.active
    ws.title = "KPI Results"

    # Row 1: Headers
    headers = ["KPI", "What it checks", "passed/failed/skipped", "Details/Errors"]
    for col, h in enumerate(headers, start=1):
        c = ws.cell(row=1, column=col, value=h)
        c.font = HEAD
        c.fill = HDRB
        c.border = BORDER
        c.alignment = Alignment(horizontal="center", vertical="center")

    # Rows 2-7: KPI Data
    row = 2
    for k in KPIS:
        ws.cell(row=row, column=1, value=k).font = HEAD
        ws.cell(row=row, column=2, value=KPI_QUESTIONS[k]).font = BODY

        raw = verdict.get(k)
        if raw is True:
            text, font, fill = "passed", OKF, OKB
        elif raw is False:
            text, font, fill = "failed", BADF, BADB
        else:
            text, font, fill = "skipped", BODY, SKIPB
        
        c = ws.cell(row=row, column=3, value=text)
        c.font, c.fill = font, fill
        c.alignment = Alignment(horizontal="center", vertical="center")

        msg = details.get(k) or ""
        m = ws.cell(row=row, column=4, value=msg)
        m.font = BODY
        m.alignment = Alignment(vertical="center", wrap_text=True)
        row += 1

    # Row 8: Classification
    ws.cell(row=row, column=1, value="Classification").font = HEAD
    ws.cell(row=row, column=2, value=classification).font = HEAD
    ws.cell(row=row, column=3, value="").font = BODY
    ws.cell(row=row, column=4, value="").font = BODY

    # Column Widths
    ws.column_dimensions["A"].width = 12
    ws.column_dimensions["B"].width = 45
    ws.column_dimensions["C"].width = 22
    ws.column_dimensions["D"].width = 60

    out = ROOT / a.out
    wb.save(out)
    print(f"Created KPI test table: {out}")

if __name__ == "__main__":
    main()