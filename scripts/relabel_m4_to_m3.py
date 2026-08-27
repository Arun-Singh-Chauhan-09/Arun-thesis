#!/usr/bin/env python3
"""
Rename the model label M4 to M3 across every artefact.

The labels were assigned as models were added, leaving a gap: M1, M2, M4 with
no M3. The gap is cosmetic but invites the question "what happened to M3?" in
a viva, so it is closed here rather than explained away.

This is safe because the label is only an index. Every generation.json also
records model_id, so the identity of the model behind each result does not
depend on the label at all - and this script verifies that before touching
anything: if any M4 record names a model other than the expected one, it
stops.

Renames:
    runs/<scenario>_<condition>_M4_r<n>/   ->  ..._M3_r<n>/
    results/<scenario>_<condition>_M4_r<n>.json  ->  ..._M3_r<n>.json
    the generation_id field inside both JSON files

Usage:
    python3 scripts/relabel_m4_to_m3.py --check    # report, change nothing
    python3 scripts/relabel_m4_to_m3.py            # perform the rename
"""
import argparse
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
RESULTS = ROOT / "results"

OLD, NEW = "M4", "M3"
EXPECTED_MODEL_ID = "claude-sonnet-5"


def collect():
    run_dirs = sorted(d for d in RUNS.glob(f"*_{OLD}_r*") if d.is_dir())
    result_files = sorted(RESULTS.glob(f"*_{OLD}_r*.json"))
    return run_dirs, result_files


def verify(run_dirs):
    """Refuse to proceed if any M4 record names an unexpected model."""
    problems, seen = [], set()
    for d in run_dirs:
        gj = d / "generation.json"
        if not gj.exists():
            continue
        mid = json.loads(gj.read_text()).get("model_id", "?")
        seen.add(mid)
        if mid != EXPECTED_MODEL_ID:
            problems.append(f"{d.name}: model_id is {mid}, expected "
                            f"{EXPECTED_MODEL_ID}")
    return problems, seen


def target_name(name):
    return name.replace(f"_{OLD}_", f"_{NEW}_")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true",
                    help="report what would change without changing it")
    a = ap.parse_args()

    if not RUNS.is_dir():
        sys.exit(f"{RUNS} not found - run this from the project root")

    run_dirs, result_files = collect()
    if not run_dirs and not result_files:
        sys.exit(f"nothing labelled {OLD} found - already renamed?")

    print(f"{len(run_dirs)} run director(ies), "
          f"{len(result_files)} result file(s) labelled {OLD}")

    problems, seen = verify(run_dirs)
    print(f"model_id(s) present under {OLD}: {', '.join(sorted(seen)) or 'none'}")
    if problems:
        print(f"\nREFUSING TO RENAME - {len(problems)} record(s) do not match "
              f"the expected model:")
        for p in problems[:10]:
            print(f"  - {p}")
        sys.exit(1)

    # nothing may already occupy the target names
    clashes = [d.name for d in run_dirs
               if (RUNS / target_name(d.name)).exists()]
    clashes += [f.name for f in result_files
                if (RESULTS / target_name(f.name)).exists()]
    if clashes:
        print(f"\nREFUSING TO RENAME - target already exists for "
              f"{len(clashes)} item(s), e.g. {clashes[0]}")
        sys.exit(1)

    if a.check:
        for d in run_dirs[:3]:
            print(f"  would rename {d.name} -> {target_name(d.name)}")
        print(f"  ... and {len(run_dirs) - 3} more directories")
        print(f"\nOK - run without --check to perform the rename")
        return

    # ---- run directories, and the generation_id inside them -----------
    for d in run_dirs:
        new_dir = RUNS / target_name(d.name)
        gj = d / "generation.json"
        if gj.exists():
            rec = json.loads(gj.read_text())
            rec["model_label"] = NEW
            rec["generation_id"] = target_name(rec["generation_id"])
            gj.write_text(json.dumps(rec, indent=2))
        d.rename(new_dir)

    # ---- result files, and the generation_id inside them --------------
    for f in result_files:
        rec = json.loads(f.read_text())
        rec["generation_id"] = target_name(rec["generation_id"])
        if "namespace" in rec:
            rec["namespace"] = rec["namespace"].replace("-m4-", "-m3-")
        f.write_text(json.dumps(rec, indent=2))
        f.rename(RESULTS / target_name(f.name))

    print(f"\nrenamed {len(run_dirs)} run director(ies) and "
          f"{len(result_files)} result file(s)")
    print("\nRemaining manual step: in scripts/generate.py, the MODELS dict")
    print("should now read")
    print('    "M3": {"id": "claude-sonnet-5", ...}')
    print("and the deepseek-reasoner entry should be removed or relabelled,")
    print("since it was never run and its slot is now taken.")
    print("\nThen re-run:  python3 scripts/analyse.py -o analysis.xlsx")


if __name__ == "__main__":
    main()