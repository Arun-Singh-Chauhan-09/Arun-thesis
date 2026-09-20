#!/usr/bin/env python3
"""
Dry run - one manifest, end to end, narrated.

This exists to be watched. It takes a single scenario through every stage of
the pipeline and pauses between them, printing what is about to happen, what
came back, and what that means. Nothing is hidden behind a progress bar.

It is deliberately separate from run_batch.py. The batch runner is built for
throughput across hundreds of cells; this is built to be explained to somebody
while it runs.

It does not touch the corpus. Everything is written under runs/DEMO_* and
results/DEMO_*, so the 480 evaluated generations are never at risk.

Usage:
    python3 scripts/dry_run.py                        # S01 / P2 / M3
    python3 scripts/dry_run.py --scenario S12 --condition P0 --model M2
    python3 scripts/dry_run.py --pause                # wait for a keypress
    python3 scripts/dry_run.py --keep                 # leave the namespace up
"""
import argparse
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
PY = sys.executable

KPI_NAMES = {
    "K1": "Syntactic Validity",
    "K2": "Schema Conformance",
    "K3": "Cluster Admission",
    "K4": "Workload Readiness",
    "K5": "Functional Intent",
    "K6": "Security Posture",
}
KPI_TOOL = {
    "K1": "PyYAML parses the document set",
    "K2": "kubeconform, strict, against the v1.31 schema",
    "K3": "kubectl apply into a namespace created for this run",
    "K4": "kubectl wait, 180 second budget",
    "K5": "a probe specific to this scenario",
    "K6": "Checkov, Trivy and kube-linter, findings deduplicated",
}
KPIS = list(KPI_NAMES)

BOLD, DIM, RESET = "\033[1m", "\033[2m", "\033[0m"
GREEN, RED, AMBER = "\033[32m", "\033[31m", "\033[33m"


def rule(char="-"):
    print(char * 72)


def stage(n, title, detail=""):
    print()
    rule("=")
    print(f"{BOLD}STAGE {n} — {title}{RESET}")
    if detail:
        print(f"{DIM}{detail}{RESET}")
    rule("=")


def wait(a):
    if a.pause:
        try:
            input(f"\n{DIM}[enter to continue]{RESET}")
        except (EOFError, KeyboardInterrupt):
            sys.exit("\nstopped")


def sh(cmd, timeout=600):
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                       timeout=timeout)
    return r.returncode == 0, (r.stdout or "") + (r.stderr or "")


def excerpt(text, n=14, indent="    "):
    lines = text.rstrip().splitlines()
    for l in lines[:n]:
        print(indent + l)
    if len(lines) > n:
        print(f"{indent}{DIM}... {len(lines) - n} more lines{RESET}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenario", default="S01")
    ap.add_argument("--condition", default="P2",
                    choices=["P0", "P1", "P2", "P3"])
    ap.add_argument("--model", default="M3")
    ap.add_argument("--pause", action="store_true",
                    help="wait for a keypress between stages")
    ap.add_argument("--keep", action="store_true",
                    help="leave the namespace running for inspection")
    a = ap.parse_args()

    gen_id = f"{a.scenario}_{a.condition}_{a.model}_rDEMO"
    rundir = ROOT / "runs" / gen_id
    prompt_path = ROOT / "prompts" / f"{a.scenario}_{a.condition}.txt"

    print()
    rule("=")
    print(f"{BOLD}  DRY RUN — one manifest, end to end{RESET}")
    rule("=")
    print(f"  scenario   {a.scenario}")
    print(f"  condition  {a.condition}")
    print(f"  model      {a.model}")
    print(f"  run id     {gen_id}")
    print(f"{DIM}  writes only to runs/{gen_id} and results/{gen_id}.json{RESET}")

    # ---- 1. the prompt -----------------------------------------------
    stage(1, "The prompt",
          f"Built earlier by build_prompts.py from the scenario statement "
          f"and,\nfor conditions other than P0, one reference example matched "
          f"to the\nscenario's resource family.")
    if not prompt_path.exists():
        sys.exit(f"missing {prompt_path} - run build_prompts.py first")
    text = prompt_path.read_text()
    print(f"  file    prompts/{prompt_path.name}")
    print(f"  size    {len(text)} bytes, {len(text.splitlines())} lines")
    has_example = "REFERENCE EXAMPLE" in text
    print(f"  example {'yes' if has_example else 'no — this is the baseline'}")
    if has_example:
        sc = text.count("securityContext")
        print(f"  the example mentions securityContext {sc} time(s)")
    print()
    task = re.search(r"TASK:\n(.+)", text)
    if task:
        print(f"  {BOLD}task:{RESET} {task.group(1).strip()}")
    wait(a)

    # ---- 2. generation -----------------------------------------------
    stage(2, "Generation",
          "The prompt is sent to the model once, at temperature 1.0.\n"
          "The reply is stored verbatim; nothing is parsed at this point.")
    t0 = time.time()
    ok, out = sh([PY, "scripts/generate.py", "--scenario", a.scenario,
                  "--condition", a.condition, "--model", a.model,
                  "--samples", "1", "--sample-start", "1"])
    if not ok:
        print(f"{RED}generation failed{RESET}")
        excerpt(out, 6)
        sys.exit(1)
    # generate.py names it _r1; move it aside so the corpus is untouched
    src = ROOT / "runs" / f"{a.scenario}_{a.condition}_{a.model}_r1"
    if src.exists() and src != rundir:
        if rundir.exists():
            for f in rundir.iterdir():
                f.unlink()
            rundir.rmdir()
        src.rename(rundir)
    print(f"  {out.strip().splitlines()[-1] if out.strip() else 'done'}")
    print(f"  elapsed {time.time() - t0:.1f}s")
    print(f"\n  {BOLD}first lines of the raw reply:{RESET}")
    excerpt((rundir / "response.txt").read_text(), 8)
    wait(a)

    # ---- 3. extraction -----------------------------------------------
    stage(3, "Extraction",
          "The YAML is lifted out of the fenced code block, verbatim.\n"
          "Keeping this separate from generation means the raw reply stays\n"
          "available for audit.")
    ok, out = sh([PY, "scripts/extract.py", "--gen", gen_id])
    if not ok and "unrecognized arguments" in out:
        ok, out = sh([PY, "scripts/extract.py", "--all"])
    manifest = rundir / "manifest.yaml"
    if not manifest.exists():
        print(f"{RED}extraction produced no manifest{RESET}")
        excerpt(out, 6)
        sys.exit(1)
    mtext = manifest.read_text()
    print(f"  wrote runs/{gen_id}/manifest.yaml "
          f"({len(mtext.splitlines())} lines)")
    print(f"\n  {BOLD}the manifest:{RESET}")
    excerpt(mtext, 18)
    wait(a)

    # ---- 4. evaluation -----------------------------------------------
    stage(4, "Evaluation — the six-rung ladder",
          "Each rung is checked in order. K1 and K2 are gating: a manifest\n"
          "that is not a valid Kubernetes object is never deployed.")
    for k in KPIS:
        print(f"  {k}  {KPI_NAMES[k]:22} {DIM}{KPI_TOOL[k]}{RESET}")
    print(f"\n{DIM}  running — K4 alone may take up to 180 seconds{RESET}")

    t0 = time.time()
    cmd = [PY, "scripts/evaluate.py", "--gen", gen_id]
    if a.keep:
        cmd.append("--keep-namespace")
    ok, out = sh(cmd)
    took = time.time() - t0

    res_path = ROOT / "results" / f"{gen_id}.json"
    if not res_path.exists():
        print(f"{RED}evaluation produced no result{RESET}")
        excerpt(out, 8)
        sys.exit(1)
    res = json.loads(res_path.read_text())
    verdict, detail = res["verdict"], res["detail"]

    print(f"\n  elapsed {took:.1f}s\n")
    print(f"  {'':4} {'KPI':22} {'result':9} why")
    rule()
    for k in KPIS:
        v = verdict.get(k)
        if v is True:
            mark, colour = "pass", GREEN
        elif v is False:
            mark, colour = "FAIL", RED
        elif isinstance(v, str):
            mark, colour = "n/a", AMBER
        else:
            mark, colour = "-", DIM
        why = (detail.get(k, "") or "").split("\n")[0][:32]
        print(f"  {k:4} {KPI_NAMES[k]:22} {colour}{mark:9}{RESET} {DIM}{why}{RESET}")
    wait(a)

    # ---- 5. the verdict ----------------------------------------------
    stage(5, "Classification")
    cls = res["classification"]
    colour = {"CLEAN": GREEN, "MISCONFIGURED": AMBER,
              "INVALID": RED}.get(cls, "")
    print(f"  {BOLD}{colour}{cls}{RESET}")
    print()
    if cls == "INVALID":
        print("  Failed K1 or K2, so it was never deployed.")
    elif cls == "MISCONFIGURED":
        failed = [k for k in KPIS if verdict.get(k) is False]
        names = ", ".join(f"{k} {KPI_NAMES[k]}" for k in failed)
        print(f"  Reached the cluster but failed: {names}.")
        if verdict.get("K6") is False and all(
                verdict.get(k) is not False for k in ("K3", "K4", "K5")):
            print()
            print(f"  {BOLD}This is the case the study is about.{RESET}")
            print("  The manifest is valid, deploys, becomes ready and does")
            print("  what was asked — and is still not secure. No static")
            print("  check alone separates those two things.")
    else:
        print("  Passed every rung: valid, deployed, ready, correct and")
        print("  carrying no HIGH or CRITICAL security fault.")

    findings = res.get("findings", [])
    if findings:
        blocking = [f for f in findings
                    if f.get("severity") in ("HIGH", "CRITICAL")]
        print(f"\n  {len(findings)} distinct canonical fault(s) after "
              f"deduplication, {len(blocking)} of them blocking:")
        for f in blocking[:6]:
            scanners = ", ".join(sorted(set(f.get("scanners", []))))
            print(f"    {RED}{f['severity']:8}{RESET} "
                  f"{f['canonical_fault']:32} {DIM}{scanners}{RESET}")
        if len(blocking) > 6:
            print(f"    {DIM}... {len(blocking) - 6} more{RESET}")

    # ---- 6. where it goes --------------------------------------------
    stage(6, "What was written")
    print(f"  runs/{gen_id}/response.txt      the raw reply")
    print(f"  runs/{gen_id}/generation.json   model id, tokens, timing, hash")
    print(f"  runs/{gen_id}/manifest.yaml     the extracted manifest")
    print(f"  results/{gen_id}.json           verdicts, faults, classification")
    print()
    print(f"{DIM}  Across the corpus these result files are what analyse.py")
    print(f"  and report.py read. Nothing is recomputed downstream.{RESET}")

    if a.keep:
        print(f"\n{AMBER}  Namespace {res.get('namespace')} was left running."
              f"{RESET}")
        print(f"  kubectl -n {res.get('namespace')} get pods")
        print(f"  kubectl delete ns {res.get('namespace')}")

    print()
    rule("=")
    print(f"  {BOLD}{cls}{RESET}   {gen_id}")
    rule("=")
    print()


if __name__ == "__main__":
    main()