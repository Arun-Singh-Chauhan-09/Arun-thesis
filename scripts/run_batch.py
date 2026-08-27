#!/usr/bin/env python3
"""
Run the full experimental matrix.

    scenarios x conditions x models x samples

Every cell is generate -> extract -> evaluate, and each stage writes to disk
before the next begins. The run is RESUMABLE: a cell whose results JSON
already exists is skipped, so an interrupted batch picks up where it stopped
rather than starting over. This matters because generation is not
deterministic - regenerating a manifest gives a different manifest, so a
restart from scratch would silently replace data you had already analysed.

Nothing is ever deleted. There is deliberately no reset step here, unlike
run_pilot.sh.

Usage:
    python3 scripts/run_batch.py --plan              # what would run, no calls
    python3 scripts/run_batch.py                     # the full matrix
    python3 scripts/run_batch.py --scenarios S01 S02 --samples 1
    python3 scripts/run_batch.py --models M1 --conditions P0 P2
    python3 scripts/run_batch.py --retry-failed      # redo cells with no result
"""
import argparse
import datetime
import json
import pathlib
import re
import subprocess
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUNS = ROOT / "runs"
RESULTS = ROOT / "results"
PROMPTS = ROOT / "prompts"
LOG = ROOT / "batch_log.jsonl"

PY = sys.executable
SCENARIOS = [f"S{i:02d}" for i in range(1, 21)]
CONDITIONS = ["P0", "P1", "P2", "P3"]
MODELS = ["M1"]                     # add "M2", "M3" once they are in generate.py
SAMPLES = 3


def gen_id(s, c, m, r):
    return f"{s}_{c}_{m}_r{r}"


def done(gid):
    return (RESULTS / f"{gid}.json").exists()


def has_manifest(gid):
    p = RUNS / gid / "manifest.yaml"
    return p.exists() and p.stat().st_size > 0


def run(cmd, timeout=None):
    """Run a stage. Returns (ok, combined_output)."""
    try:
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True,
                           timeout=timeout)
    except subprocess.TimeoutExpired:
        return False, f"timed out after {timeout}s"
    out = (r.stdout or "") + (r.stderr or "")
    return r.returncode == 0, out.strip()


def log(record):
    record["at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with LOG.open("a") as f:
        f.write(json.dumps(record) + "\n")


def hms(seconds):
    seconds = int(seconds)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    return f"{h}h{m:02d}m" if h else f"{m}m{s:02d}s"


QUOTA_MARKERS = ("RESOURCE_EXHAUSTED", "quotaValue", "429", "rate limit")


def retry_delay(text, default=30):
    """Seconds the API asked us to wait, from its RetryInfo block."""
    m = re.search(r"'retryDelay':\s*'(\d+)s'", text)
    return int(m.group(1)) + 2 if m else default


def is_quota(text):
    return any(k in text for k in QUOTA_MARKERS)


def generate_with_retry(s, c, m, sample=1, tries=5):
    """
    Call generate.py, waiting out quota errors rather than charging through.

    The free tier allows a fixed number of requests per minute. A failed call
    still counts against that window, so retrying immediately keeps the quota
    exhausted - the batch burns through every remaining cell in minutes and
    produces nothing. Sleeping for the delay the server names lets the window
    reset before the next attempt.
    """
    for attempt in range(1, tries + 1):
        ok, out = run([PY, "scripts/generate.py", "--scenario", s,
                       "--condition", c, "--model", m, "--samples", "1",
                       "--sample-start", str(sample)])
        if ok:
            return True, out
        if not is_quota(out):
            return False, out
        if attempt == tries:
            return False, out
        wait = retry_delay(out)
        print(f"        quota reached, waiting {wait}s "
              f"(attempt {attempt}/{tries})", flush=True)
        time.sleep(wait)
    return False, "exhausted retries"


def cells(a):
    for s in a.scenarios:
        for c in a.conditions:
            for m in a.models:
                for r in range(1, a.samples + 1):
                    yield s, c, m, r


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--scenarios", nargs="+", default=SCENARIOS)
    ap.add_argument("--conditions", nargs="+", default=CONDITIONS)
    ap.add_argument("--models", nargs="+", default=MODELS)
    ap.add_argument("--samples", type=int, default=SAMPLES)
    ap.add_argument("--plan", action="store_true",
                    help="report what would run and stop")
    ap.add_argument("--retry-failed", action="store_true",
                    help="also redo cells that produced no result last time")
    ap.add_argument("--pace", type=float, default=4.0,
                    help="seconds to wait between generate calls")
    ap.add_argument("--eval-timeout", type=int, default=600,
                    help="seconds before an evaluation is abandoned")
    a = ap.parse_args()

    all_cells = list(cells(a))
    todo = [c for c in all_cells if not done(gen_id(*c))]
    total, remaining = len(all_cells), len(todo)

    print(f"matrix: {len(a.scenarios)} scenarios x {len(a.conditions)} "
          f"conditions x {len(a.models)} models x {a.samples} samples "
          f"= {total} cells")
    print(f"already complete: {total - remaining}")
    print(f"to run:           {remaining}")

    missing_prompts = sorted({f"{s}_{c}" for s, c, _, _ in todo
                              if not (PROMPTS / f"{s}_{c}.txt").exists()})
    if missing_prompts:
        print(f"\nMISSING PROMPT FILES ({len(missing_prompts)}):")
        print("  " + ", ".join(missing_prompts[:12])
              + (" ..." if len(missing_prompts) > 12 else ""))
        sys.exit("\nrun build_prompts.py first")

    if a.plan:
        # K4 has a 180s budget, so a cell that fails readiness is the slow case
        print(f"\nrough time: {hms(remaining * 25)} if everything is healthy, "
              f"up to {hms(remaining * 200)} if many fail K4")
        return

    if not remaining:
        print("\nnothing to do - every cell already has a result")
        return

    started = time.time()
    counts = {"clean": 0, "misconfigured": 0, "invalid": 0, "error": 0}

    for i, (s, c, m, r) in enumerate(todo, start=1):
        gid = gen_id(s, c, m, r)
        t0 = time.time()
        prefix = f"[{i}/{remaining}] {gid}"

        # ---- generate (skipped if the manifest is already extracted) ----
        if not has_manifest(gid):
            ok, out = generate_with_retry(s, c, m, sample=r)
            if not ok:
                print(f"{prefix}  GENERATE FAILED  {out[-120:]}")
                log({"gen_id": gid, "stage": "generate", "ok": False,
                     "output": out[-500:]})
                counts["error"] += 1
                if is_quota(out):
                    print("\nquota still exhausted after retries - stopping "
                          "so the rest of the matrix is not burned through.\n"
                          "re-run the same command later to continue.")
                    break
                continue

            ok, out = run([PY, "scripts/extract.py", "--gen", gid])
            if not ok and "unrecognized arguments" in out:
                # older extract.py only supports --all
                ok, out = run([PY, "scripts/extract.py", "--all"])
            if not ok:
                print(f"{prefix}  EXTRACT FAILED  {out[-120:]}")
                log({"gen_id": gid, "stage": "extract", "ok": False,
                     "output": out[-500:]})
                counts["error"] += 1
                continue

        # ---- evaluate ---------------------------------------------------
        ok, out = run([PY, "scripts/evaluate.py", "--gen", gid],
                      timeout=a.eval_timeout)
        if not ok or not done(gid):
            print(f"{prefix}  EVALUATE FAILED  {out[-120:]}")
            log({"gen_id": gid, "stage": "evaluate", "ok": False,
                 "output": out[-500:]})
            counts["error"] += 1
            continue

        if a.pace:
            time.sleep(a.pace)
        rec = json.loads((RESULTS / f"{gid}.json").read_text())
        klass = rec.get("classification", "?")
        counts[klass.lower()] = counts.get(klass.lower(), 0) + 1
        took = time.time() - t0

        elapsed = time.time() - started
        eta = (elapsed / i) * (remaining - i)
        print(f"{prefix}  {klass:14} {hms(took):>7}   eta {hms(eta)}")
        log({"gen_id": gid, "stage": "done", "ok": True,
             "classification": klass, "seconds": round(took, 1)})

    # ---- summary --------------------------------------------------------
    ran = sum(counts.values())
    print(f"\nran {ran} cell(s) in {hms(time.time() - started)}")
    for k in ("clean", "misconfigured", "invalid", "error"):
        if counts.get(k):
            print(f"  {k:14} {counts[k]}")

    scored = counts.get("clean", 0) + counts.get("misconfigured", 0) + \
        counts.get("invalid", 0)
    if scored:
        # SDR keeps INVALID in the denominator: failing to produce valid YAML
        # is itself a result, not a sample to discard
        print(f"\nSDR this session: {counts.get('clean', 0)}/{scored} = "
              f"{100 * counts.get('clean', 0) / scored:.1f}%")
    print(f"\nlog: {LOG.name}")
    print("re-run the same command to retry anything that errored")


if __name__ == "__main__":
    main()