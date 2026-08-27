#!/usr/bin/env python3
"""
Stage 4 - KPI ladder K1..K6 and stage 5 - classification.

Ladder semantics follow the thesis:
  K1 parse            PyYAML                        fail -> INVALID, stop
  K2 schema           kubeconform (v1.31)           fail -> INVALID, stop
  K3 apply            kubectl apply, kind cluster   fail -> MISCONFIGURED, continue to K6
  K4 ready            kubectl wait, 180s budget     fail -> MISCONFIGURED, continue to K6
  K5 intent           per-scenario probe            fail -> MISCONFIGURED, continue to K6
  K6 security         Checkov + Trivy + kube-linter fail -> MISCONFIGURED

K4 vacuity rule: a manifest that creates no Pods records K4 = N/A, treated as a
pass for classification.

K6 union semantics: a HIGH or CRITICAL canonical fault from any one scanner is
sufficient to fail. Agreement is recorded but not required.

Usage:
    python3 scripts/evaluate.py --gen S01_P0_M1_r1 --keep-namespace
    python3 scripts/evaluate.py --all
"""
import argparse
import csv
import json
import pathlib
import subprocess
import time

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent
K8S_VERSION = "1.31.0"
READY_BUDGET = 180
SEVERITY_REGISTER = ROOT / "severity_register.csv"
FAIL_SEVERITIES = {"HIGH", "CRITICAL"}


def sh(cmd, timeout=300, **kw):
    return subprocess.run(cmd, capture_output=True, text=True,
                          timeout=timeout, **kw)


def load_register():
    reg = {}
    if SEVERITY_REGISTER.exists():
        with open(SEVERITY_REGISTER) as f:
            for row in csv.DictReader(f):
                reg[(row["scanner"], row["rule_id"])] = {
                    "canonical_fault": row["canonical_fault"],
                    "severity": row["severity"].upper(),
                }
    return reg


# --------------------------------------------------------------------------
# K1 / K2
# --------------------------------------------------------------------------
def k1_parse(manifest_path):
    text = manifest_path.read_text()
    if not text.strip():
        return False, "empty manifest - no YAML extracted from response"
    try:
        docs = [d for d in yaml.safe_load_all(text) if d is not None]
    except yaml.YAMLError as e:
        return False, f"YAML parse error: {str(e)[:300]}"
    if not docs:
        return False, "parsed but contains no documents"
    for i, d in enumerate(docs):
        if not isinstance(d, dict):
            return False, f"document {i} is not a mapping"
    return True, f"{len(docs)} document(s) parsed"


def k2_schema(manifest_path):
    r = sh(["kubeconform", "-strict", "-summary", "-output", "json",
            "-kubernetes-version", K8S_VERSION, str(manifest_path)])
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return False, f"kubeconform produced no JSON: {r.stderr[:200]}"
    bad = [x for x in data.get("resources", [])
           if x.get("status") in ("statusInvalid", "statusError")]
    if bad:
        msgs = "; ".join(f"{x.get('kind')}: {x.get('msg', '')[:120]}" for x in bad[:3])
        return False, msgs
    return True, f"{data.get('summary', {}).get('valid', 0)} resource(s) valid"


# --------------------------------------------------------------------------
# K3 / K4
# --------------------------------------------------------------------------
def k3_apply(manifest_path, ns):
    sh(["kubectl", "create", "namespace", ns])
    r = sh(["kubectl", "apply", "-n", ns, "-f", str(manifest_path)])
    if r.returncode != 0:
        return False, r.stderr.strip()[:400]
    return True, r.stdout.strip()[:300]


def k4_ready(ns):
    r = sh(["kubectl", "get", "pods", "-n", ns, "-o", "json"])
    pods = json.loads(r.stdout).get("items", []) if r.returncode == 0 else []
    if not pods:
        # Give controllers a moment before declaring the manifest pod-less.
        time.sleep(10)
        r = sh(["kubectl", "get", "pods", "-n", ns, "-o", "json"])
        pods = json.loads(r.stdout).get("items", []) if r.returncode == 0 else []
    if not pods:
        return "N/A", "manifest creates no Pods - vacuity rule applied"
    r = sh(["kubectl", "wait", "--for=condition=Ready", "pod", "--all",
            "-n", ns, f"--timeout={READY_BUDGET}s"], timeout=READY_BUDGET + 60)
    if r.returncode != 0:
        r2 = sh(["kubectl", "get", "pods", "-n", ns, "-o",
                 "jsonpath={range .items[*]}{.metadata.name}={.status.phase} {end}"])
        return False, f"not ready in {READY_BUDGET}s: {r2.stdout.strip()[:300]}"
    return True, f"all pods ready within {READY_BUDGET}s"


# --------------------------------------------------------------------------
# K5 - intent probe for S01
# --------------------------------------------------------------------------
# S01: "Deploy a stateless web application with two replicas, reachable inside
# the cluster on port 80."
#
# Positive requirements : two replicas ready, a ClusterIP Service serving 80
#                         that actually answers.
# Negative requirement  : nothing beyond what was asked. External exposure
#                         (NodePort, LoadBalancer, Ingress) is more than the
#                         scenario requested and fails the "and no more" clause.
S01_ALLOWED_KINDS = {"Deployment", "Service", "ServiceAccount", "ConfigMap"}


def k5_intent_s01(manifest_path, ns):
    docs = [d for d in yaml.safe_load_all(manifest_path.read_text()) if d]
    kinds = [d.get("kind") for d in docs]
    problems = []

    extra = sorted(set(kinds) - S01_ALLOWED_KINDS)
    if extra:
        problems.append(f"unrequested object kinds: {', '.join(extra)}")

    deps = [d for d in docs if d.get("kind") == "Deployment"]
    if len(deps) != 1:
        problems.append(f"expected 1 Deployment, found {len(deps)}")
    else:
        spec_replicas = deps[0].get("spec", {}).get("replicas")
        if spec_replicas != 2:
            problems.append(f"spec.replicas is {spec_replicas}, expected 2")
        name = deps[0].get("metadata", {}).get("name")
        r = sh(["kubectl", "get", "deployment", name, "-n", ns, "-o",
                "jsonpath={.status.readyReplicas}"])
        ready = r.stdout.strip() or "0"
        if ready != "2":
            problems.append(f"readyReplicas is {ready}, expected 2")

    svcs = [d for d in docs if d.get("kind") == "Service"]
    if len(svcs) != 1:
        problems.append(f"expected 1 Service, found {len(svcs)}")
    else:
        svc = svcs[0]
        stype = svc.get("spec", {}).get("type", "ClusterIP")
        if stype != "ClusterIP":
            problems.append(f"Service type is {stype} - exposes beyond the cluster")
        ports = svc.get("spec", {}).get("ports", [])
        if not any(p.get("port") == 80 for p in ports):
            problems.append(f"no Service port 80 (found {[p.get('port') for p in ports]})")
        svc_name = svc.get("metadata", {}).get("name")
        probe = sh(["kubectl", "run", f"probe-{int(time.time())}", "-n", ns,
                    "--rm", "-i", "--restart=Never", "--image=curlimages/curl:8.10.1",
                    "--command", "--", "curl", "-s", "-o", "/dev/null",
                    "-w", "%{http_code}", "--max-time", "10",
                    f"http://{svc_name}.{ns}.svc.cluster.local:80/"],
                   timeout=180)
        code = probe.stdout.strip().splitlines()[0] if probe.stdout.strip() else ""
        if not code.startswith(("2", "3")):
            problems.append(f"in-cluster GET on port 80 returned '{code or 'no response'}'")

    if problems:
        return False, "; ".join(problems)
    return True, "2 replicas ready, ClusterIP:80 answers, no extra objects"


INTENT_PROBES = {"S01": k5_intent_s01}


# --------------------------------------------------------------------------
# K6
# --------------------------------------------------------------------------
def run_checkov(path, reg):
    out = []
    r = sh(["checkov", "-f", str(path), "--framework", "kubernetes",
            "-o", "json", "--compact", "--quiet"])
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return out, f"checkov produced no JSON: {r.stderr[:150]}"
    blocks = data if isinstance(data, list) else [data]
    for b in blocks:
        for f in b.get("results", {}).get("failed_checks", []):
            rid = f.get("check_id")
            m = reg.get(("checkov", rid))
            out.append({
                "scanner": "checkov", "rule_id": rid,
                "title": f.get("check_name"),
                "resource": f.get("resource"),
                "canonical_fault": m["canonical_fault"] if m else rid,
                "severity": m["severity"] if m else "UNMAPPED",
            })
    return out, None


def run_trivy(path, reg):
    out = []
    r = sh(["trivy", "config", "--quiet", "--format", "json", str(path)])
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return out, f"trivy produced no JSON: {r.stderr[:150]}"
    for res in data.get("Results", []):
        for m in res.get("Misconfigurations", []):
            rid = m.get("ID")
            mapped = reg.get(("trivy", rid))
            out.append({
                "scanner": "trivy", "rule_id": rid,
                "title": m.get("Title"),
                "resource": res.get("Target"),
                "canonical_fault": mapped["canonical_fault"] if mapped else rid,
                "severity": (mapped["severity"] if mapped
                             else m.get("Severity", "UNKNOWN").upper()),
            })
    return out, None


def run_kubelinter(path, reg):
    out = []
    r = sh(["kube-linter", "lint", "--format", "json", str(path)])
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError:
        return out, f"kube-linter produced no JSON: {r.stderr[:150]}"
    for rep in data.get("Reports") or []:
        rid = rep.get("Check")
        mapped = reg.get(("kube-linter", rid))
        obj = (rep.get("Object") or {}).get("K8sObject") or {}
        out.append({
            "scanner": "kube-linter", "rule_id": rid,
            "title": (rep.get("Diagnostic") or {}).get("Message"),
            "resource": f"{obj.get('GroupVersionKind', {}).get('Kind')}/{obj.get('Name')}",
            "canonical_fault": mapped["canonical_fault"] if mapped else rid,
            "severity": mapped["severity"] if mapped else "UNMAPPED",
        })
    return out, None


def k6_security(manifest_path):
    reg = load_register()
    findings, notes = [], []
    for fn in (run_checkov, run_trivy, run_kubelinter):
        f, err = fn(manifest_path, reg)
        findings.extend(f)
        if err:
            notes.append(err)

    # Deduplicate on canonical_fault alone so one authoring mistake
    # reported by three scanners counts once in the RQ3 distribution.
    dedup = {}
    for f in findings:
        key = f["canonical_fault"]
        if key not in dedup:
            dedup[key] = dict(f, scanners=[f["scanner"]])
        else:
            dedup[key]["scanners"].append(f["scanner"])
    canonical = list(dedup.values())

    blocking = [f for f in canonical if f["severity"] in FAIL_SEVERITIES]
    unmapped = [f for f in canonical if f["severity"] == "UNMAPPED"]
    if unmapped:
        notes.append(f"{len(unmapped)} finding(s) not in severity register")

    if blocking:
        top = "; ".join(f"{f['canonical_fault']} [{f['severity']}]"
                        for f in blocking[:4])
        extra = f" (+{len(blocking) - 4} more)" if len(blocking) > 4 else ""
        return False, top + extra, canonical, notes
    return True, f"0 HIGH/CRITICAL after dedup ({len(canonical)} total findings)", canonical, notes


# --------------------------------------------------------------------------
def teardown(ns, cluster_scoped):
    for obj in cluster_scoped:
        sh(["kubectl", "delete", obj["kind"].lower(), obj["name"], "--ignore-not-found"])
    sh(["kubectl", "delete", "namespace", ns, "--ignore-not-found", "--wait=false"])


def classify(k):
    if k["K1"] is False or k["K2"] is False:
        return "INVALID"
    for name in ("K3", "K4", "K5", "K6"):
        if k[name] is False:
            return "MISCONFIGURED"
    return "CLEAN"


def evaluate(gen_id, keep_ns=False):
    rundir = ROOT / "runs" / gen_id
    manifest = rundir / "manifest.yaml"
    extraction = json.loads((rundir / "extraction.json").read_text())
    scenario = gen_id.split("_")[0]
    ns = f"eval-{gen_id.lower().replace('_', '-')}"

    verdict = {k: None for k in ("K1", "K2", "K3", "K4", "K5", "K6")}
    detail = {k: "" for k in verdict}
    findings, notes = [], []

    verdict["K1"], detail["K1"] = k1_parse(manifest)
    if verdict["K1"]:
        verdict["K2"], detail["K2"] = k2_schema(manifest)

    if verdict["K1"] and verdict["K2"]:
        try:
            verdict["K3"], detail["K3"] = k3_apply(manifest, ns)
            if verdict["K3"]:
                verdict["K4"], detail["K4"] = k4_ready(ns)
                probe = INTENT_PROBES.get(scenario)
                if probe:
                    verdict["K5"], detail["K5"] = probe(manifest, ns)
                else:
                    verdict["K5"], detail["K5"] = "N/A", "no intent probe defined"
            else:
                detail["K4"] = detail["K5"] = "not attempted - K3 failed"
            verdict["K6"], detail["K6"], findings, notes = k6_security(manifest)
        finally:
            if not keep_ns:
                teardown(ns, extraction.get("cluster_scoped_objects", []))
    else:
        for name in ("K3", "K4", "K5", "K6"):
            detail[name] = "not attempted - INVALID at K1/K2"

    result = {
        "generation_id": gen_id,
        "scenario": scenario,
        "namespace": ns,
        "verdict": verdict,
        "detail": detail,
        "classification": classify(verdict),
        "findings": findings,
        "notes": notes,
        "evaluated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }
    out = ROOT / "results" / f"{gen_id}.json"
    out.write_text(json.dumps(result, indent=2))
    print(f"{gen_id}  {result['classification']}  " +
          "  ".join(f"{k}={verdict[k]}" for k in verdict))
    return result


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--gen")
    p.add_argument("--all", action="store_true")
    p.add_argument("--keep-namespace", action="store_true",
                   help="skip teardown so you can inspect the cluster")
    a = p.parse_args()
    ids = (sorted(d.name for d in (ROOT / "runs").iterdir() if d.is_dir())
           if a.all else [a.gen])
    for g in ids:
        evaluate(g, a.keep_namespace)
