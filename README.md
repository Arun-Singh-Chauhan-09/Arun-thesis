# LLM-Generated Kubernetes Manifest Benchmark

Empirical benchmark measuring whether LLM-generated Kubernetes manifests are both
**deployable** and **secure**. Supporting code for the MEng thesis *Security and
Deployability of LLM-Generated Kubernetes Manifests: An Empirical Benchmark Study*.

Each generated manifest is validated, deployed to a live `kind` cluster, probed for
intended behaviour, and scanned by three security scanners. It is then classified as
`INVALID`, `MISCONFIGURED`, or `CLEAN`.

---

## Experimental design

| Dimension | Values | Count |
|---|---|---|
| Scenarios | S01 – S20 | 20 |
| Prompting conditions | P0 zero-shot, P1 one-shot, P2 two-shot, P4 four-shot | 4 |
| Models | M1, M2, M3 | 3 |
| Samples per cell | independent generations | 3 |
| **Total manifests** | 20 × 4 × 3 × 3 | **720** |

Primary outcome is the **Secure Deployment Rate (SDR)**: manifests classified `CLEAN`
divided by all generations attempted. `INVALID` generations stay in the denominator —
failing to produce valid YAML is itself a meaningful result.

---

## Requirements

Six CLI tools must be on `PATH`:

| Tool | Used for |
|---|---|
| `kind` | local Kubernetes cluster |
| `kubectl` | apply, wait, teardown |
| `kubeconform` | K2 schema validation |
| `checkov` | K6 security scanning |
| `trivy` | K6 security scanning |
| `kube-linter` | K6 security scanning |

Plus Python 3, Docker (running), and the `openai` and `openpyxl` Python packages.

```bash
pip install openai openpyxl
```

---

## Setup

**1. API key.** The generator reads it from the environment — never commit it.

```bash
export GEMINI_API_KEY="your-key-here"
```

Persist it across terminals:

```bash
echo 'export GEMINI_API_KEY="your-key-here"' >> ~/.bashrc && source ~/.bashrc
```

**2. Cluster.** Pin the node image to the version named in the methodology. Running
`kind create cluster` without `--image` yields whatever the installed kind binary
defaults to, which will not match the thesis target.

```bash
kind create cluster --name llm-k8s-bench --image kindest/node:v1.31.0
kubectl --context kind-llm-k8s-bench get nodes    # expect v1.31.0, STATUS Ready
```

**3. Docker must be running.** On WSL2 with Docker Desktop, enable WSL integration for
the distro. With native Docker Engine: `sudo service docker start`.

---

## Running

Single-cell pilot, end to end:

```bash
bash run_pilot.sh
```

This runs prechecks → cluster → reset → generate → extract → evaluate → workbook, and
writes `KPI_result.xlsx`.

Stages can also be run individually:

```bash
python3 scripts/generate.py --scenario S01 --condition P0 --model M1 --samples 1
python3 scripts/extract.py  --all
python3 scripts/evaluate.py --all
python3 scripts/make_yaml_sheet.py -o KPI_result.xlsx
```

Watch pods deploy in a second terminal — they are torn down within ~20 seconds, so
log the output rather than trying to read it live:

```bash
kubectl --context kind-llm-k8s-bench get pods -A -w | tee pod_lifecycle.log
```

---

## The KPI ladder

| KPI | Question | Decided by | On failure |
|---|---|---|---|
| K1 | Is it parseable YAML? | PyYAML | `INVALID`, stop |
| K2 | Is it a valid Kubernetes object? | kubeconform, v1.31 schema | `INVALID`, stop |
| K3 | Does the cluster accept it? | `kubectl apply` | `MISCONFIGURED`, continue |
| K4 | Does it become ready? | `kubectl wait`, 180 s budget | `MISCONFIGURED`, continue |
| K5 | Does it do what was asked? | per-scenario intent probe | `MISCONFIGURED`, continue |
| K6 | Free of serious security faults? | Checkov + Trivy + kube-linter | `MISCONFIGURED` |

**K4 vacuity rule.** Manifests that create no Pods (RBAC-only, for example) have
nothing for `kubectl wait` to observe. K4 is recorded as `N/A` and treated as a pass.

**Outcome classes**

- `INVALID` — fails K1 or K2. Deployment is not attempted.
- `MISCONFIGURED` — passes K1–K2, fails any of K3–K6.
- `CLEAN` — passes K1–K6, with zero HIGH/CRITICAL faults after normalisation.

---

## K6 and the severity register

Each scanner finding is mapped through `severity_register.csv` to a **canonical fault**
with a project-assigned severity. K6 fails if any canonical fault is `HIGH` or
`CRITICAL`, from any scanner (union semantics).

```csv
scanner,rule_id,canonical_fault,severity,cis_reference,note
trivy,KSV-0001,allow_privilege_escalation,HIGH,CIS 5.2.5,Privilege escalation allowed
```

The register serves two purposes:

1. **Severity control** — the project decides what counts as serious, not the scanner.
   Scanners disagree; the register is the single source of truth.
2. **Cross-scanner deduplication** — one authoring mistake found by three scanners maps
   to one canonical fault and is counted once. Without this, the RQ3 fault distribution
   would be weighted by scanner redundancy rather than by model behaviour.

Findings whose `rule_id` is absent from the register are recorded as `UNMAPPED`. They
cannot trip K6, so **a gap in the register can let a serious fault pass silently.**
Check for unmapped findings before any large batch:

```bash
python3 -c "
import json,glob
for f in glob.glob('results/*.json'):
    for x in json.load(open(f)).get('findings',[]):
        if x['severity']=='UNMAPPED': print(f, x['rule_id'])
"
```

---

## Project structure

```
.
├── run_pilot.sh              single-cell pilot runner
├── severity_register.csv     rule_id → canonical fault + severity
├── prompts/                  scenario definitions, reference examples
├── scripts/
│   ├── generate.py           calls the model, writes raw response
│   ├── extract.py            recovers YAML from the response
│   ├── evaluate.py           K1–K6 ladder, classification, teardown
│   ├── make_yaml_sheet.py    per-KPI Excel sheet
│   └── make_workbook.py      multi-run workbook
├── runs/<id>/                response.txt, generation.json,
│                             manifest.yaml, extraction.json
└── results/<id>.json         K1–K6 verdicts, findings, classification
```

Run IDs follow `<scenario>_<condition>_<model>_r<sample>`, e.g. `S01_P0_M1_r1`.
Each evaluation gets its own namespace, `eval-s01-p0-m1-r1`, deleted at teardown.

---

## Scaling to the full study

No structural change is needed — widen the loops and extend the registry.

```
--samples 1  →  --samples 3
scenario  S01  →  S01 .. S20
condition P0   →  P0, P1, P2, P4
model     M1   →  M1, M2, M3          (add to MODELS in generate.py)
```

**Remove the reset step first.** `run_pilot.sh` contains:

```bash
rm -rf runs/* results/*
```

That is correct for repeated single-cell testing but destructive for the full batch —
generation is non-deterministic, so regenerated manifests will not match the originals.
Use `mkdir -p runs results` in the batch runner instead, and skip cells whose output
directory already exists so an interrupted run can resume.

Free-tier rate limits apply (roughly 10 requests/minute), so the generator waits
between calls. A full 720-manifest run takes hours.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `set GEMINI_API_KEY first` | New terminal. Re-export, or add to `~/.bashrc`. |
| `failed to connect to the docker API` | Docker not running. Start Docker Desktop or `sudo service docker start`. |
| Node stuck `NotReady` | CNI still starting. Wait ~30 s, or `kubectl wait --for=condition=Ready node --all`. |
| Cluster reports v1.29 not v1.31 | Created without `--image`. Delete and recreate with the pinned node image. |
| `KPI_result.xlsx is open in Excel` | Close the workbook. Excel's `~$` lock blocks the write. |
| `sed: cannot rename ...: Permission denied` | `sed -i` fails on `/mnt/c` Windows drives. Use `sed ... > /tmp/f && cp /tmp/f target`. |
| Fault names appear as raw rule IDs | `severity_register.csv` key mismatch — the register ID must match exactly what the scanner emits. |
| Same fault counted several times | Deduplication key must be the canonical fault alone; per-scanner resource names never collide. |
| No pods visible after a run | Expected. Teardown deletes the namespace within ~20 s. Watch with `-w`, or deploy manually to inspect. |

---

## Inspecting a manifest manually

Teardown removes everything, so to examine a deployment at rest:

```bash
kubectl create namespace demo
kubectl -n demo apply -f runs/S01_P0_M1_r1/manifest.yaml
kubectl -n demo get pods -o wide
kubectl delete namespace demo
```

To see why K6 failed on a specific manifest:

```bash
trivy config --severity HIGH,CRITICAL runs/S01_P0_M1_r1/manifest.yaml
checkov -f runs/S01_P0_M1_r1/manifest.yaml --compact
```