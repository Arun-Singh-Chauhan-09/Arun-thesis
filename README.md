# LLM-Generated Kubernetes Manifest Benchmark

Empirical benchmark measuring whether LLM-generated Kubernetes manifests are both
**deployable** and **secure**. Supporting code for the MEng thesis *Security and
Deployability of LLM-Generated Kubernetes Manifests: An Empirical Benchmark Study*.

Every generated manifest is validated, deployed to a live `kind` cluster, probed for
its intended behaviour, and scanned by three security scanners. It is then classified
as `INVALID`, `MISCONFIGURED`, or `CLEAN`. The headline metric is the **Secure
Deployment Rate (SDR)** — the share of generations that pass all six checks.

---

## What the study found

From 720 generations (three models × four prompting conditions × 20 scenarios × three
samples):

- **27.6%** were `CLEAN`, **63.6%** `MISCONFIGURED`, **8.8%** `INVALID`.
- SDR by model: Llama 3.3 70B **22.9%**, DeepSeek Chat **24.2%**, Claude Sonnet 5 **35.8%**.
- A reference example only helps when it is itself hardened: the pooled clean rate moves
  from **15.6%** (no example) to **16.7%** (unhardened example), then jumps to **31.7%**
  (one hardened example) and **46.7%** (two hardened examples).

Deployability and security are separate axes: most failures happen *after* the syntax
and schema gates — at readiness (K4) and security (K6), not at K1/K2.

---

## Experimental design

| Dimension | Values | Count |
|---|---|---|
| Scenarios | S01 – S20 (workload / batch / policy families) | 20 |
| Prompting conditions | P0 Zero-Shot, P1 Non-Plausible, P2 Plausible, P3 Plausible Pair | 4 |
| Models | M1, M2, M3 | 3 |
| Samples per cell | independent generations, temperature 1.0 | 3 |
| **Total manifests** | 20 × 4 × 3 × 3 | **720** |

**Prompting conditions** differ only in the reference example supplied with the prompt:

| Condition | Reference example supplied |
|---|---|
| P0 — Zero-Shot | none (task and output rules only) |
| P1 — Non-Plausible | one *unhardened* example |
| P2 — Plausible | one *hardened* example |
| P3 — Plausible Pair | two *hardened* examples |

**Models** are each called through an OpenAI-compatible chat-completions endpoint, so
only the model identifier, base URL, and credential differ:

| Label | Model | Provider |
|---|---|---|
| M1 | Llama 3.3 70B Instruct Turbo | Together AI |
| M2 | DeepSeek Chat | DeepSeek |
| M3 | Claude Sonnet 5 | Anthropic |

`INVALID` generations stay in the SDR denominator — failing to produce valid YAML is
itself a meaningful result.

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

**1. Model credentials.** The three providers are configured in the `MODELS` block at
the top of `scripts/generate.py` (model ID, base URL, and the environment variable each
key is read from). Export the key for every provider you intend to run — never commit
them (`.gitignore` already excludes `.env` and `*.key`):

```bash
export TOGETHER_API_KEY="your-together-key"     # M1  (Llama 3.3 70B)
export DEEPSEEK_API_KEY="your-deepseek-key"     # M2  (DeepSeek Chat)
export ANTHROPIC_API_KEY="your-anthropic-key"   # M3  (Claude Sonnet 5)
```

> The exact variable names above are whatever `scripts/generate.py` reads — check the
> `MODELS` block and set them to match. Persist keys across terminals by appending the
> `export` lines to `~/.bashrc` and running `source ~/.bashrc`.

**2. Cluster.** Pin the node image to the version named in the methodology. Running
`kind create cluster` without `--image` yields whatever the installed kind binary
defaults to, which will not match the thesis target (v1.31.0).

```bash
kind create cluster --name llm-k8s-bench --image kindest/node:v1.31.0
kubectl --context kind-llm-k8s-bench get nodes    # expect v1.31.0, STATUS Ready
```

**3. Docker must be running.** On WSL2 with Docker Desktop, enable WSL integration for
the distro. With native Docker Engine: `sudo service docker start`.

---

## How the pipeline works

Each generation flows through five stages; `run_batch.py` orchestrates them across every
cell of the design.

```
build_prompts.py  →  generate.py  →  extract.py  →  evaluate.py  →  report.py
   prompts/           runs/<id>/       runs/<id>/     results/<id>     report.xlsx
   (corpus)           response,        manifest.yaml  .json            + figures/
                      generation.json                 (K1–K6 verdict)
```

1. **`build_prompts.py`** assembles the prompt corpus in `prompts/` — each scenario
   paired with a prompting condition and, for the example-bearing conditions, a
   family-matched reference manifest.
2. **`generate.py`** sends each prompt to each model (temperature 1.0, three samples)
   and writes the raw response to `runs/<id>/`.
3. **`extract.py`** recovers the fenced YAML from each response verbatim into
   `runs/<id>/manifest.yaml`.
4. **`evaluate.py`** runs the K1–K6 ladder against a live cluster, classifies the
   generation, and tears the namespace down — writing the verdict to `results/<id>.json`.
5. **`report.py`** aggregates every result into `report.xlsx` and renders the figures
   into `figures/`.

### Full study

```bash
python3 scripts/run_batch.py                 # generate + evaluate all 720 cells (hours)
python3 scripts/report.py --all              # build report.xlsx + figures/
```

`report.py` flags: `--excel report.xlsx` (workbook only), `--charts figures/` (PNGs
only), `--all` (both, plus a printed text summary), `--model M3 --condition P2` (filter).

### Single-cell smoke test

```bash
bash run_pilot.sh
```

Runs prechecks → cluster → reset → generate → extract → evaluate → workbook for one cell
and writes `KPI_result.xlsx`. Handy for verifying the toolchain before a long batch.

### Individual stages

```bash
python3 scripts/generate.py --scenario S01 --condition P0 --model M1 --samples 1
python3 scripts/extract.py  --all
python3 scripts/evaluate.py --all
python3 scripts/report.py   --all
```

Watch pods deploy in a second terminal — they are torn down within ~20 seconds, so log
the output rather than trying to read it live:

```bash
kubectl --context kind-llm-k8s-bench get pods -A -w | tee pod_lifecycle.log
```

---

## The K1–K6 ladder

| KPI | Question | Decided by | On failure |
|---|---|---|---|
| K1 | Is it parseable YAML? | PyYAML | `INVALID`, stop |
| K2 | Is it a valid Kubernetes object? | kubeconform, v1.31 schema | `INVALID`, stop |
| K3 | Does the cluster accept it? | `kubectl apply` | `MISCONFIGURED`, continue |
| K4 | Does it become ready? | `kubectl wait`, 180 s budget | `MISCONFIGURED`, continue |
| K5 | Does it do what was asked? | per-scenario intent probe | `MISCONFIGURED`, continue |
| K6 | Free of serious security faults? | Checkov + Trivy + kube-linter | `MISCONFIGURED` |

**K4 vacuity rule.** Manifests that create no Pods (RBAC-only, for example) have nothing
for `kubectl wait` to observe. K4 is recorded as `N/A` and treated as a pass. K5 is
`N/A` where no scenario probe is defined.

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
cannot trip K6, so **a gap in the register can let a serious fault pass silently.** Check
for unmapped findings before any large batch:

```bash
python3 -c "
import json,glob
for f in glob.glob('results/*.json'):
    for x in json.load(open(f)).get('findings',[]):
        if x['severity']=='UNMAPPED': print(f, x['rule_id'])
"
```

---

## Harness validation (mutation testing)

Before trusting the ladder, `scripts/mutation_test.py` seeds six controlled faults into a
known-clean manifest and checks that each is caught at the rung the design predicts
(five defects M-01…M-05, plus M-06 which adds full hardening and must reach `CLEAN`).
Its outputs live under `runs/…_MUT-M-0x`. Run it standalone:

```bash
python3 scripts/mutation_test.py
```

Nothing imports this script — it is a validation entry point you run by hand, and it
underpins the thesis's Harness Validation section, so keep it in the repo.

---

## Project structure

```
.
├── run_pilot.sh              single-cell pilot runner → KPI_result.xlsx
├── severity_register.csv     rule_id → canonical fault + severity
├── report.xlsx               aggregated results workbook (per-manifest grid + summaries)
├── prompts/                  scenario definitions + assembled prompts
├── examples/                 reference manifests (hardened / unhardened, per family)
├── figures/                  charts rendered by report.py
├── scripts/
│   ├── build_prompts.py      assembles the prompt corpus
│   ├── generate.py           calls each model, writes the raw response
│   ├── extract.py            recovers YAML from the response
│   ├── evaluate.py           K1–K6 ladder, classification, teardown
│   ├── report.py             aggregates results → report.xlsx + figures/
│   ├── analyse.py            aggregate statistics for the research questions
│   ├── make_yaml_sheet.py    single-cell KPI sheet (used by run_pilot.sh)
│   ├── mutation_test.py      harness validation (six seeded faults)
│   └── run_batch.py          orchestrates generate→evaluate across all cells
├── runs/<id>/                response, generation.json, manifest.yaml, extraction.json
└── results/<id>.json         K1–K6 verdicts, findings, classification
```

Run IDs follow `<scenario>_<condition>_<model>_r<sample>`, e.g. `S01_P0_M1_r1`. Each
evaluation gets its own namespace, `eval-s01-p0-m1-r1`, deleted at teardown.

---

## Reproducing from scratch vs. resuming

Generation is non-deterministic (temperature 1.0), so a re-run produces a *new* corpus
with the same statistical character, not identical manifests. `run_pilot.sh` contains a
reset step that is correct for repeated single-cell testing but destructive for a batch:

```bash
rm -rf runs/* results/*
```

For the full batch, `run_batch.py` instead creates the directories if missing and skips
cells whose output already exists, so an interrupted run can resume. Provider rate limits
apply, so the generator waits between calls — a full 720-manifest run takes hours.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `set <PROVIDER>_API_KEY first` | New terminal. Re-export the provider key, or add it to `~/.bashrc`. |
| `failed to connect to the docker API` | Docker not running. Start Docker Desktop or `sudo service docker start`. |
| Node stuck `NotReady` | CNI still starting. Wait ~30 s, or `kubectl wait --for=condition=Ready node --all`. |
| Cluster reports v1.29 not v1.31 | Created without `--image`. Delete and recreate with the pinned node image. |
| `report.xlsx is open in Excel` | Close the workbook. Excel's `~$` lock blocks the write. |
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

---

## Citation

If you use this benchmark or its data, please cite the thesis:

> A. S. Chauhan, *Security and Deployability of LLM-Generated Kubernetes Manifests: An
> Empirical Benchmark Study*, MEng thesis, Gisma University of Applied Sciences, 2026.