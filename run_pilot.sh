#!/usr/bin/env bash
# S01 / P0 / M1 pilot - end to end.
# Generates ONE manifest with Gemini (M1), runs the K1..K6 ladder,
# and writes the per-KPI Excel sheet.
set -euo pipefail

CLUSTER=llm-k8s-bench
NODE_IMAGE=kindest/node:v1.31.0     # pinned: thesis targets Kubernetes v1.31
SCENARIO=S01
CONDITION=P0
MODEL=M1
SAMPLES=1
OUT=KPI_result.xlsx

command -v kind        >/dev/null || { echo "kind not installed"; exit 1; }
command -v kubectl     >/dev/null || { echo "kubectl not installed"; exit 1; }
command -v kubeconform >/dev/null || { echo "kubeconform not installed"; exit 1; }
command -v checkov     >/dev/null || { echo "checkov not installed"; exit 1; }
command -v trivy       >/dev/null || { echo "trivy not installed"; exit 1; }
command -v kube-linter >/dev/null || { echo "kube-linter not installed"; exit 1; }
: "${GEMINI_API_KEY:?set GEMINI_API_KEY first}"

# Docker must be up before kind can do anything.
docker info >/dev/null 2>&1 || {
  echo "Docker is not reachable. Start Docker Desktop (with WSL integration)"
  echo "or run: sudo service docker start"
  exit 1
}

# Excel keeps a ~$ lock file open; the workbook write would fail at the last step.
if [ -e "~\$${OUT}" ]; then
  echo "${OUT} is open in Excel. Close it and re-run."
  exit 1
fi

echo "== cluster =="
if kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  echo "reusing existing cluster '$CLUSTER'"
else
  kind create cluster --name "$CLUSTER" --image "$NODE_IMAGE"
fi
kubectl cluster-info --context "kind-$CLUSTER" >/dev/null
kubectl --context "kind-$CLUSTER" wait --for=condition=Ready node --all --timeout=120s >/dev/null
kubectl --context "kind-$CLUSTER" get nodes --no-headers

echo "== reset =="
# Start clean so exactly one generation is present, not last run's leftovers.
#rm -rf runs/* results/*
mkdir -p runs results

echo "== generate =="
python3 scripts/generate.py --scenario "$SCENARIO" --condition "$CONDITION" \
                            --model "$MODEL" --samples "$SAMPLES"

echo "== extract =="
python3 scripts/extract.py --all

echo "== evaluate =="
python3 scripts/evaluate.py --all

echo "== workbook =="
python3 scripts/make_yaml_sheet.py -o "$OUT"

echo
echo "Done. Open $OUT   (sheet YAML1: KPI1-KPI6, Passed/Failed, Summary)"
echo "Manifest: runs/${SCENARIO}_${CONDITION}_${MODEL}_r1/manifest.yaml"
echo "Cluster '$CLUSTER' left running. Remove with: kind delete cluster --name $CLUSTER"
