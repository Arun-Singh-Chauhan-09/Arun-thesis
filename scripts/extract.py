#!/usr/bin/env python3
"""
Stage 3 - extraction and normalisation.

CONTRACT: this stage recovers the YAML the model produced. It never repairs it.
No indentation is fixed, no missing field is added, no invalid value is
corrected. If the extractor were allowed to repair, K1 and K2 would measure the
extractor rather than the model, and the INVALID rate would be meaningless.

Permitted operations:
  - strip surrounding prose
  - strip markdown code fences
  - normalise line endings and strip a BOM
  - record structural facts (document count, object kinds)

Namespace isolation is NOT done by editing the manifest. `kubectl apply -n`
supplies the namespace at apply time, so the file under test stays byte-identical
to what the model produced.

Usage:
    python3 scripts/extract.py --gen S01_P0_M1_r1
    python3 scripts/extract.py --all
"""
import argparse
import hashlib
import json
import pathlib
import re

import yaml

ROOT = pathlib.Path(__file__).resolve().parent.parent

FENCE = re.compile(r"```[ \t]*([A-Za-z0-9_+-]*)[ \t]*\r?\n(.*?)```", re.DOTALL)

# Kinds that are not namespaced. Recorded so teardown can delete them
# explicitly - a namespace delete will not remove them.
CLUSTER_SCOPED = {
    "ClusterRole", "ClusterRoleBinding", "PersistentVolume", "StorageClass",
    "Namespace", "CustomResourceDefinition", "ValidatingWebhookConfiguration",
    "MutatingWebhookConfiguration", "PriorityClass", "IngressClass",
    "APIService", "CSIDriver", "RuntimeClass",
}


def extract_yaml(text):
    """Return (yaml_text, extraction_method, n_blocks)."""
    text = text.replace("\ufeff", "").replace("\r\n", "\n")
    blocks = FENCE.findall(text)

    if blocks:
        # Rule: keep every fenced block whose language tag is yaml/yml or empty.
        # Concatenating as multi-document YAML preserves everything the model
        # emitted. Discarding later blocks would silently drop objects and
        # inflate the failure rate for K5.
        keep = [b for lang, b in blocks if lang.lower() in ("yaml", "yml", "")]
        if keep:
            joined = "\n---\n".join(b.strip("\n") for b in keep)
            return joined + "\n", "fenced", len(keep)
        return "", "fenced_but_no_yaml_block", len(blocks)

    # No fences. If the whole response parses as YAML, treat it as the manifest.
    stripped = text.strip()
    if stripped:
        try:
            docs = list(yaml.safe_load_all(stripped))
            if any(isinstance(d, dict) and "kind" in d for d in docs):
                return stripped + "\n", "bare", 0
        except yaml.YAMLError:
            pass
    return "", "no_yaml_found", 0


def process(rundir):
    text = (rundir / "response.txt").read_text()
    manifest, method, n_blocks = extract_yaml(text)
    (rundir / "manifest.yaml").write_text(manifest)

    kinds, cluster_scoped, n_docs, parse_ok, parse_error = [], [], 0, True, None
    if manifest:
        try:
            docs = [d for d in yaml.safe_load_all(manifest) if d is not None]
            n_docs = len(docs)
            for d in docs:
                if isinstance(d, dict):
                    k = d.get("kind")
                    if k:
                        kinds.append(k)
                        if k in CLUSTER_SCOPED:
                            name = (d.get("metadata") or {}).get("name")
                            cluster_scoped.append({"kind": k, "name": name})
        except yaml.YAMLError as e:
            # Not an error here. K1 is where this is judged and recorded.
            parse_ok, parse_error = False, str(e)[:400]
    else:
        parse_ok = False
        parse_error = f"extraction produced no YAML ({method})"

    record = {
        "generation_id": rundir.name,
        "extraction_method": method,
        "fenced_blocks_kept": n_blocks,
        "manifest_sha256": hashlib.sha256(manifest.encode()).hexdigest(),
        "manifest_bytes": len(manifest),
        "document_count": n_docs,
        "kinds": kinds,
        "cluster_scoped_objects": cluster_scoped,
        "parses": parse_ok,
        "parse_error": parse_error,
        "repaired": False,
    }
    (rundir / "extraction.json").write_text(json.dumps(record, indent=2))
    print(f"{rundir.name}  method={method}  docs={n_docs}  kinds={kinds or '-'}")
    return record


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--gen")
    p.add_argument("--all", action="store_true")
    a = p.parse_args()
    targets = (sorted(d for d in (ROOT / "runs").iterdir() if d.is_dir())
               if a.all else [ROOT / "runs" / a.gen])
    for t in targets:
        process(t)
