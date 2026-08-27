#!/usr/bin/env python3
"""
Write the batch and policy reference examples.

These four manifests are author-written, not sourced. Stack Overflow answers
for these resource types are predominantly troubleshooting fragments rather
than complete manifests, and the Kubernetes documentation examples do not
carry a full hardening posture in any single manifest. Rather than misattribute
a constructed manifest to a source it did not come from, each .meta written
here records author: this project explicitly, so the corpus stays auditable.

The workload family is NOT touched: workload_p1 and workload_p2 are sourced
from the Kubernetes documentation and should stay that way. All three P3 slots
are left alone as well - build_prompts.py composes them from P1 + P2.

Usage:
    python3 scripts/write_fallback_examples.py            # write missing only
    python3 scripts/write_fallback_examples.py --force    # overwrite existing
"""
import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXDIR = ROOT / "examples"

# The hardening posture below matches what the K6 scanners actually check:
# securityContext at pod AND container level (Checkov CKV_K8S_29, Trivy
# KSV-0118), runAsNonRoot, allowPrivilegeEscalation false, capabilities
# dropped to ALL, and resource requests and limits.

BATCH_P1 = """apiVersion: batch/v1
kind: CronJob
metadata:
  name: hello
spec:
  schedule: "* * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: hello
            image: busybox:1.28
            command:
            - /bin/sh
            - -c
            - date; echo Hello from the Kubernetes cluster
          restartPolicy: OnFailure
"""

BATCH_P2 = """apiVersion: batch/v1
kind: Job
metadata:
  name: hardened-task
spec:
  backoffLimit: 2
  template:
    metadata:
      labels:
        app: hardened-task
    spec:
      restartPolicy: OnFailure
      automountServiceAccountToken: false
      securityContext:
        runAsNonRoot: true
        runAsUser: 10001
        runAsGroup: 10001
        fsGroup: 10001
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: task
        image: busybox:1.36
        imagePullPolicy: Always
        command: ["sh", "-c", "echo working; sleep 1"]
        securityContext:
          runAsNonRoot: true
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
          seccompProfile:
            type: RuntimeDefault
        resources:
          requests:
            cpu: "50m"
            memory: "64Mi"
          limits:
            cpu: "200m"
            memory: "128Mi"
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
"""

# For the policy family, "unhardened" means broad permissions rather than a
# missing securityContext: these manifests create no Pods.
POLICY_P1 = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: app-account
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: app-role-binding
subjects:
- kind: ServiceAccount
  name: app-account
roleRef:
  kind: Role
  name: app-role
  apiGroup: rbac.authorization.k8s.io
"""

POLICY_P2 = """apiVersion: v1
kind: ServiceAccount
metadata:
  name: pod-reader
automountServiceAccountToken: false
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
rules:
- apiGroups: [""]
  resources: ["pods", "pods/log"]
  verbs: ["get", "list", "watch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: pod-reader
subjects:
- kind: ServiceAccount
  name: pod-reader
roleRef:
  kind: Role
  name: pod-reader
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
spec:
  podSelector: {}
  policyTypes:
  - Ingress
"""

NOTE_COMMON = ("author-written for this study, not sourced. Stack Overflow "
               "answers for this resource type are predominantly "
               "troubleshooting fragments rather than complete manifests")

EXAMPLES = {
    "batch_p1": (
        BATCH_P1,
        {"title": "Unhardened CronJob, minimal fields only",
         "author": "this project",
         "license": "n/a - author-written",
         "note": NOTE_COMMON + "; shape follows the CronJob example in the "
                 "Kubernetes documentation"},
    ),
    "batch_p2": (
        BATCH_P2,
        {"title": "Hardened Job with full security posture",
         "author": "this project",
         "license": "n/a - author-written",
         "note": NOTE_COMMON + "; carries securityContext at pod and "
                 "container level, dropped capabilities and resource limits"},
    ),
    "policy_p1": (
        POLICY_P1,
        {"title": "Permissive RBAC granting wildcard verbs and resources",
         "author": "this project",
         "license": "n/a - author-written",
         "note": NOTE_COMMON + "; for the policy family 'unhardened' means "
                 "broad permissions, since these manifests create no Pods"},
    ),
    "policy_p2": (
        POLICY_P2,
        {"title": "Least-privilege RBAC with a default-deny NetworkPolicy",
         "author": "this project",
         "license": "n/a - author-written",
         "note": NOTE_COMMON + "; narrow verbs and resources, service account "
                 "token not mounted, ingress denied by default"},
    ),
}

META_ORDER = ["title", "url", "author", "score", "license", "note"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true",
                    help="overwrite slots that already have content")
    a = ap.parse_args()

    if not EXDIR.is_dir():
        sys.exit(f"{EXDIR} not found - run build_prompts.py --init first")

    wrote, skipped = 0, []
    for stem, (manifest, meta) in EXAMPLES.items():
        y = EXDIR / f"{stem}.yaml"
        existing = ""
        if y.exists():
            existing = "\n".join(
                l for l in y.read_text().splitlines()
                if not l.strip().startswith("#")).strip()
        if existing and not a.force:
            skipped.append(stem)
            continue

        y.write_text(manifest)
        (EXDIR / f"{stem}.meta").write_text(
            "\n".join(f"{k}: {meta[k]}" for k in META_ORDER if meta.get(k))
            + "\n")
        print(f"wrote examples/{stem}.yaml + .meta  (author-written)")
        wrote += 1

    if skipped:
        print(f"\nleft alone (already filled): {', '.join(skipped)}")
        print("use --force to overwrite")

    print(f"\n{wrote} slot(s) written. The workload family and all P3 slots "
          f"are untouched.")
    print("Next:")
    print("  python3 scripts/build_prompts.py --check")


if __name__ == "__main__":
    main()