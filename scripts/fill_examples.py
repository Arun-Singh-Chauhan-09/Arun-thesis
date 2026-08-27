#!/usr/bin/env python3
"""
Split one collected file into the nine examples/*.yaml + *.meta pairs.

Collect everything in one place while you browse Stack Overflow, then run this
once. It validates as it goes, so a bad paste is caught here rather than after
you have spent API calls on a broken corpus.

FORMAT of examples_input.txt
----------------------------
One block per slot. Metadata lines first, then a line containing only ---,
then the manifest. Blocks are separated by a line starting with ###.

    ### workload_p1
    url: https://stackoverflow.com/a/12345678
    title: How do I create a simple nginx deployment?
    author: Jane Doe
    score: 412
    note: trimmed trailing comments
    ---
    apiVersion: apps/v1
    kind: Deployment
    metadata:
      name: nginx
    ...

    ### workload_p2
    url: ...

The nine slot names are:
    workload_p1  workload_p2  workload_p3
    batch_p1     batch_p2     batch_p3
    policy_p1    policy_p2    policy_p3

You do not have to fill all nine in one pass - this script writes whichever
blocks are present and leaves the rest alone.

Usage:
    python3 scripts/fill_examples.py --template   # write a blank input file
    python3 scripts/fill_examples.py --dry-run    # parse and validate only
    python3 scripts/fill_examples.py              # write examples/
"""
import argparse
import pathlib
import re
import sys

try:
    import yaml
except ImportError:
    yaml = None

ROOT = pathlib.Path(__file__).resolve().parent.parent
EXDIR = ROOT / "examples"
DEFAULT_INPUT = ROOT / "examples_input.txt"

SLOTS = [
    "workload_p1", "workload_p2", "workload_p3",
    "batch_p1", "batch_p2", "batch_p3",
    "policy_p1", "policy_p2", "policy_p3",
]

WANTED = {
    "p1": "typical, widely-upvoted but UNHARDENED",
    "p2": "HARDENED - securityContext at pod AND container level, "
          "dropped capabilities, resource limits",
    "p3": "NEGATIVE example paired with its CORRECTION (paste both, "
          "separated by ---)",
}

FAMILY_WANTED = {
    "workload": "Deployment / StatefulSet / DaemonSet / Pod",
    "batch": "Job / CronJob",
    "policy": "RBAC / NetworkPolicy / ResourceQuota",
}

META_KEYS = ["title", "url", "author", "score", "license", "note"]
REQUIRED_META = ["title", "url", "author"]

# Where a reference example may come from. Stack Overflow answers are
# mostly troubleshooting fragments rather than complete manifests, and
# often use API versions removed years ago, so the official docs and the
# upstream examples repository are accepted as well. Whichever source is
# used, the .meta records it, so the corpus stays auditable.
ALLOWED_SOURCES = {
    "stackoverflow.com": ("Stack Overflow", "CC BY-SA 4.0"),
    "kubernetes.io": ("Kubernetes documentation", "CC BY 4.0"),
    "github.com/kubernetes": ("Kubernetes examples repo", "Apache-2.0"),
}

# score is a Stack Overflow concept; docs pages do not have one
SCORE_REQUIRED_FOR = ("stackoverflow.com",)


def write_template(path):
    if path.exists():
        sys.exit(f"{path} already exists - delete it first if you want a "
                 f"fresh template")
    out = [
        "# Paste one block per slot. Metadata first, then a line with only",
        "# three dashes, then the manifest. Leave a slot blank to skip it.",
        "#",
        "# Accepted sources: stackoverflow.com (score required),",
        "# kubernetes.io, github.com/kubernetes. The licence defaults to",
        "# match the source if you leave it blank.",
        "#",
        "# The three dashes on their own line separate metadata from YAML.",
        "# If a manifest itself needs --- (multiple documents), that is fine:",
        "# only the FIRST --- after the metadata is treated as the separator.",
        "",
    ]
    for slot in SLOTS:
        fam, cond = slot.rsplit("_", 1)
        out += [
            f"### {slot}",
            f"# want: {FAMILY_WANTED[fam]} - {WANTED[cond]}",
            "title:",
            "url:",
            "author:",
            "score:",
            "license: CC BY-SA 4.0",
            "note:",
            "---",
            "",
            "",
        ]
    path.write_text("\n".join(out))
    print(f"wrote {path.relative_to(ROOT)}")
    print("\nFill it in, then run:")
    print("  python3 scripts/fill_examples.py --dry-run")


def parse(text):
    """Return {slot: (meta_dict, manifest_str)} for every non-empty block."""
    blocks, problems = {}, []

    chunks = re.split(r"^###\s*", text, flags=re.M)[1:]
    if not chunks:
        problems.append("no ### blocks found - is the file filled in?")
        return blocks, problems

    for chunk in chunks:
        lines = chunk.splitlines()
        slot = lines[0].strip()
        body = lines[1:]

        if slot not in SLOTS:
            problems.append(f"unknown slot '{slot}' - expected one of "
                            f"{', '.join(SLOTS)}")
            continue

        # first standalone --- ends the metadata section
        sep = None
        for i, line in enumerate(body):
            if line.strip() == "---":
                sep = i
                break
        if sep is None:
            problems.append(f"{slot}: no --- separator between metadata "
                            f"and manifest")
            continue

        meta = {}
        for line in body[:sep]:
            line = line.strip()
            if not line or line.startswith("#") or ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip().lower()
            if k in META_KEYS and v.strip():
                meta[k] = v.strip()

        manifest = "\n".join(body[sep + 1:]).strip()
        if not manifest:
            continue                      # slot left blank, skip silently

        blocks[slot] = (meta, manifest)

    return blocks, problems


def validate(slot, meta, manifest):
    """Return a list of problems for one block."""
    out = []
    missing = [k for k in REQUIRED_META if not meta.get(k)]
    if missing:
        out.append(f"{slot}: missing {', '.join(missing)}")

    url = meta.get("url", "")
    host = None
    for key in ALLOWED_SOURCES:
        if key in url:
            host = key
            break
    if url and host is None:
        out.append(f"{slot}: url is not from an accepted source "
                   f"({', '.join(ALLOWED_SOURCES)}) - {url}")

    if host in SCORE_REQUIRED_FOR and not meta.get("score"):
        out.append(f"{slot}: Stack Overflow answers need a score")
    if meta.get("score") and not re.fullmatch(r"-?\d+", meta["score"]):
        out.append(f"{slot}: score '{meta['score']}' is not a number")

    if "```" in manifest:
        out.append(f"{slot}: manifest still contains ``` fences - remove them")

    if yaml:
        try:
            docs = [d for d in yaml.safe_load_all(manifest) if d]
            if not docs:
                out.append(f"{slot}: manifest parses but contains no documents")
            kinds = [d.get("kind", "?") for d in docs if isinstance(d, dict)]
            return out, kinds
        except yaml.YAMLError as e:
            out.append(f"{slot}: YAML does not parse - {str(e)[:70]}")
    return out, []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("input", nargs="?", default=str(DEFAULT_INPUT),
                    help="collected input file (default: examples_input.txt)")
    ap.add_argument("--template", action="store_true",
                    help="write a blank input file to fill in")
    ap.add_argument("--dry-run", action="store_true",
                    help="parse and validate without writing examples/")
    a = ap.parse_args()

    path = pathlib.Path(a.input)

    if a.template:
        write_template(path)
        return

    if not path.exists():
        sys.exit(f"{path} not found - run with --template to create it")

    blocks, problems = parse(path.read_text())

    print(f"{'slot':14} {'docs':>5}  {'kinds':28} {'lines':>5}  "
          f"{'source':24} score")
    print("-" * 92)
    for slot in SLOTS:
        if slot not in blocks:
            print(f"{slot:14} {'-':>5}  {'(not filled in)':32}")
            continue
        meta, manifest = blocks[slot]
        errs, kinds = validate(slot, meta, manifest)
        problems += errs
        label = "-"
        for key, (name, _) in ALLOWED_SOURCES.items():
            if key in meta.get("url", ""):
                label = name
                break
        print(f"{slot:14} {len(kinds):>5}  {', '.join(kinds)[:28]:28} "
              f"{len(manifest.splitlines()):>5}  {label:24} "
              f"{meta.get('score', '-')}")

    if problems:
        print("\nPROBLEMS:")
        for p in problems:
            print(f"  - {p}")

    if a.dry_run:
        print(f"\n{len(blocks)}/9 slots filled, "
              f"{'no problems' if not problems else str(len(problems)) + ' problem(s)'}"
              f" - nothing written")
        return

    if problems:
        sys.exit("\nfix the problems above, then run again")

    if not blocks:
        sys.exit("nothing to write")

    EXDIR.mkdir(exist_ok=True)
    for slot, (meta, manifest) in blocks.items():
        (EXDIR / f"{slot}.yaml").write_text(manifest.rstrip() + "\n")
        # licence follows the source unless the block states one
        if not meta.get("license"):
            for key, (_, lic) in ALLOWED_SOURCES.items():
                if key in meta.get("url", ""):
                    meta["license"] = lic
                    break
            meta.setdefault("license", "CC BY-SA 4.0")
        lines = [f"{k}: {meta[k]}" for k in META_KEYS if meta.get(k)]
        (EXDIR / f"{slot}.meta").write_text("\n".join(lines) + "\n")
        print(f"wrote examples/{slot}.yaml + .meta")

    print(f"\n{len(blocks)}/9 slots written. Next:")
    print("  python3 scripts/build_prompts.py --check")


if __name__ == "__main__":
    main()