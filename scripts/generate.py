#!/usr/bin/env python3
"""
Stage 2 - manifest generation.

Calls the model R times for one (scenario, condition, model) combination and
records the raw response verbatim. Nothing is parsed or cleaned here; that is
the extractor's job. Keeping generation and extraction separate means the raw
response is always available for audit and for the manual verification track.

Every provider here is reached through an OpenAI-compatible endpoint, so only
the model id, base_url and key differ between them.

Usage:
    export DEEPSEEK_API_KEY=...
    export ANTHROPIC_API_KEY=...
    python3 scripts/generate.py --list-models
    python3 scripts/generate.py --scenario S01 --condition P0 --model M3 --samples 3
"""
import argparse
import hashlib
import json
import os
import pathlib
import sys
import time

try:
    from openai import OpenAI
except ImportError:
    sys.exit("pip install openai  (all providers here use the OpenAI-compatible API)")

ROOT = pathlib.Path(__file__).resolve().parent.parent

# --------------------------------------------------------------------------
# Model registry.
#
# Labels are FIXED once results exist: every results/*.json is filed under its
# label, so redefining one would make old and new records incomparable while
# looking identical. A label may only be reassigned by renaming the artefacts
# already filed under it, never by editing this dict alone.
#
# Ids are explicit GA versions, never preview aliases. Preview aliases get
# retired and repointed by the provider without notice, which would silently
# change the model behind your results mid-study. The id is recorded in every
# generation.json so a result can always be traced to what produced it.
#
# The base_url values are OpenAI-compatibility endpoints. Providers that do
# not serve the OpenAI wire format natively usually publish a compatibility
# path for it; that path is what belongs here.
# --------------------------------------------------------------------------
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/"

MODELS = {
    # M1 is reserved for a third model that has not yet been selected. Any
    # provider exposing an OpenAI-compatible endpoint slots in here by
    # supplying an id, a base_url and the name of its credential variable;
    # nothing else in this file changes.
    #
    # "M1": {
    #     "id": "...",
    #     "base_url": "...",
    #     "key_env": "...",
    #     "delay_seconds": 0,
    #     "supports_top_p": True,
    # },
    "M2": {
        "id": "deepseek-chat",
        "base_url": DEEPSEEK_BASE_URL,
        "key_env": "DEEPSEEK_API_KEY",
        # paid tier, no free-tier RPM cap to work around
        "delay_seconds": 0,
        "supports_top_p": True,
    },
    "M3": {
        "id": "claude-sonnet-5",
        "base_url": ANTHROPIC_BASE_URL,
        "key_env": "ANTHROPIC_API_KEY",
        "delay_seconds": 0,
        # Sonnet 5 rejects top_p outright. Since TOP_P is 1.0 - the value that
        # disables nucleus filtering entirely - omitting it is behaviourally
        # equivalent, not a change in sampling. The generation record says so
        # explicitly rather than leaving the field silently absent.
        "supports_top_p": False,
    },
}

# Sampling parameters are fixed for the whole study and recorded per run.
# Temperature must be > 0, otherwise the three samples collapse to one output
# and the intra-prompt variance the design relies on disappears.
TEMPERATURE = 1.0
TOP_P = 1.0
MAX_TOKENS = 4096


def generate(scenario, condition, model_key, samples, outdir, sample_start=1):
    prompt_path = ROOT / "prompts" / f"{scenario}_{condition}.txt"
    if not prompt_path.exists():
        sys.exit(f"missing prompt file: {prompt_path}")
    prompt = prompt_path.read_text()

    spec = MODELS[model_key]
    key_env = spec["key_env"]
    api_key = os.environ.get(key_env)
    if not api_key:
        sys.exit(f"{key_env} is not set (needed for {model_key} = {spec['id']})")
    client = OpenAI(api_key=api_key, base_url=spec["base_url"])
    delay = spec.get("delay_seconds", 0)
    use_top_p = spec.get("supports_top_p", True)

    # sample_start lets a batch runner request one specific sample, e.g. r2,
    # without regenerating r1. Without it every single-sample call would write
    # r1 and the later samples would never exist.
    for r in range(sample_start, sample_start + samples):
        gen_id = f"{scenario}_{condition}_{model_key}_r{r}"
        rundir = outdir / gen_id
        rundir.mkdir(parents=True, exist_ok=True)

        kwargs = {
            "model": spec["id"],
            "messages": [{"role": "user", "content": prompt}],
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
        }
        if use_top_p:
            kwargs["top_p"] = TOP_P

        started = time.time()
        resp = client.chat.completions.create(**kwargs)
        elapsed = round(time.time() - started, 2)
        text = resp.choices[0].message.content or ""

        (rundir / "response.txt").write_text(text)
        record = {
            "generation_id": gen_id,
            "scenario": scenario,
            "condition": condition,
            "model_label": model_key,
            "model_id": spec["id"],
            "provider_base_url": spec["base_url"],
            "sample": r,
            "temperature": TEMPERATURE,
            "top_p": TOP_P if use_top_p else "not supported by this model",
            "max_tokens": MAX_TOKENS,
            "finish_reason": resp.choices[0].finish_reason,
            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,
            "elapsed_seconds": elapsed,
            "response_sha256": hashlib.sha256(text.encode()).hexdigest(),
            "generated_at_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        (rundir / "generation.json").write_text(json.dumps(record, indent=2))
        print(f"{gen_id}  {elapsed}s  {resp.usage.completion_tokens} tok  "
              f"finish={resp.choices[0].finish_reason}")

        # Pace requests for rate-limited providers. Skip after the last sample.
        if r < sample_start + samples - 1 and delay:
            time.sleep(delay)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--scenario", default="S01")
    p.add_argument("--condition", default="P0")
    p.add_argument("--model", default="M2", choices=list(MODELS))
    p.add_argument("--samples", type=int, default=3)
    p.add_argument("--sample-start", type=int, default=1,
                   help="number the first sample r<N> instead of r1")
    p.add_argument("--list-models", action="store_true",
                   help="show the registry and which keys are set")
    a = p.parse_args()

    if a.list_models:
        for k, v in MODELS.items():
            have = "set" if os.environ.get(v["key_env"]) else "MISSING"
            print(f"{k}  {v['id']:22} {v['key_env']:18} {have}")
        sys.exit(0)

    generate(a.scenario, a.condition, a.model, a.samples, ROOT / "runs",
             sample_start=a.sample_start)