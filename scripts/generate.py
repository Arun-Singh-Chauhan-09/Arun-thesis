#!/usr/bin/env python3
"""
Stage 2 - manifest generation.

Calls the model R times for one (scenario, condition, model) combination and
records the raw response verbatim. Nothing is parsed or cleaned here; that is
the extractor's job.

Providers use OpenAI-compatible endpoints.

Usage:
    export TOGETHER_API_KEY=...
    export DEEPSEEK_API_KEY=...
    export ANTHROPIC_API_KEY=...

    python3 scripts/generate.py --list-models

    python3 scripts/generate.py \
        --scenario S01 \
        --condition P0 \
        --model M1 \
        --samples 1
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
    sys.exit(
        "pip install openai  "
        "(all providers here use the OpenAI-compatible API)"
    )

ROOT = pathlib.Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------
# Provider endpoints
# --------------------------------------------------------------------------

TOGETHER_BASE_URL = "https://api.together.xyz/v1"
DEEPSEEK_BASE_URL = "https://api.deepseek.com/v1"
ANTHROPIC_BASE_URL = "https://api.anthropic.com/v1/"


# --------------------------------------------------------------------------
# Model registry
#
# M1 = Llama 3.3 70B Instruct Turbo via Together AI
# M2 = DeepSeek Chat
# M3 = Claude Sonnet 5
# --------------------------------------------------------------------------

MODELS = {

    "M1": {
        "id": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
        "base_url": TOGETHER_BASE_URL,
        "key_env": "TOGETHER_API_KEY",
        "delay_seconds": 0,
        "supports_top_p": True,
    },

    "M2": {
        "id": "deepseek-chat",
        "base_url": DEEPSEEK_BASE_URL,
        "key_env": "DEEPSEEK_API_KEY",
        "delay_seconds": 0,
        "supports_top_p": True,
    },

    "M3": {
        "id": "claude-sonnet-5",
        "base_url": ANTHROPIC_BASE_URL,
        "key_env": "ANTHROPIC_API_KEY",
        "delay_seconds": 0,
        "supports_top_p": False,
    },
}


# --------------------------------------------------------------------------
# Fixed sampling parameters for the study
# --------------------------------------------------------------------------

TEMPERATURE = 1.0
TOP_P = 1.0
MAX_TOKENS = 4096


def generate(scenario, condition, model_key, samples, outdir, sample_start=1):

    # ------------------------------------------------------------
    # 1. Load prompt
    # ------------------------------------------------------------

    prompt_path = ROOT / "prompts" / f"{scenario}_{condition}.txt"

    if not prompt_path.exists():
        sys.exit(f"missing prompt file: {prompt_path}")

    prompt = prompt_path.read_text()


    # ------------------------------------------------------------
    # 2. Load model configuration
    # ------------------------------------------------------------

    spec = MODELS[model_key]

    key_env = spec["key_env"]

    api_key = os.environ.get(key_env)

    if not api_key:
        sys.exit(
            f"{key_env} is not set "
            f"(needed for {model_key} = {spec['id']})"
        )


    # ------------------------------------------------------------
    # 3. Create OpenAI-compatible client
    # ------------------------------------------------------------

    client = OpenAI(
        api_key=api_key,
        base_url=spec["base_url"]
    )

    delay = spec.get("delay_seconds", 0)
    use_top_p = spec.get("supports_top_p", True)


    # ------------------------------------------------------------
    # 4. Generate samples
    # ------------------------------------------------------------

    for r in range(sample_start, sample_start + samples):

        gen_id = f"{scenario}_{condition}_{model_key}_r{r}"

        rundir = outdir / gen_id
        rundir.mkdir(parents=True, exist_ok=True)


        # --------------------------------------------------------
        # API request
        # --------------------------------------------------------

        kwargs = {
            "model": spec["id"],
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ],
            "temperature": TEMPERATURE,
            "max_tokens": MAX_TOKENS,
        }

        if use_top_p:
            kwargs["top_p"] = TOP_P


        # --------------------------------------------------------
        # Call model
        # --------------------------------------------------------

        started = time.time()

        resp = client.chat.completions.create(**kwargs)

        elapsed = round(time.time() - started, 2)

        text = resp.choices[0].message.content or ""


        # --------------------------------------------------------
        # Save raw response
        # --------------------------------------------------------

        (rundir / "response.txt").write_text(text)


        # --------------------------------------------------------
        # Save generation metadata
        # --------------------------------------------------------

        record = {
            "generation_id": gen_id,
            "scenario": scenario,
            "condition": condition,

            "model_label": model_key,
            "model_id": spec["id"],
            "provider_base_url": spec["base_url"],

            "sample": r,

            "temperature": TEMPERATURE,
            "top_p": (
                TOP_P
                if use_top_p
                else "not supported by this model"
            ),

            "max_tokens": MAX_TOKENS,

            "finish_reason": resp.choices[0].finish_reason,

            "prompt_tokens": resp.usage.prompt_tokens,
            "completion_tokens": resp.usage.completion_tokens,

            "elapsed_seconds": elapsed,

            "response_sha256": hashlib.sha256(
                text.encode()
            ).hexdigest(),

            "generated_at_utc": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime()
            ),
        }


        (rundir / "generation.json").write_text(
            json.dumps(record, indent=2)
        )


        # --------------------------------------------------------
        # Console output
        # --------------------------------------------------------

        print(
            f"{gen_id}  "
            f"{elapsed}s  "
            f"{resp.usage.completion_tokens} tok  "
            f"finish={resp.choices[0].finish_reason}"
        )


        # --------------------------------------------------------
        # Optional delay between samples
        # --------------------------------------------------------

        if (
            r < sample_start + samples - 1
            and delay
        ):
            time.sleep(delay)


# --------------------------------------------------------------------------
# Command-line interface
# --------------------------------------------------------------------------

if __name__ == "__main__":

    p = argparse.ArgumentParser()

    p.add_argument(
        "--scenario",
        default="S01"
    )

    p.add_argument(
        "--condition",
        default="P0"
    )

    p.add_argument(
        "--model",
        default="M2",
        choices=list(MODELS)
    )

    p.add_argument(
        "--samples",
        type=int,
        default=3
    )

    p.add_argument(
        "--sample-start",
        type=int,
        default=1,
        help="number the first sample r<N> instead of r1"
    )

    p.add_argument(
        "--list-models",
        action="store_true",
        help="show the registry and which keys are set"
    )

    a = p.parse_args()


    # ------------------------------------------------------------
    # List configured models
    # ------------------------------------------------------------

    if a.list_models:

        for k, v in MODELS.items():

            have = (
                "set"
                if os.environ.get(v["key_env"])
                else "MISSING"
            )

            print(
                f"{k}  "
                f"{v['id']:45} "
                f"{v['key_env']:20} "
                f"{have}"
            )

        sys.exit(0)


    # ------------------------------------------------------------
    # Run generation
    # ------------------------------------------------------------

    generate(
        a.scenario,
        a.condition,
        a.model,
        a.samples,
        ROOT / "runs",
        sample_start=a.sample_start
    )