#!/usr/bin/env python3
"""Run the vuln-evidence-registry extraction prompt over the 50-CVE KEV sample.

For each CVE in ``kev_sample.json`` this sends PROMPT.md + the advisory text
(verbatim, already fetched — the model is told NOT to fetch) to an LLM and stores:

- ``<out>/<CVE>.md``    the full response (THE READING + THE RECORD)
- ``<out>/<CVE>.yaml``  the YAML block only, parsed by ``analyse.py`` / ``compare.py``
- ``<out>/<CVE>.error`` if the call failed, was refused, or returned no YAML

Idempotent: CVEs with an existing ``.yaml`` in ``<out>`` are skipped, so it can be
re-run after a rate-limit stop and will pick up where it left off.

Providers (``--provider``):
- ``anthropic`` — Claude via the official SDK. Model ``EXTRACT_MODEL`` (default claude-opus-5).
- ``groq``      — openai/gpt-oss-120b on Groq's free tier (~30 RPM; tokens/day capped).
- ``gemini``    — gemini-3.1-flash-lite on Google's OpenAI-compatible endpoint (free tier).
The two free providers are the house LLM chain (``app/enrichment/llm_client.py``) —
same models, same base URLs, so a result here predicts production behaviour.

Source (``--source``): ``msrc-preferred`` (default) uses ``row["msrc"]["advisory_text"]``
when ``fetch_msrc.py`` attached it (Microsoft rows), else the NVD description;
``nvd`` forces NVD everywhere (the original run).

Setup:
    pip install pyyaml anthropic      # or: pip install pyyaml openai   (groq / gemini)
    export ANTHROPIC_API_KEY=... | GROQ_API_KEY=... | GEMINI_API_KEY=...
    python run_extraction.py --provider groq --out records-groq [--limit N] [--only CVE-...]

Cost: Anthropic ~US$4-5 for the 50 on Opus (EXTRACT_MODEL=claude-sonnet-5 ≈ 40% of that);
Groq/Gemini free but rate-limited — the runner honours Retry-After and paces calls.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import pathlib
import re
import sys
import time

HERE = pathlib.Path(__file__).parent

PROVIDERS = {
    "anthropic": {"model": os.environ.get("EXTRACT_MODEL", "claude-opus-5"), "pace": 0.0},
    "groq": {"model": "openai/gpt-oss-120b", "base_url": "https://api.groq.com/openai/v1",
             "key": "GROQ_API_KEY", "pace": 2.5},
    "gemini": {"model": "gemini-3.1-flash-lite",
               "base_url": "https://generativelanguage.googleapis.com/v1beta/openai/",
               "key": "GEMINI_API_KEY", "pace": 4.5},
}

YAML_BLOCK = re.compile(r"```ya?ml\s*\n(.*?)\n```", re.S)


def pick_source(row: dict, mode: str) -> dict | None:
    """Return {name, url, retrieved, text} or None when no text is available."""
    msrc = row.get("msrc")
    # Only prefer MSRC when it actually carries articles — a title-only SUG record
    # (the 2016 CVEs) is no better than NVD's title-only description.
    if mode == "msrc-preferred" and msrc and msrc.get("advisory_text") and msrc.get("article_types"):
        return {"name": f"MSRC Security Update Guide (release {msrc.get('release')}; HTML stripped)",
                "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{row['cveID']}",
                "retrieved": msrc.get("retrieved"), "text": msrc["advisory_text"]}
    nvd = row.get("nvd") or {}
    if nvd.get("description"):
        return {"name": "NVD (official description)",
                "url": f"https://nvd.nist.gov/vuln/detail/{row['cveID']}",
                "retrieved": row.get("nvd_retrieved"), "text": nvd["description"],
                "cvss": nvd.get("cvss_vector")}
    return None


def build_user_message(prompt: str, row: dict, src: dict) -> str:
    today = dt.date.today().isoformat()
    cvss = f"CVSS vector (metadata, context only — never cite it): {src.get('cvss') or 'none'}\n" if src.get("cvss") else ""
    return (
        f"{prompt.rstrip()}\n\n"
        f"CVE ID: {row['cveID']}\n"
        f"Source: {src['name']}, fetched {src['retrieved']}; today is {today}\n"
        f"Source URL: {src['url']}\n{cvss}\n"
        "The advisory text is supplied verbatim below — do not fetch anything. Cite sentences "
        "exactly as they appear here.\n\n"
        f"---\n{src['text']}\n---\n"
    )


# ── provider calls: each returns (text, stop_reason, usage_in, usage_out) ─────

def call_anthropic(model: str, text: str):
    import anthropic  # lazy — the CI job for groq/gemini does not install it

    client = anthropic.Anthropic()
    try:
        with client.messages.stream(model=model, max_tokens=16000,
                                    thinking={"type": "adaptive"},
                                    messages=[{"role": "user", "content": text}]) as stream:
            msg = stream.get_final_message()
    except anthropic.RateLimitError as exc:
        raise Throttled(int(exc.response.headers.get("retry-after", "60"))) from exc
    except anthropic.APIStatusError as exc:
        raise Failed(f"api error {exc.status_code}: {exc.message}") from exc
    except anthropic.APIConnectionError as exc:
        raise Failed(f"connection error: {exc}") from exc
    if msg.stop_reason == "refusal":
        raise Failed(f"refusal: {getattr(msg, 'stop_details', None)}")
    out = "".join(b.text for b in msg.content if b.type == "text")
    return out, msg.stop_reason, msg.usage.input_tokens, msg.usage.output_tokens


def call_openai_compat(model: str, base_url: str, key_env: str, text: str):
    import openai  # lazy

    key = os.environ.get(key_env)
    if not key:
        raise SystemExit(f"{key_env} is not set")
    client = openai.OpenAI(api_key=key, base_url=base_url, max_retries=0)
    try:
        resp = client.chat.completions.create(
            model=model, temperature=0.1, max_tokens=8000,
            messages=[{"role": "user", "content": text}],
        )
    except openai.RateLimitError as exc:
        ra = exc.response.headers.get("retry-after") if exc.response is not None else None
        raise Throttled(int(float(ra)) + 1 if ra else 30) from exc
    except openai.APIStatusError as exc:
        raise Failed(f"api error {exc.status_code}: {exc.message}") from exc
    except openai.APIConnectionError as exc:
        raise Failed(f"connection error: {exc}") from exc
    choice = resp.choices[0]
    u = resp.usage
    return (choice.message.content or "", choice.finish_reason,
            u.prompt_tokens if u else 0, u.completion_tokens if u else 0)


class Throttled(Exception):
    def __init__(self, wait: int):
        super().__init__(f"rate limited, wait {wait}s")
        self.wait = wait


class Failed(Exception):
    pass


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", choices=PROVIDERS, default="anthropic")
    ap.add_argument("--out", default=None, help="output directory (default candidates/<provider>)")
    ap.add_argument("--source", choices=["msrc-preferred", "nvd"], default="msrc-preferred")
    ap.add_argument("--limit", type=int, default=0, help="stop after N new records")
    ap.add_argument("--only", action="append", default=[], help="run only these CVE ids")
    ap.add_argument("--pace", type=float, default=None, help="seconds between calls (default per provider)")
    ap.add_argument("--max-throttle-retries", type=int, default=8)
    ap.add_argument("--quota-wait-threshold", type=int, default=600,
                    help="a retry-after longer than this (seconds) means the daily quota is gone: stop")
    args = ap.parse_args()

    cfg = PROVIDERS[args.provider]
    pace = cfg["pace"] if args.pace is None else args.pace
    prompt = (HERE / "PROMPT.md").read_text()
    rows = json.loads((HERE / "kev_sample.json").read_text())
    out_dir = HERE / (args.out or f"candidates/{args.provider}")
    out_dir.mkdir(parents=True, exist_ok=True)

    done = 0
    t_start = time.time()
    tok_in = tok_out = 0
    for row in rows:
        cve = row["cveID"]
        if args.only and cve not in args.only:
            continue
        if (out_dir / f"{cve}.yaml").exists():
            continue
        src = pick_source(row, args.source)
        if not src:
            (out_dir / f"{cve}.error").write_text("no advisory text in kev_sample.json\n")
            print(f"skip {cve}: no text", file=sys.stderr)
            continue
        text = build_user_message(prompt, row, src)

        t0 = time.time()
        result = None
        quota_exhausted = False
        for attempt in range(args.max_throttle_retries + 1):
            try:
                if args.provider == "anthropic":
                    result = call_anthropic(cfg["model"], text)
                else:
                    result = call_openai_compat(cfg["model"], cfg["base_url"], cfg["key"], text)
                break
            except Throttled as exc:
                # A per-minute limit says "retry in seconds". A retry-after of many
                # minutes is the DAILY quota talking (Groq free tier: ~1h windows) —
                # no amount of in-job retrying helps, and the 2026-09-02 run burned
                # its whole 120-minute budget proving that. Stop, leave a marker, and
                # let the next dispatch resume (the runner is idempotent).
                if exc.wait > args.quota_wait_threshold:
                    quota_exhausted = True
                    (out_dir / "QUOTA_EXHAUSTED").write_text(
                        f"{cve}: retry-after {exc.wait}s at {dt.datetime.now(dt.UTC).isoformat()}\n")
                    print(f"!! {cve}: quota exhausted (retry-after {exc.wait}s) — stopping; "
                          f"re-run later to resume", file=sys.stderr, flush=True)
                    break
                print(f"   {cve}: {exc} (attempt {attempt + 1})", file=sys.stderr, flush=True)
                time.sleep(exc.wait)
            except Failed as exc:
                (out_dir / f"{cve}.error").write_text(f"{exc}\n")
                print(f"!! {cve}: {exc}", file=sys.stderr, flush=True)
                break
        if quota_exhausted:
            break
        if result is None:
            if not (out_dir / f"{cve}.error").exists():
                (out_dir / f"{cve}.error").write_text("gave up after repeated rate limiting\n")
                print(f"!! {cve}: gave up after repeated rate limiting", file=sys.stderr)
            continue

        body, stop, n_in, n_out = result
        tok_in += n_in
        tok_out += n_out
        (out_dir / f"{cve}.md").write_text(body)
        m = YAML_BLOCK.search(body)
        if not m:
            (out_dir / f"{cve}.error").write_text("no ```yaml block in response\n")
            print(f"!! {cve}: no YAML block (response saved to .md)", file=sys.stderr, flush=True)
            continue
        (out_dir / f"{cve}.yaml").write_text(m.group(1) + "\n")
        truncated = stop in ("max_tokens", "length")
        print(f"{cve}: ok in {time.time() - t0:.0f}s, {n_in} in / {n_out} out"
              f"{' (TRUNCATED)' if truncated else ''}  [{src['name'].split(' (')[0]}]", flush=True)
        done += 1
        if args.limit and done >= args.limit:
            break
        if pace:
            time.sleep(pace)

    el = time.time() - t_start
    print(f"done: {done} new records in {out_dir} — {el:.0f}s, {tok_in} in / {tok_out} out tokens"
          + (f", {el / done:.0f}s per CVE" if done else ""))
    if (out_dir / "QUOTA_EXHAUSTED").exists():
        print("stopped early: provider quota exhausted — re-run to resume", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
