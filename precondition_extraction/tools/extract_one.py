#!/usr/bin/env python3
"""Steps 1–4 of the recipe in one command, for ONE CVE — exactly what the evaluation did.

    python3 tools/extract_one.py CVE-2024-38475 --vendor "Apache" --product "HTTP Server"
    python3 tools/extract_one.py CVE-2024-38475 --vendor Apache --product "HTTP Server" --model sonnet --out work/

What it does, in order (each step is the same function the batch pipeline uses):
  1. fetch the advisory text verbatim                     (tools/cve_text.py)
  2. build the prompt: the frozen rules, then the text    (pipeline/extract.py::build_prompt)
  3. run `claude -p --model <m> --output-format json`      (pipeline/extract.py::call_claude)
     and record which model actually answered
  4. parse the YAML, substitute the canonical text, validate against the schema, check every
     `cites` is a verbatim substring                       (pipeline/extract.py::check)

Writes <out>/<CVE>.yaml (the record), <out>/<CVE>.advisory.txt, <out>/<CVE>.input.json and
<out>/<CVE>.run.json (model requested + model that answered + verdict). Exit 0 = record
accepted, 1 = rejected (the reason is printed; do not fix the YAML by hand — re-run).

`--vendor` / `--product` are the record's identity. Rule 1 stops the model from naming a
vendor the text never mentions, so you supply them, as the batch run took them from KEV.
Needs: Python 3, PyYAML, and the `claude` CLI signed in (a subscription is enough).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "pipeline"))
from cve_text import build_entry  # noqa: E402
from extract import PROMPT_PATH, build_prompt, call_claude, check, parse_record  # noqa: E402

import yaml  # noqa: E402


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cve")
    ap.add_argument("--vendor", required=True, help='record identity, e.g. "Apache"')
    ap.add_argument("--product", required=True, help='record identity, e.g. "HTTP Server"')
    ap.add_argument("--model", default="sonnet", help="alias or exact id passed to `claude -p --model`")
    ap.add_argument("--out", type=Path, default=Path("."))
    ap.add_argument("--timeout", type=int, default=300)
    a = ap.parse_args(argv)
    cve = a.cve.strip().upper()
    a.out.mkdir(parents=True, exist_ok=True)

    print(f"[1/4] fetching advisory text for {cve} …", flush=True)
    entry = build_entry(cve)
    entry["kev_vendor"], entry["kev_product"] = a.vendor, a.product
    (a.out / f"{cve}.advisory.txt").write_text(entry["text"], encoding="utf-8")
    (a.out / f"{cve}.input.json").write_text(json.dumps({cve: entry}, indent=2), encoding="utf-8")
    print(f"      source={entry['source']} cna={entry['cna']} chars={len(entry['text'])}")

    print("[2/4] building the prompt from the frozen rules …", flush=True)
    rules = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = build_prompt(cve, entry, rules)

    print(f"[3/4] running `claude -p --model {a.model} --output-format json` …", flush=True)
    raw, used, err = call_claude(prompt, a.model, a.timeout)
    run = {"cve_id": cve, "model_requested": a.model, "model_resolved": used, "prompt_file": str(PROMPT_PATH)}
    if err:
        run["verdict"] = f"rejected: {err}"
        (a.out / f"{cve}.run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
        print(f"      FAILED: {err}")
        return 1
    print(f"      answered by: {used}")

    print("[4/4] parsing, substituting the canonical text, validating, checking citations …", flush=True)
    rec, err = parse_record(raw)
    if err is None:
        err = check(rec, cve, entry)
    if err:
        run["verdict"] = f"rejected: {err}"
        (a.out / f"{cve}.run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
        (a.out / f"{cve}.rejected.txt").write_text(raw, encoding="utf-8")
        print(f"      REJECTED: {err}\n      raw reply kept in {a.out / (cve + '.rejected.txt')}")
        return 1
    (a.out / f"{cve}.yaml").write_text(yaml.safe_dump(rec, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")
    run["verdict"] = "accepted"
    run["preconditions"] = len(rec["expected"]["preconditions"])
    (a.out / f"{cve}.run.json").write_text(json.dumps(run, indent=2), encoding="utf-8")
    print(f"      ACCEPTED — {run['preconditions']} precondition(s), every citation verified")
    print(f"      record: {a.out / (cve + '.yaml')}")
    print("\nTHE READING (what to review):")
    for c in rec["expected"]["preconditions"]:
        print(f"  - {c['id']}  [{c['category']}, required={c['required_for_exploit']}, default={c['enabled_by_default']}]")
        print(f"      cites: \"{c['cites']}\"")
    if not rec["expected"]["preconditions"]:
        print(f"  (empty) notes: {rec['expected'].get('notes')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
