#!/usr/bin/env python3
"""Emit one JSON bundle for an extraction run — the file downstream consumers ingest.

    python3 bundle.py --run runs/edge-2023plus

Writes `<run>/bundle.json`. One file rather than 170 YAMLs because a consumer then needs
one HTTP fetch, no YAML dependency, and one sha256 to decide "unchanged since last time".

Every record carries the full `advisory_text` alongside its preconditions so a consumer can
re-run the citation check itself — `cites` ⊂ `advisory_text` under NBSP/whitespace
normalisation — rather than trusting this file. The bundle is evidence, and evidence that
cannot be re-checked at the point of use is a claim.

The `family` on each precondition comes from `families.py`, the one implementation, so the
consumer stores what the registry says and the numbers stay reproducible.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import sys

import yaml

HERE = pathlib.Path(__file__).parent
sys.path.insert(0, str(HERE))
from families import family  # noqa: E402

BUNDLE_VERSION = 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--run", required=True)
    ap.add_argument("--extractor", default=None, help="override; default read from _run.json")
    a = ap.parse_args()
    run = pathlib.Path(a.run)
    if not run.is_absolute():
        run = HERE / run
    files = sorted(run.glob("CVE-*.yaml"))
    if not files:
        raise SystemExit(f"error: no records in {run}")

    meta = {}
    if (run / "_run.json").exists():
        meta = json.loads((run / "_run.json").read_text())
    # Prefer the model recorded FROM the calls (model_resolved) over the alias asked for.
    extractor = a.extractor or meta.get("model_resolved") or meta.get("model") or "unknown"

    records = []
    for p in files:
        rec = yaml.safe_load(p.read_text(encoding="utf-8"))
        exp = rec.get("expected") or {}
        text = rec.get("advisory_text") or ""
        pcs = []
        for pc in exp.get("preconditions") or []:
            pcs.append({
                "id": pc.get("id"),
                "statement": pc.get("statement"),
                "category": pc.get("category"),
                "cites": pc.get("cites"),
                "required_for_exploit": pc.get("required_for_exploit"),
                "enabled_by_default": pc.get("enabled_by_default"),
                "family": family(pc),
            })
        records.append({
            "cve_id": rec["cve_id"],
            "source": rec.get("source"),
            "source_url": rec.get("source_url"),
            "retrieved": str(rec.get("retrieved") or ""),
            "advisory_text": text,
            "advisory_sha256": hashlib.sha256(text.encode("utf-8")).hexdigest(),
            "preconditions": pcs,
            "notes": exp.get("notes"),
        })

    out = {
        "bundle_version": BUNDLE_VERSION,
        "run": run.name,
        "extractor": extractor,
        "rules": "precondition_extraction/evaluation/PROMPT.md (rules 1-10)",
        "generated": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds"),
        "record_count": len(records),
        "precondition_count": sum(len(r["preconditions"]) for r in records),
        "records": records,
    }
    path = run / "bundle.json"
    path.write_text(json.dumps(out, indent=1, ensure_ascii=False), encoding="utf-8")
    print(f"wrote {path}: {out['record_count']} records, {out['precondition_count']} preconditions, "
          f"{path.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
