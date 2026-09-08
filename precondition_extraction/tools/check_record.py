#!/usr/bin/env python3
"""Step 4 of the recipe: check a record mechanically. No model, no network.

    python3 tools/check_record.py CVE-2026-9586.yaml --input CVE-2026-9586.input.json
    python3 tools/check_record.py CVE-2026-9586.yaml            # warns: text not substituted

--input is the capture written by cve_text.py / extract_one.py ({cve: {source, source_url,
retrieved, text, ...}}). When given, the record's advisory_text, source, source_url and
retrieved are REPLACED from the capture before anything is checked, and the tool prints
"TEXT SUBSTITUTED FROM CAPTURE". This closes the hole where a model writes the YAML file
itself and types its own (possibly paraphrased) advisory_text: citations would then be checked
against the model's copy, not the captured text. Without --input the tool still runs but
prints a WARNING, and the result should be treated as unverified.

For each file: confirm every precondition's `cites` is a verbatim substring of `advisory_text`
(whitespace and non-breaking spaces normalised), confirm an empty precondition list states
which of Rule 5's two readings applies, then validate the whole record against the schema.
One line per citation, PASS or FAIL; exit 0 only when everything passes. A failing record is
not fixed here — that is the point of the check.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from precondition_extraction.schema import FixtureError, citation_in_text, validate_fixture  # noqa: E402

EMPTY_READINGS = ("genuinely nothing gates this", "this text states no precondition")
WARNING = ("WARNING: advisory_text not substituted from capture; "
           "citations checked against the record's own text")


def substitute(data: dict, capture: dict) -> bool:
    """Replace the four captured fields from {cve: entry}. Returns False if the CVE is absent."""
    entry = capture.get(str(data.get("cve_id", "")).upper())
    if not entry:
        return False
    data["advisory_text"] = entry["text"]
    data["source"] = entry["source"]
    data["source_url"] = entry["source_url"]
    data["retrieved"] = entry["retrieved"]
    return True


def check_file(path: Path, capture: dict | None) -> bool:
    print(f"== {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"YAML FAIL  {exc}")
        return False
    if not isinstance(data, dict) or "expected" not in data or "advisory_text" not in data:
        print("SHAPE FAIL  not a record (needs advisory_text and expected)")
        return False
    if capture is not None:
        if not substitute(data, capture):
            print(f"CAPTURE FAIL  no entry for {data.get('cve_id')!r} in the --input file")
            return False
        print("TEXT SUBSTITUTED FROM CAPTURE")
    else:
        print(WARNING)
    ok = True
    text = data["advisory_text"] or ""
    conds = (data["expected"] or {}).get("preconditions") or []
    for c in conds:
        cites = c.get("cites") or ""
        good = bool(cites) and citation_in_text(cites, text)
        ok &= good
        print(f"{'PASS' if good else 'FAIL'}  {c.get('id')}  [{c.get('category')}]")
        print(f"      cites: \"{cites or '(none)'}\"")
    if not conds:
        notes = str((data["expected"] or {}).get("notes") or "")
        good = notes.startswith(EMPTY_READINGS)
        ok &= good
        print(f"{'PASS' if good else 'FAIL'}  (empty list) notes must begin with one of {EMPTY_READINGS}")
        print(f"      notes: \"{notes[:160]}\"")
    try:
        validate_fixture(data)
        print("SCHEMA PASS")
    except FixtureError as exc:
        ok = False
        print(f"SCHEMA FAIL  {exc}")
    print(f"{'ACCEPTED' if ok else 'REJECTED'}  {len(conds)} precondition(s)")
    return ok


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("files", nargs="*", type=Path)
    ap.add_argument("--input", type=Path, help="the .input.json capture; substitutes the four captured fields")
    a = ap.parse_args(argv)
    if not a.files:
        print(__doc__)
        return 2
    capture = None
    if a.input:
        capture = {k.upper(): v for k, v in json.loads(a.input.read_text(encoding="utf-8")).items()}
    results = [check_file(p, capture) for p in a.files]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
