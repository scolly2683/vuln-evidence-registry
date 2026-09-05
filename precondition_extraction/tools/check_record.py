#!/usr/bin/env python3
"""Step 4 of the recipe: check a record mechanically. No model, no network.

    python3 tools/check_record.py CVE-2026-9586.yaml [more.yaml ...]

For each file: confirm every precondition's `cites` is a verbatim substring of
`advisory_text` (whitespace and non-breaking spaces normalised — the same check the
evaluation applied), confirm an empty precondition list states which of Rule 5's two
readings applies, then validate the whole record against the schema
(tests/fixtures/schema.json). One line per citation, PASS or FAIL; exit 0 only when
everything passes. A failing record is not fixed here — that is the point of the check.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[1]))
from precondition_extraction.schema import FixtureError, citation_in_text, validate_fixture  # noqa: E402

EMPTY_READINGS = ("genuinely nothing gates this", "this text states no precondition")


def check_file(path: Path) -> bool:
    print(f"== {path}")
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        print(f"YAML FAIL  {exc}")
        return False
    if not isinstance(data, dict) or "expected" not in data or "advisory_text" not in data:
        print("SHAPE FAIL  not a record (needs advisory_text and expected)")
        return False
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
    args = list(argv if argv is not None else sys.argv[1:])
    if not args:
        print(__doc__)
        return 2
    results = [check_file(Path(a)) for a in args]
    return 0 if all(results) else 1


if __name__ == "__main__":
    sys.exit(main())
