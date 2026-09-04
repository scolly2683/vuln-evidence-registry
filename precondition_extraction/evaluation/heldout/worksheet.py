#!/usr/bin/env python3
"""Blind-annotation worksheets for the owner, and the collector that turns them into records.

    python3 worksheet.py --make      # writes owner/<CVE>.md for the 15 owner records
    python3 worksheet.py --collect   # parses filled worksheets -> annotators/owner/<CVE>.yaml

The owner never writes YAML and never copies a quote. The advisory is shown as numbered
sentence spans, and **picking a sentence number is the citation**: the collector puts the
exact span text into `cites`, so the record passes the same substring check as everything
else and scores on the same cited-sentence key.

Spans are cut from the ORIGINAL text by character offset (split at sentence punctuation
followed by whitespace and a capital/digit/quote, and at line breaks), then stripped of
surrounding whitespace — so every span is a verbatim substring however imperfect the split.
A sentence the splitter fails to separate is still fine: the gate cites the whole span.

Before annotating, do NOT open reference/, candidates/, runs/, README.md or STANDARDS.md.
The only inputs are PROMPT.md (the rules) and the worksheet.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
EVAL = HERE.parent
ROOT = EVAL.parent.parent
sys.path.insert(0, str(ROOT))
from precondition_extraction.schema import validate_fixture  # noqa: E402

INPUTS = ROOT / "precondition_extraction" / "pipeline" / "data" / "inputs.json"
OWNER_DIR = HERE / "owner"
OUT_DIR = HERE / "annotators" / "owner"

CATEGORIES = ("configuration", "deployment", "api-usage", "network-reachability", "platform")
_BOUNDARY = re.compile(r'(?<=[.!?])\s+(?=[A-Z0-9"“(\[])|\n+')


def spans(text: str) -> list[str]:
    """Numbered sentence spans, each a verbatim substring of `text`."""
    out, start = [], 0
    for m in _BOUNDARY.finditer(text):
        piece = text[start:m.start()].strip()
        if piece:
            out.append(piece)
        start = m.end()
    tail = text[start:].strip()
    if tail:
        out.append(tail)
    for s in out:
        assert s in text, "span is not a substring — splitter bug"
    return out


def make() -> int:
    sample = json.loads((HERE / "sample.json").read_text(encoding="utf-8"))
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    OWNER_DIR.mkdir(parents=True, exist_ok=True)
    n = 0
    for row in sample:
        if not row.get("owner"):
            continue
        cve = row["cve_id"]
        e = inputs[cve]
        ss = spans(e["text"])
        lines = [
            f"# {cve} — blind annotation worksheet",
            "",
            f"Vendor / product (from KEV): **{row.get('kev_vendor')} / {row.get('kev_product')}**  ",
            f"Text source: `{e['source']}` — {e['source_url']}  ",
            f"Stratum: {row['stratum']}",
            "",
            "Rules: `../PROMPT.md` (rules 1–10). Do not open reference/, candidates/, runs/,",
            "README.md or STANDARDS.md until the whole set is collected.",
            "",
            "## Advisory text, as numbered spans",
            "",
        ]
        for i, s in enumerate(ss, 1):
            lines.append(f"**[{i}]** {s}")
            lines.append("")
        lines += [
            "## Your gates",
            "",
            "One row per gate. A span can carry several gates; several spans can carry none.",
            "`category` is one of: configuration · deployment · api-usage · network-reachability · platform.",
            "`required` is y (gates the vulnerability), n (gates only the known exploit — the",
            "text allows other paths), or ? (the text doesn't say).",
            "",
            "| span | category | statement — what must be true of the deployment | required |",
            "|---|---|---|---|",
            "|  |  |  |  |",
            "|  |  |  |  |",
            "|  |  |  |  |",
            "",
            "## If there are no gates",
            "",
            "Leave the table rows blank and uncomment ONE of these (delete the `<!-- -->`):",
            "",
            "<!-- EMPTY: this text states no precondition -->",
            "<!-- EMPTY: genuinely nothing gates this — span N shows it -->",
            "",
            "## Notes (optional — outside-the-text knowledge goes here, labelled as such)",
            "",
            "",
        ]
        (OWNER_DIR / f"{cve}.md").write_text("\n".join(lines), encoding="utf-8")
        n += 1
    print(f"wrote {n} worksheets to {OWNER_DIR}")
    return 0


def _slug(s: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", s.lower()).strip("-")
    return s[:60].rstrip("-") or "gate"


def collect() -> int:
    sample = {r["cve_id"]: r for r in json.loads((HERE / "sample.json").read_text(encoding="utf-8"))}
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    today = dt.date.today().isoformat()
    done, skipped = 0, []
    for md in sorted(OWNER_DIR.glob("CVE-*.md")):
        cve = md.stem
        body = md.read_text(encoding="utf-8")
        e, row = inputs[cve], sample[cve]
        ss = spans(e["text"])

        empty_reading = None
        m = re.search(r"^\s*EMPTY:\s*(.+?)\s*$", body, re.M)
        if m:
            empty_reading = m.group(1).strip()

        gates, ids = [], set()
        for line in body.splitlines():
            if not line.startswith("|") or line.startswith("|---") or line.startswith("| span"):
                continue
            cells = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cells) < 4 or not any(cells):
                continue
            span_no, cat, stmt, req = cells[:4]
            if not span_no and not stmt:
                continue
            try:
                idx = int(span_no)
                span_text = ss[idx - 1]
            except (ValueError, IndexError):
                raise SystemExit(f"{cve}: row has a bad span number {span_no!r}")
            if cat not in CATEGORIES:
                raise SystemExit(f"{cve}: row has a bad category {cat!r}")
            if not stmt:
                raise SystemExit(f"{cve}: span {idx} row has no statement")
            pid = _slug(stmt)
            while pid in ids:
                pid += "-2"
            ids.add(pid)
            gates.append({
                "id": pid,
                "statement": stmt,
                "category": cat,
                "enabled_by_default": None,
                "required_for_exploit": {"y": True, "n": False}.get(req.lower()[:1], None),
                "cites": span_text,
            })

        if not gates and not empty_reading:
            skipped.append(cve)
            continue

        notes = f"Blind owner annotation, {today}, rules frozen per RULES_FROZEN.json."
        if not gates:
            # The test suite requires the prescribed opening for empty records.
            notes = f"{empty_reading} — blind owner annotation, {today}."
        m2 = re.search(r"## Notes.*?\n(.*)\Z", body, re.S)
        extra = (m2.group(1).strip() if m2 else "")
        if extra:
            notes += " Owner notes: " + " ".join(extra.split())

        rec = {
            "cve_id": cve,
            "ghsa_id": None,
            "source": e["source"],
            "source_url": e["source_url"],
            "retrieved": e["retrieved"],
            "advisory_text": e["text"],
            "expected": {
                "identity": {"vendor": row.get("kev_vendor") or "Unknown",
                             "product": row.get("kev_product") or "Unknown",
                             "cpe": None, "purl": None},
                "affected_versions": {"introduced": None, "fixed": None, "excluded_fixed": [],
                                      "notes": "not annotated in the agreement study"},
                "preconditions": gates,
                "remediation_notes": [],
                "general_notes": [],
                "notes": notes,
            },
        }
        validate_fixture(rec)
        (OUT_DIR / f"{cve}.yaml").write_text(
            yaml.safe_dump(rec, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8")
        done += 1
    print(f"collected {done} records -> {OUT_DIR}")
    if skipped:
        print(f"not yet filled in ({len(skipped)}): {', '.join(skipped)}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--make", action="store_true")
    g.add_argument("--collect", action="store_true")
    a = ap.parse_args()
    return make() if a.make else collect()


if __name__ == "__main__":
    raise SystemExit(main())
