#!/usr/bin/env python3
"""Step 1 of the recipe: get the advisory text for ONE CVE, verbatim, and save it.

    python3 tools/cve_text.py CVE-2024-38475            # prints, and writes CVE-2024-38475.advisory.txt + .input.json
    python3 tools/cve_text.py CVE-2024-38475 --out work/  # same, into a folder

Reads the CVE Program's own record (cvelistV5 on GitHub) through the same helpers the batch
pipeline uses (pipeline/fetch_sources.py): the English description(s), plus the CNA's
`configurations` and `workarounds` text when they filled it. Microsoft CVEs are title-only
in the CVE record, so for those the Security Update Guide text is fetched instead.

The text is never edited. The `.input.json` beside it is what tools/extract_one.py feeds to
the model — source, source_url, retrieved date and the text — so a citation can always be
re-checked against exactly what the model saw.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "pipeline"))
from fetch_sources import cvelist_record, cvelist_text, fetch_sug  # noqa: E402


def build_entry(cve: str) -> dict:
    """The same shape pipeline/extract.py expects: source, source_url, retrieved, text, cna, …"""
    cve = cve.strip().upper()
    today = dt.date.today().isoformat()
    rec = cvelist_record(cve)
    if rec is None:
        raise SystemExit(f"{cve}: no record at cvelistV5 (typo, or not yet published)")
    text, cna, has_conf, has_work = cvelist_text(rec)
    if cna.lower() == "microsoft":
        sug = fetch_sug(cve)
        if sug and sug.get("advisory_text"):
            return {"source": "msrc", "cna": cna,
                    "source_url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                    "retrieved": today, "text": sug["advisory_text"],
                    "has_configurations": False, "has_workarounds": "Workaround" in (sug.get("article_types") or [])}
    if not text.strip():
        raise SystemExit(f"{cve}: the CVE record has no English description")
    return {"source": "cvelist", "cna": cna,
            "source_url": f"https://www.cve.org/CVERecord?id={cve}",
            "retrieved": today, "text": text,
            "has_configurations": has_conf, "has_workarounds": has_work}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("cve")
    ap.add_argument("--out", type=Path, default=Path("."), help="folder to write into (default: here)")
    a = ap.parse_args(argv)
    cve = a.cve.strip().upper()
    entry = build_entry(cve)
    a.out.mkdir(parents=True, exist_ok=True)
    (a.out / f"{cve}.advisory.txt").write_text(entry["text"], encoding="utf-8")
    (a.out / f"{cve}.input.json").write_text(json.dumps({cve: entry}, indent=2), encoding="utf-8")
    print(f"cve_id: {cve}")
    print(f"source: {entry['source']}   cna: {entry['cna']}")
    print(f"source_url: {entry['source_url']}")
    print(f"retrieved: {entry['retrieved']}")
    print(f"CNA filled `configurations`: {'yes' if entry['has_configurations'] else 'no'}")
    print("--- ADVISORY TEXT (verbatim) ---")
    print(entry["text"])
    print("--- END ---")
    print(f"wrote {a.out / (cve + '.advisory.txt')} and {a.out / (cve + '.input.json')}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
