#!/usr/bin/env python3
"""Attach MSRC Security Update Guide text to the Microsoft rows of sample50.json.

NVD descriptions for MSRC-assigned CVEs are title-only, so the NVD-sourced
records are empty by rule 2. The gating text lives in MSRC's per-CVE record:
``GET https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/{CVE}``
(no auth) whose ``articles[]`` hold the FAQ ("Is the Preview Pane an attack
vector?"), Executive Summary and similar notes as HTML.

This writes ``row["msrc"]`` = {release, retrieved, exploited, publicly_disclosed,
article_types, advisory_text} where advisory_text is the title + each article's
text with HTML stripped (block tags -> newlines, entities unescaped, whitespace
collapsed). The stripped text is what the extractor cites against — the record
says so in its ``source`` field. Idempotent; re-run to refresh.
"""

from __future__ import annotations

import datetime as dt
import html
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).parent
SAMPLE = HERE / "sample50.json"
SUG = "https://api.msrc.microsoft.com/sug/v2.0/en-US/vulnerability/"

_BLOCK = re.compile(r"</?(p|div|li|ul|ol|tr|table|thead|tbody|br|h[1-6])\b[^>]*>", re.I)
_CELL = re.compile(r"</?(td|th)\b[^>]*>", re.I)
_TAG = re.compile(r"<[^>]+>")


def strip_html(s: str) -> str:
    s = _BLOCK.sub("\n", s)
    s = _CELL.sub(" | ", s)
    s = _TAG.sub("", s)
    s = html.unescape(s).replace("\xa0", " ")
    lines = [re.sub(r"[ \t]+", " ", ln).strip(" |") for ln in s.splitlines()]
    return "\n".join(ln for ln in lines if ln)


def fetch(cve: str) -> dict | None:
    req = urllib.request.Request(SUG + cve, headers={"Accept": "application/json"})
    for attempt in range(3):
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            print(f"  {cve}: HTTP {exc.code}, retry", file=sys.stderr)
        except Exception as exc:  # network blip — retry
            print(f"  {cve}: {exc}, retry", file=sys.stderr)
        time.sleep(5 * (attempt + 1))
    return None


def main() -> int:
    rows = json.loads(SAMPLE.read_text())
    today = dt.date.today().isoformat()
    n = 0
    for row in rows:
        if row["vendorProject"] != "Microsoft":
            continue
        cve = row["cveID"]
        rec = fetch(cve)
        if not rec:
            row["msrc"] = None
            print(f"{cve}: not in SUG")
            continue
        parts = [rec.get("cveTitle") or ""]
        types = []
        for a in rec.get("articles") or []:
            t = a.get("articleType") or "?"
            body = strip_html(a.get("description") or "")
            if body:
                types.append(t)
                parts.append(body)
        text = "\n\n".join(p for p in parts if p)
        row["msrc"] = {
            "release": rec.get("releaseNumber"),
            "retrieved": today,
            "exploited": rec.get("exploited"),
            "publicly_disclosed": rec.get("publiclyDisclosed"),
            "article_types": types,
            "advisory_text": text,
        }
        n += 1
        print(f"{cve}: {rec.get('releaseNumber')} articles={types} chars={len(text)}")
        time.sleep(1)
    SAMPLE.write_text(json.dumps(rows, indent=1, ensure_ascii=False))
    print(f"wrote msrc text for {n} rows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
