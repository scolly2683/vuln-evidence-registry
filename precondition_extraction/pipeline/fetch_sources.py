#!/usr/bin/env python3
"""Build the extraction input set for a CVE list: one advisory text per CVE, chosen by the
source ladder (evaluation/README.md, "Scaling past the sample").

    python fetch_sources.py --kev            # every CVE in the CISA KEV feed
    python fetch_sources.py CVE-2026-0257 …  # specific ids

Rung order per CVE:
  1. Microsoft → MSRC Security Update Guide (title + FAQ, HTML stripped)      source: msrc
  2. CNA record (cvelistV5): description + `configurations` + `workarounds`
     containers when present, each under a labelled heading                  source: cvelist
  (rung 3, vendor advisory pages, is not built yet; rung 4 is rung 2's description.)

Writes data/inputs.json: {cve: {source, source_url, retrieved, text, cna, has_configurations,
has_workarounds, kev_vendor, kev_product, kev_date_added}}. Idempotent: existing entries are
kept unless --refresh. Text is stored exactly as the extractor will see it, so a citation is
re-checkable against this file forever.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import pathlib
import re
import sys
import time
import urllib.error
import urllib.request

HERE = pathlib.Path(__file__).parent
DATA = HERE / "data"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
RAW = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{y}/{prefix}xxx/{cve}.json"

sys.path.insert(0, str(HERE.parent / "evaluation"))
from fetch_msrc import fetch as fetch_sug, strip_html  # noqa: E402


def get_json(url: str, tries: int = 3, timeout: int = 60):
    for i in range(tries):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers={"Accept": "application/json"}), timeout=timeout) as r:
                return json.load(r)
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                return None
            time.sleep(3 * (i + 1))
        except Exception:
            time.sleep(3 * (i + 1))
    return None


def cvelist_record(cve: str):
    y, n = cve.split("-")[1], cve.split("-")[2]
    return get_json(RAW.format(y=y, prefix=n[:-3], cve=cve))


def english(items) -> list[str]:
    out = []
    for it in items or []:
        if isinstance(it, dict) and str(it.get("lang", "en")).lower().startswith("en") and it.get("value"):
            out.append(str(it["value"]).strip())
    return out


def cvelist_text(rec: dict) -> tuple[str, str, bool, bool]:
    cna = rec.get("containers", {}).get("cna", {})
    parts = english(cna.get("descriptions"))
    conf = english(cna.get("configurations"))
    work = english(cna.get("workarounds"))
    text = "\n\n".join(parts)
    if conf:
        text += "\n\nConfigurations (stated by the CNA):\n" + "\n\n".join(conf)
    if work:
        text += "\n\nWorkarounds (stated by the CNA):\n" + "\n\n".join(work)
    short = (cna.get("providerMetadata") or {}).get("shortName", "")
    return text, short, bool(conf), bool(work)


def build(cves: list[dict], refresh: bool) -> dict:
    DATA.mkdir(exist_ok=True)
    out_path = DATA / "inputs.json"
    out = json.loads(out_path.read_text()) if out_path.exists() and not refresh else {}
    today = dt.date.today().isoformat()
    for i, row in enumerate(cves, 1):
        cve = row["cveID"]
        if cve in out:
            continue
        entry = {"kev_vendor": row.get("vendorProject"), "kev_product": row.get("product"),
                 "kev_date_added": row.get("dateAdded"), "retrieved": today}
        text = None
        if (row.get("vendorProject") or "").lower() == "microsoft":
            sug = fetch_sug(cve)
            if sug and sug.get("articles"):
                parts = [sug.get("cveTitle") or ""]
                types = []
                for a in sug["articles"]:
                    body = strip_html(a.get("description") or "")
                    if body:
                        types.append(a.get("articleType") or "?")
                        parts.append(body)
                if types:
                    text = "\n\n".join(p for p in parts if p)
                    entry.update(source="msrc", source_url=f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
                                 cna="microsoft", has_configurations=False, has_workarounds="Workaround" in types)
        if text is None:
            rec = cvelist_record(cve)
            if rec:
                text, short, has_conf, has_work = cvelist_text(rec)
                entry.update(source="cvelist", source_url=f"https://www.cve.org/CVERecord?id={cve}",
                             cna=short, has_configurations=has_conf, has_workarounds=has_work)
        if not text:
            entry.update(source=None, text=None, error="no text from any rung")
        else:
            entry["text"] = text
            entry["sha256"] = hashlib.sha256(text.encode("utf-8")).hexdigest()
        out[cve] = entry
        if i % 25 == 0 or i == len(cves):
            out_path.write_text(json.dumps(out, indent=1, ensure_ascii=False))
            print(f"{i}/{len(cves)}", flush=True)
        time.sleep(0.2)
    out_path.write_text(json.dumps(out, indent=1, ensure_ascii=False))
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cves", nargs="*")
    ap.add_argument("--kev", action="store_true")
    ap.add_argument("--refresh", action="store_true")
    a = ap.parse_args()
    if a.kev:
        rows = get_json(KEV_URL)["vulnerabilities"]
    else:
        rows = [{"cveID": c} for c in a.cves]
    out = build(rows, a.refresh)
    n = len(out); ok = sum(1 for v in out.values() if v.get("text"))
    print(f"inputs: {n} CVEs, {ok} with text; sources:",
          {s: sum(1 for v in out.values() if v.get("source") == s) for s in ("msrc", "cvelist", None)})
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
