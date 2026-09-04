#!/usr/bin/env python3
"""Draw the held-out evaluation set and freeze the rules it will be scored under.

    python3 draw.py            # writes sample.json + RULES_FROZEN.json, prints the table

Why this exists: every number the standard carried before this was a *training* score.
Rules 8-10 were adopted because of failures on the 50 reference records, and the reference
was then rewritten to match them. This draws 30 KEV CVEs the rules were never tuned on, by
the same stratification as the original 50 (`../select_sample.py`), excluding

  - the 50 reference IDs (the development set), and
  - the 170 in `pipeline/data/slice_edge_2023plus.json` (the extractor has already produced
    output for those, and a reference builder could peek).

Source is `pipeline/data/inputs.json`, which already holds advisory text, source and KEV
metadata for all 1,694 KEV CVEs, so this needs no network.

`RULES_FROZEN.json` records sha256(PROMPT.md) + the git SHA at the draw. `tests/test_heldout.py`
asserts PROMPT.md still matches — a rule edit after the draw fails loudly, because the
held-out number is only valid for the rules it was scored under.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import json
import pathlib
import re
import subprocess

HERE = pathlib.Path(__file__).parent
EVAL = HERE.parent
ROOT = EVAL.parent.parent
INPUTS = ROOT / "precondition_extraction" / "pipeline" / "data" / "inputs.json"
SLICE = ROOT / "precondition_extraction" / "pipeline" / "data" / "slice_edge_2023plus.json"
REFERENCE = EVAL / "reference"
PROMPT = EVAL / "PROMPT.md"

# Same stratum specs as select_sample.py, same most-recent-first order. Sizes are the
# 20/15/15 proportions scaled to 30. The first OWNER_PER_STRATUM of each stratum are the
# owner's blind-annotation set (15 total).
SIZES = {"edge": 12, "microsoft": 9, "oss": 9}
OWNER_PER_STRATUM = 5

EDGE = [
    ("fortios", "Fortinet", "FortiOS$"), ("fortios-2", "Fortinet", "FortiOS$"),
    ("panos", "Palo Alto", "PAN-OS"), ("panos-2", "Palo Alto", "PAN-OS"),
    ("ivanti-ics", "Ivanti", "Connect Secure"), ("ivanti-epmm", "Ivanti", "EPMM"),
    ("citrix", "Citrix", "NetScaler"), ("citrix-2", "Citrix", "NetScaler"),
    ("cisco-asa", "Cisco", "ASA"), ("cisco-iosxe", "Cisco", "IOS and IOS XE"),
    ("juniper", "Juniper", "Junos"), ("sonicwall", "SonicWall", "."),
    ("f5", "F5", "BIG-IP"), ("exchange", "Microsoft", "Exchange Server"),
    ("zimbra", "Synacor", "Zimbra"), ("manageengine", "Zoho", "ManageEngine"),
    ("sap", "SAP", "NetWeaver"), ("coldfusion", "Adobe", "ColdFusion"),
    ("weblogic", "Oracle", "WebLogic"), ("vcenter", "VMware", "vCenter"),
    ("moveit", "Progress", "MOVEit"), ("confluence", "Atlassian", "Confluence"),
]
MICROSOFT = [
    ("win-smb", "Microsoft", "^Windows$"), ("office", "Microsoft", "^Office$"),
    ("sharepoint", "Microsoft", "SharePoint"), ("win32k", "Microsoft", "Win32k"),
    ("defender", "Microsoft", "Defender"), ("outlook", "Microsoft", "Outlook"),
    ("hyperv", "Microsoft", "Hyper-V"), ("spooler", "Microsoft", "Print Spooler|Windows Print"),
    ("mshtml", "Microsoft", "MSHTML|Internet Explorer"), ("word", "Microsoft", "Word"),
    ("excel", "Microsoft", "Excel"), ("sql", "Microsoft", "SQL Server"),
    ("ntlm", "Microsoft", "Windows$"), ("kerberos", "Microsoft", "Windows$"),
    ("edge", "Microsoft", "Edge"), ("access", "Microsoft", "Access"),
]
OSS = [
    ("log4j", "Apache", "Log4j"), ("kernel", "Linux", "Kernel"), ("kernel-2", "Linux", "Kernel"),
    ("tomcat", "Apache", "Tomcat"), ("struts", "Apache", "Struts"), ("httpd", "Apache", "HTTP Server"),
    ("activemq", "Apache", "ActiveMQ"), ("ofbiz", "Apache", "OFBiz"), ("spring", "VMware|Spring", "Spring"),
    ("jenkins", "Jenkins", "."), ("langflow", "Langflow", "."), ("php", "PHP", "."),
    ("gitlab", "GitLab", "."), ("openssh", "OpenBSD|OpenSSH", "OpenSSH"), ("roundcube", "Roundcube", "."),
    ("nextjs", "Vercel", "Next"), ("django", "Django", "."), ("grafana", "Grafana", "."),
    ("git", "Git", "^Git$"),
]


def pick(rows: list[dict], stratum: str, rules, n: int, seen: set[str]) -> list[dict]:
    """select_sample.py's pick(), with the exclusion set threaded through."""
    out: list[dict] = []
    for label, vend, prod in rules:
        for x in rows:
            if prod.endswith("Windows$") and int(x["cve_id"][4:8]) < 2020:
                continue
            if (re.search(vend, x["kev_vendor"] or "", re.I)
                    and re.search(prod, x["kev_product"] or "", re.I)
                    and x["cve_id"] not in seen):
                out.append(dict(x, stratum=stratum, slot=label))
                seen.add(x["cve_id"])
                break
        if len(out) >= n:
            break
    return out[:n]


def main() -> int:
    inputs = json.loads(INPUTS.read_text(encoding="utf-8"))
    rows = [
        {"cve_id": c, "kev_vendor": v.get("kev_vendor"), "kev_product": v.get("kev_product"),
         "kev_date_added": v.get("kev_date_added"), "source": v.get("source")}
        for c, v in inputs.items() if v.get("text")
    ]
    rows.sort(key=lambda x: x["kev_date_added"] or "", reverse=True)

    seen = {p.stem for p in REFERENCE.glob("CVE-*.yaml")}
    n_ref = len(seen)
    seen |= set(json.loads(SLICE.read_text()))
    print(f"excluding {n_ref} reference + {len(seen) - n_ref} edge-slice IDs")

    edge = pick(rows, "edge", EDGE, SIZES["edge"], seen)
    ms = pick(rows, "microsoft", MICROSOFT, SIZES["microsoft"], seen)
    # The '^Windows$' slots collide on dedupe; backfill with next-most-recent Windows entries.
    for x in rows:
        if len(ms) >= SIZES["microsoft"]:
            break
        if (x["kev_vendor"] == "Microsoft" and x["kev_product"] == "Windows"
                and int(x["cve_id"][4:8]) >= 2020 and x["cve_id"] not in seen):
            ms.append(dict(x, stratum="microsoft", slot="win-fill"))
            seen.add(x["cve_id"])
    oss = pick(rows, "oss", OSS, SIZES["oss"], seen)

    sample = []
    for stratum, xs in (("edge", edge), ("microsoft", ms), ("oss", oss)):
        print(f"== {stratum} ({len(xs)} / {SIZES[stratum]})")
        for i, x in enumerate(xs):
            x["owner"] = i < OWNER_PER_STRATUM
            mark = "OWNER" if x["owner"] else "     "
            print(f"  {mark} {x['cve_id']:<16} {x['kev_date_added']}  {x['kev_vendor']} / {x['kev_product']}  [{x['slot']}]  {x['source']}")
            sample.append({k: x[k] for k in ("cve_id", "stratum", "slot", "owner", "kev_vendor",
                                             "kev_product", "kev_date_added", "source")})
    short = [s for s in SIZES if sum(1 for x in sample if x["stratum"] == s) < SIZES[s]]
    if short:
        raise SystemExit(f"error: stratum short of its size: {short} — widen the rule list")
    ids = [x["cve_id"] for x in sample]
    assert len(ids) == len(set(ids)) == sum(SIZES.values())

    (HERE / "sample.json").write_text(json.dumps(sample, indent=1), encoding="utf-8")

    prompt_sha = hashlib.sha256(PROMPT.read_bytes()).hexdigest()
    try:
        git_sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout.strip()
    except Exception:
        git_sha = None
    frozen = {
        "frozen_at": dt.date.today().isoformat(),
        "git_sha": git_sha,
        "prompt_md_sha256": prompt_sha,
        "sample_size": len(sample),
        "owner_records": sum(1 for x in sample if x["owner"]),
        "note": "The held-out number is valid only for the PROMPT.md with this sha256. "
                "A rule change means a new draw, not a re-score.",
    }
    (HERE / "RULES_FROZEN.json").write_text(json.dumps(frozen, indent=1), encoding="utf-8")
    print(f"\nwrote sample.json ({len(sample)}) and RULES_FROZEN.json (PROMPT.md {prompt_sha[:12]}…)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
