#!/usr/bin/env python3
"""Tabulate the 50-CVE precondition sample and estimate the collapse rate.

Reads ``records/<CVE>.yaml`` (written by ``run_extraction.py``) and prints:

1. Per-CVE: stratum, precondition count, categories, empty-list reading.
2. Per-category counts across the sample.
3. Coarse *control families* — a regex bucketing of precondition statements into
   the handful of controls a defender could actually apply. **This is the number the
   experiment exists to produce**, and it is only a first pass: a human must read the
   ``unbucketed`` list and decide whether the families hold. The script deliberately
   does not let an LLM do that merge — that would bias the very question being asked.

Usage:  python analyse.py            # prints + writes analysis.md
No dependencies beyond PyYAML (backend/requirements-dev.txt).
"""

from __future__ import annotations

import collections
import json
import pathlib
import re
import sys

import yaml

HERE = pathlib.Path(__file__).parent
RECORDS = HERE / "reference"

# Order matters: first match wins. These are the six families from the 2026-09-01
# manual merge (README → Result), encoded so re-runs on other models land in the
# same buckets. They are a reading aid, not a taxonomy — check the statements.
FAMILIES: list[tuple[str, re.Pattern]] = [
    ("default-credentials", re.compile(r"default (administrator |admin )?password|default credentials", re.I)),
    ("outbound-egress-to-attacker", re.compile(
        r"reach (out|an attacker|a remote)|attacker[- ](controlled|hosted) (ldap|server|host|spring|jndi)|"
        r"load(s|ing)? (code|a remote|remote)|outbound|egress|\bjndi\b", re.I)),
    ("attacker-already-has-access", re.compile(
        r"\balready\b|authenticated|\bholds?\b|\bhold(ing)?\b|credentials|community string|"
        r"local (user|access|attacker)|local to the device|privileged user|high privileges|"
        r"administrative access|admin(istrator)? (account|access)|\bshell\b|obtained|compromised|"
        r"user session|unprivileged|can create a .* socket", re.I)),
    ("attacker-controlled-input-processed", re.compile(
        r"crafted (document|web site|excel|file|email|image)|process(es)? a crafted|"
        r"attacker[- ]controlled (input|web site|log|content|link)|logs? messages|"
        r"supply the routing|from attacker-controlled|able to supply|loads? an attacker|"
        r"open(s|ing)? (a |the )?(file|document|attachment)|preview pane|user (must )?(open|click)", re.I)),
    ("platform-or-deployment-model", re.compile(
        r"ios xe|pa-series|vm-series|self-hosted|filesystem locations|\bplatform\b|"
        r"(32|64)-bit|\bx86|\barm\b", re.I)),
    ("management-plane-reachable", re.compile(
        r"jenkins cli|jolokia|web console|grafana|vcenter|validate endpoint|langflow|"
        r"admin(istration|istrative)? (interface|console|portal)|management (interface|plane|port)", re.I)),
    ("remote-access-portal-exposed", re.compile(
        r"globalprotect|captive portal|authentication portal|ssl vpn|\bvpn\b|work place|"
        r"access policy|\bgateway\b|aaa virtual|saml identity provider|\bidp\b|virtual server|"
        r"remote access", re.I)),
    ("optional-feature-or-component-enabled", re.compile(
        r"\benabled\b|configured|in use|installed|deployed|uses the|using the|is using|running the|"
        r"transport|parser|plug-in|plugin|interceptor|mod_rewrite|rewriterule|package|component|"
        r"routing functionality|notifications|setting", re.I)),
    ("other-listener-reachable", re.compile(
        r"\breach\b|send (snmp|smtp|packets|http|traffic|requests)|network access|can send|"
        r"http requests|serialized|over (a |the )?network|remote(ly)?", re.I)),
]


def bucket(statement: str) -> str:
    for name, rx in FAMILIES:
        if rx.search(statement or ""):
            return name
    return "UNBUCKETED"


def load() -> list[dict]:
    rows = []
    sample = {r["cveID"]: r for r in json.loads((HERE / "kev_sample.json").read_text())}
    for p in sorted(RECORDS.glob("*.yaml")):
        try:
            rec = yaml.safe_load(p.read_text()) or {}
        except yaml.YAMLError as exc:  # keep going — one bad record must not hide 49 good ones
            print(f"!! {p.name}: YAML parse failed: {exc}", file=sys.stderr)
            continue
        cve = p.stem
        meta = sample.get(cve, {})
        exp = rec.get("expected", rec)  # tolerate records that omit the `expected:` wrapper
        pcs = exp.get("preconditions") or []
        rows.append({
            "cve": cve,
            "stratum": meta.get("stratum", "?"),
            "product": f"{meta.get('vendorProject', '?')} / {meta.get('product', '?')}",
            "n": len(pcs),
            "cats": sorted({(pc.get("category") or "?") for pc in pcs}),
            "pcs": pcs,
            "notes": (exp.get("notes") or rec.get("notes") or "") if isinstance(exp.get("notes", ""), str) else str(exp.get("notes")),
        })
    return rows


def main() -> int:
    rows = load()
    if not rows:
        print("no records found in", RECORDS)
        return 1
    out: list[str] = []
    w = out.append

    w(f"# Precondition sample — analysis ({len(rows)} records)\n")
    w("## Per CVE\n")
    w("| CVE | stratum | product | #pre | categories | empty-list reading |")
    w("|---|---|---|---|---|---|")
    empties = 0
    for r in rows:
        reading = ""
        if r["n"] == 0:
            empties += 1
            n = r["notes"].lower()
            if "nothing gates" in n or "affected version is enough" in n:
                reading = "nothing gates it"
            elif "states no precondition" in n or "text states no" in n:
                reading = "text states none"
            else:
                reading = "⚠ not stated"
        w(f"| {r['cve']} | {r['stratum']} | {r['product']} | {r['n']} | {', '.join(r['cats'])} | {reading} |")

    cat_counts = collections.Counter(pc.get("category") or "?" for r in rows for pc in r["pcs"])
    w("\n## Per category\n")
    for cat, n in cat_counts.most_common():
        w(f"- **{cat}**: {n}")
    w(f"- empty precondition lists: **{empties}/{len(rows)}**")

    fam = collections.defaultdict(list)
    for r in rows:
        for pc in r["pcs"]:
            fam[bucket(pc.get("statement", ""))].append((r["cve"], r["stratum"], pc.get("id"), pc.get("statement")))

    total_pcs = sum(len(v) for v in fam.values())
    w("\n## Control families (regex first pass — a human confirms the merge)\n")
    w(f"{total_pcs} preconditions across {len(rows)} CVEs fell into "
      f"**{len([k for k in fam if k != 'UNBUCKETED'])} families** "
      f"+ {len(fam.get('UNBUCKETED', []))} unbucketed.\n")
    w("| family | #pre | #CVEs | edge | microsoft | oss |")
    w("|---|---|---|---|---|---|")
    for name, items in sorted(fam.items(), key=lambda kv: -len(kv[1])):
        cves = {c for c, *_ in items}
        strata = collections.Counter(s for _, s, *_ in items)
        w(f"| {name} | {len(items)} | {len(cves)} | {strata.get('edge', 0)} | {strata.get('microsoft', 0)} | {strata.get('oss', 0)} |")

    w("\n### Statements per family (read these — the regex is a hint, not a verdict)\n")
    for name, items in sorted(fam.items(), key=lambda kv: -len(kv[1])):
        w(f"\n**{name}**\n")
        for cve, stratum, pid, stmt in items:
            w(f"- `{cve}` ({stratum}) `{pid}` — {stmt}")

    w("\n## How to read the result\n")
    w("- **Collapse holds** if ≥80% of *network-reachability* + *configuration* preconditions land in "
      "≤10 families after your manual merge, and the families are things a defender can actually "
      "apply (segment the admin plane, egress-filter, disable feature X) — not restatements of the CVE.")
    w("- **Collapse fails** if the unbucketed list stays long after merging, or if the families are "
      "product-specific ('Ivanti ICS web component reachable') rather than cross-product.")
    w("- Either way, note the empty-list count: KEV CVEs whose advisory text states *no* gate are "
      "the 'an affected version is enough' population — the ledger cannot help with those, only patching can.")

    text = "\n".join(out) + "\n"
    (HERE / "analysis.md").write_text(text)
    print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
