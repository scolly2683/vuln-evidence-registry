#!/usr/bin/env python3
"""Print the advisory text an extractor should use for one CVE (msrc-preferred rule).

    python get_text.py CVE-2024-21413
"""
import json, pathlib, sys

HERE = pathlib.Path(__file__).parent
rows = {r["cveID"]: r for r in json.loads((HERE / "kev_sample.json").read_text())}
r = rows[sys.argv[1]]
m = r.get("msrc")
if m and m.get("advisory_text") and m.get("article_types"):
    src = "msrc"
    url = f"https://msrc.microsoft.com/update-guide/vulnerability/{r['cveID']}"
    retrieved, text = m["retrieved"], m["advisory_text"]
else:
    src = "nvd"
    url = f"https://nvd.nist.gov/vuln/detail/{r['cveID']}"
    retrieved, text = r["nvd_retrieved"], r["nvd"]["description"]
print(f"cve_id: {r['cveID']}")
print(f"vendor/product (metadata): {r['vendorProject']} / {r['product']}")
print(f"source: {src}")
print(f"source_url: {url}")
print(f"retrieved: {retrieved}")
print(f"cvss_vector (metadata, never cite): {r['nvd'].get('cvss_vector')}")
print(f"cpe (metadata): {(r['nvd'].get('cpe_sample') or [None])[0]}")
print("--- ADVISORY TEXT (verbatim) ---")
print(text)
print("--- END ---")
