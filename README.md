# vuln-evidence-registry

Three small patterns for vulnerability prioritisation and routing, extracted from a working CVE
intelligence pipeline:

1. **A declarative evidence-source registry** — one source of truth for both a SQL gate and its
   pure-Python predicate twin, so the two can never drift.
2. **A CISA BOD 26-04 remediation-timeline engine** — the directive's Table 1 encoded as code.
3. **A learning routing registry** — deterministic fix-channel routing that accretes rules from
   observed misroutes, with git as the review/audit layer and regression fixtures as an anti-decay
   CI gate.

Patterns 1–2 are pure stdlib. Pattern 3 adds one dependency (PyYAML) — its rule files are
append-only YAML because comments, human-readable diffs, and `git blame` are part of the design.

## 1. The evidence-source registry

A recurring bug in prioritisation pipelines: the same "is this signal high-priority?" decision is
hand-wired twice — once as **SQL** (to gate the whole corpus in one query) and once as a **Python
predicate** (to evaluate a single record in memory). They drift. Worse, a new evidence source gets
ingested into a table but someone forgets to add it to the gate SQL, so it's *stored but never gates
anything*.

This makes one registry the single source of truth for both. Each `EvidenceSource` carries a SQL
fragment **and** its Python-predicate twin; the gate SQL and the in-memory evaluator are both *composed*
from the registry:

```python
from vuln_evidence_registry import EvidenceContext, evaluate_gate, gate_union_sql

# In-memory decision (e.g. on a freshly-ingested record):
evaluate_gate(EvidenceContext(in_kev=True))                      # True
evaluate_gate(EvidenceContext(epss_score=0.2))                   # True  (>= 0.10 gate)
evaluate_gate(EvidenceContext(ssvc_automatable="yes"))           # False (needs total impact too)

# The exact same rules, composed into one SQL gate over the whole corpus:
print(gate_union_sql(scoped=False))
#   SELECT DISTINCT cve_id FROM kev_entries WHERE TRUE
#   UNION
#   SELECT id AS cve_id FROM cves WHERE vulncheck_kev = TRUE
#   UNION
#   ... one leg per registry entry ...
```

Add a source once and it flows into the gate SQL, the Python twin, and the "act now" escalation set at
the same time — there is no second place to update. `act_now_union_sql()` composes a strict subset (the
*known-exploited* legs only): a public PoC or a high EPSS score gates enrichment but is deliberately not
"act now," which keeps high-impact-but-never-targeted items out of an urgent queue.

The SQL fragments reference example table/column names to keep the demo concrete — adapt them to your
schema. The *pattern* (one registry → two composed outputs) is the point.

## 2. BOD 26-04 remediation-timeline engine

[CISA BOD 26-04](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk)
(issued 2026-06-10) sets remediation deadlines as a function of four booleans: publicly exposed, in KEV,
automatable, and total technical impact. `bod_26_04.py` encodes its Table 1 verbatim and composes a full
assessment for a CVE — computing **both** the exposed and internal branches, since exposure is
asset-level and org-specific:

```python
from vuln_evidence_registry import assess, remediation_timeline

remediation_timeline(in_kev=True, automatable=True, total_impact=True, publicly_exposed=True)
# (3, True)  → 3-day fix + forensic triage

assess(
    in_kev=True, ssvc_exploitation="active",
    ssvc_automatable="yes", ssvc_technical_impact="total",
)
# {'source': 'cisa_adp', 'exploitation': 'active',
#  'exposed':  {'days': 3, 'forensic_triage': True},    # Table 1 row 1
#  'internal': {'days': 3, 'forensic_triage': True}, ...} # Table 1 row 9
```

`assess()` uses authoritative SSVC decision points when supplied, falls back to a CVSS-vector heuristic
otherwise, and worst-cases (never under-triages) when neither is available — flagging which happened via
a `source` field. A common implementation mistake the tests pin down: an exposed KEV entry is **always**
3 or 14 days, never 60-day or fix-on-upgrade.

## 3. The learning routing registry

Bulk vulnerability management is a routing problem before it is a scoring problem: in a measured
month (July 2026), 9,919 CVEs were published, 21% screened out instantly, and 57% collapsed into
**ten** grouped fix-channel records — Patch Tuesday, Oracle CPU, distro errata, dependency bumps —
that ship on a schedule whether or not anyone predicted exploitability. The remaining 22% is the
real analyst queue.

The routing registry routes findings along **two axes** and *learns* from its mistakes:

- **Identity** (per-CVE): what software is this? CNA, vendor, package, purl, keywords —
  advisory-first, because 67% of that month's CVEs had no CPE data at NVD at disclosure time.
- **Context** (per-finding): how is this instance deployed *here*? The same Tomcat CVE routes to
  the base-image rebuild cycle (`image_layer: base`), the app team's dependency lane
  (`image_layer: app`), or the middleware lane (no context) — one CVE, three homes.

When routing is wrong — a product turns out not to be in the central patch bundle, a package turns
out to be app-layer-installed — the correction is **appended as data** with mandatory provenance,
and the triggering finding becomes a permanent regression fixture:

```bash
python -m routing_registry route --registry registry \
    --findings examples/findings.sample.jsonl --stats

python -m routing_registry propose-correction --registry registry \
    --route euc-user-installed \
    --match vendor=microsoft --match "keywords=visual studio" \
    --context bundle_member=false \
    --decided-by you --trigger "survived 2 central patch cycles" \
    --review-by 2027-02-01 --fixture-finding finding.json
```

The correction lands as a reviewable git diff; `git blame` on `registry/rules/corrections.yaml` is
the provenance trail; CI replays every past fixture so learned routing can never silently decay.
The metric that proves it works is `unroutable_pct`, run over run — if the registry is learning,
it falls.

Docs: [module overview](docs/routing-registry.md) · [15-minute tutorial](docs/tutorial.md) ·
[schema reference](docs/schema-reference.md) · [design rationale](docs/design.md) ·
[bringing it into your organisation](docs/workplace-translation.md)

## Install & test

```bash
pip install -e ".[test,routing]"   # routing extra = PyYAML, for pattern 3
pytest -q
python -m routing_registry validate --registry registry
```

## License

[MIT](./LICENSE) © 2026 Donal Scollan. Independent project — not affiliated with, sponsored by, or
endorsed by CISA or any company or organization. "CISA" and "BOD 26-04" are referenced for
interoperability only.
