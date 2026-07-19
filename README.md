# vuln-evidence-registry

Two small, dependency-free patterns for vulnerability prioritisation, extracted from a working CVE
intelligence pipeline:

1. **A declarative evidence-source registry** — one source of truth for both a SQL gate and its
   pure-Python predicate twin, so the two can never drift.
2. **A CISA BOD 26-04 remediation-timeline engine** — the directive's Table 1 encoded as code.

Pure stdlib, no external dependencies.

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

## Install & test

```bash
pip install -e ".[test]"
pytest -q
```

## License

[MIT](./LICENSE) © 2026 Donal Scollan. Independent project — not affiliated with, sponsored by, or
endorsed by CISA or any company or organization. "CISA" and "BOD 26-04" are referenced for
interoperability only.
