# Build status — what is built and tested vs. designed

An architecture review panel flagged that the docs mix shipped code with
design intent, which risks a program betting on prose. This file is the
honest ledger. **Rule of thumb: code under `routing_registry/` and `tools/`
with tests is real; SQL/DDL, Power BI, and org-process content in `docs/` is
design to be implemented against your systems.**

## Built and tested (in this repo, covered by `pytest`)

| Capability | Where | Status |
|---|---|---|
| Deterministic routing engine (suppress → screen → correct → identify → unroutable) | `routing_registry/router.py` | ✅ tested |
| Two-axis identity/context model, safe-by-default (context fires only when present) | `router.py`, `models.py` | ✅ tested |
| Append-on-misroute corrections with provenance + regression fixtures | `corrections.py`, `fixtures/` | ✅ tested |
| Suppression stage: exact `cve_id`/`qid` match, verdicts, **route-time expiry**, **loader-enforced evidence** | `router.py`, `loader.py` | ✅ tested |
| CLI: `validate`, `route`, `propose-correction`, `propose-suppression` | `cli.py` | ✅ tested |
| SQL export (YAML → CSVs for the twin) | `tools/export_registry_sql.py` | ✅ tested |
| OpenVEX export (expired + QID-only excluded) | `tools/export_vex.py` | ✅ tested |
| Scanner sync plan/reconcile, **context-scoped rules held back from blanket mute** | `tools/sync_suppressions.py` | ✅ tested |
| Tier-0 enrichment (KEV/EPSS/PoC → triage band) | `tools/enrich_findings.py` | ✅ tested |

## Designed, NOT built (docs are blueprints, not running code)

| Capability | Where described | Reality |
|---|---|---|
| SQL routing view + parity gate | `docs/sql-powerbi.md` | **Markdown only** — no `.sql` asset, not run in CI. The Python↔SQL parity claim is currently unverified. |
| Power BI dashboards / DAX | `docs/sql-powerbi.md` | Design; no `.pbix`. |
| Asset entity, `first_seen`/status, `finding_assets` | `estate-blueprint.md` §7, `sql-powerbi.md` | **Not in the schema.** Worklist/currency views reference columns the exporter does not emit — they will not run as written. |
| Cross-scanner dedup / normalization / findings store | `ownership-and-sources.md` | Prose only. The engine routes in-memory, no persistence, no dedup. |
| Owner resolution (channel → team) | `ownership-and-sources.md` | Design; resolution tables not built. |
| No-code analyst surface (Power Apps, request list) | `analyst-operating-model.md` | Design pattern; no app/flow shipped. |
| Tier-1/2 verification (reachability, Nuclei/OAST wrapper) | `exploit-verification.md` | Design; only tier-0 enrichment is built. |
| Live scanner apply (Qualys/Wiz APIs) | `scanner-sync.md` | Only offline plan/reconcile is built; apply is documented, not coded. |
| RBAC / multi-tenancy / separation of duties | — | Not modeled; git merge rights are the only control today. |

## The panel's bottom line

This is a genuinely differentiated **decision/policy layer** (regression-tested
routing corrections + convergence metric, suppression-as-lease with cross-tool
reconcile, git-audited VEX authoring) — ahead of the market in those specific
mechanisms. It is **not** a standalone VM platform: dedup, asset model,
lifecycle, connectors, owner resolution, RBAC, the analyst UI, and
scale-validated queries are the ~95% that a bought execution platform
(DefectDojo / Nucleus / Seemplicity / ServiceNow VR) should provide.

**Path to success: buy the execution body, keep this as its brain.** See
`docs/architecture-review.md` for the full verdict and phased roadmap.
