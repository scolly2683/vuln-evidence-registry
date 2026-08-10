# Architecture review — verdict and roadmap

A five-lens adversarial review (enterprise VM architect, ASPM competitive
analyst, exploitability engineer, data/integration architect, operating-model
skeptic) evaluated this repo against industry-leading VM/ASPM solutions at
huge-org scale, then a principal architect synthesized the verdict. This is
the record.

## Verdict: promising-but-incomplete

> A genuinely market-leading vulnerability **decision layer** bolted onto a
> data/execution/operating layer that is mostly design-doc. It can make a
> huge org's VM program world-class **as a component**, but cannot be the
> platform the org gets on top of its estate with.

**Straight answer to "will this let a huge org get on top of VM?"** Not on
its own; yes as part of a pair. Deploy it *as the platform* and the program
fails — ~5% of the needed surface is built. Deploy it *as the decision brain
on top of a bought execution platform* and the org lands in a differentiated
position most never reach. **The decision that determines success is made
before the code: buy the body, keep this as the brain.**

## Where it genuinely leads the market

- **Regression-tested routing corrections with a convergence metric.** No
  ASPM/RemOps product applies detection-as-code discipline (frozen fixture
  per decision, CI replay, `unroutable_pct` over time) to routing/triage.
- **Two-axis identity × context, safe-by-default.** Same CVE → different
  homes by deployment context; un-enriched findings fall to the identity
  default rather than being mis-suppressed.
- **Suppression-as-lease with cross-tool reconcile-back.** Group-level,
  git-audited, evidence-and-expiry-mandatory, and it flags tool-side
  suppressions with no registry rule as unmanaged risk acceptance.
- **Git-audited OpenVEX authoring** from the suppression ledger.

## Where it is behind (table-stakes the incumbents ship)

Cross-scanner dedup/normalization; an asset entity and finding lifecycle
(state, first_seen, MTTR, reopen); owner resolution; scale-validated queries
(the SQL view is a dev toy at millions of rows); RBAC/multi-tenancy; and the
no-code analyst UI. All are prose or design here; see `STATUS.md`.

## Correctness holes found in shipped code — FIXED in this branch

The review verified four real defects; all are now fixed and tested:

1. **Route-time expiry** — the router ignored `review_by`, so an expired
   suppression kept hiding findings from the analyst queue. Now expired
   leases are skipped at route time and the finding resurfaces.
   (`router.py`, `test_expired_suppression_stops_silencing_and_resurfaces`)
2. **Loader-enforced evidence** — evidence was required only in the CLI, so a
   hand-appended suppression without it passed CI. Now the loader rejects it.
   (`loader.py`, `test_loader_rejects_incomplete_suppression[evidence]`)
3. **Context-conditional over-suppression** — the scanner sync turned a
   config-conditional verdict into a blanket estate-wide CVE mute, which could
   hide genuinely exploitable instances. Context-bearing suppressions are now
   held out of blanket sync and surfaced for scoped handling.
   (`sync_suppressions.py`, `test_context_bearing_suppression_is_not_blanket_synced`)
4. **Brittle QID parser** — a bare `\d{5,7}` regex matched asset ids/ports.
   The reconciler now prefers a real QID column and only falls back to regex.
   (`sync_suppressions.py`, `test_parse_actual_qualys_uses_qid_column_when_present`)

## Roadmap to close the gap

### Phase 0 — decide the architecture, stop the bleeding (weeks, cheap)
- **Program decision (buy/integrate):** select the execution platform
  (ServiceNow VR if the org runs ServiceNow, else DefectDojo/Nucleus/
  Seemplicity). This repo is the decision layer on top, not the system of record.
- ✅ Correctness fixes 1–4 above — **done in this branch.**
- ✅ Honest built-vs-designed labelling — **`STATUS.md`, this branch.**
- **Build (cheap, highest leverage):** make the routing parity gate real —
  check in the SQL view as a tested `.sql` asset (or generate it from the
  registry) and run every fixture through both engines in CI.

### Phase 1 — give the decision layer a body (1–2 quarters)
- Integrate the bought platform's dedup, normalization, connectors, CMDB
  asset inventory, and finding lifecycle; feed routing/suppression decisions
  back via API.
- Add `asset_id`, `first_seen`/`last_seen`, `status` to the finding contract;
  make `(cve, asset)` the identity key with runtime>artifact>manifest
  precedence and PURL canonicalization.
- Replace the generic SQL view with candidate-narrowing on indexed
  exact/prefix keys + a per-batch materialized routing_results table;
  benchmark at 5–10M findings.
- Routing-correctness telemetry: per-rule hit counts, overlap/shadow
  detection, sampled precision audit on keyword rules.
- Resolve channel→owner via CMDB/directory for distributed ownership.

### Phase 2 — runnable as a program at scale (2–3 quarters)
- Front analysts with the platform's workbench + RBAC + approval chains;
  generate `propose-*` YAML directly from form fields so the maintainer batch
  becomes an approval gate on machine-generated diffs.
- Enforce separation of duties (proposer ≠ approver); elevated sign-off to
  suppress KEV/act-now; bound approver identity.
- Ship tier-1 context/reachability enricher (or integrate a vendor / the
  Neo4j SBOM graph); add a QID→CVE bridge; staleness checks on KEV/EPSS.
- Make `review_by` hygiene active: expired leases escalate to an assigned
  worklist, not warn-only.
- Program instrumentation: request-list backlog/age, merge latency vs SLA,
  enrichment-coverage %, MTTR/SLA per channel, suppressed-then-exploited
  alarm wired to KEV — charted next to `unroutable_pct`.

### Phase 3 — prove and harden (ongoing)
- Run 3–6 months of a real estate through the loop; publish the convergence
  curve (today the flagship claim rests on a 28-CVE backtest).
- Scope rules by BU/region for multi-tenancy and regulatory boundaries.
- Rule-lifecycle tooling: dead-rule detection, static overlap/shadow linter
  in `validate`, fixture-pruning policy.
- Live bi-directional scanner sync (auth, pagination, backoff, apply).

## Why the review is trustworthy

Five independent expert lenses read the actual code and docs (137 tool calls,
grounded in file citations), disagreed explicitly (verdicts ranged
"not-yet-a-solution" to "competitive"), and the synthesis resolved the split
by separating the two jobs — "be the platform" (behind) vs "be the decision
layer on a platform" (ahead). The repo's own docs already concede the
buy-don't-build conclusion; this review confirms it and prices it.
