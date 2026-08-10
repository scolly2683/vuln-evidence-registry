# Design rationale

Why the engine is shaped the way it is — each decision with the alternative
it rejected and why. Read this before proposing structural changes; change
it when a decision is deliberately reversed.

## D1. Two axes, not one

**Decision:** routing is identity (per-CVE: what software) × context
(per-finding: how deployed here). Corrections are context rules; identity
rules are defaults.

**Rejected:** per-CVE routing alone — the model most feeds and tools imply.

A CVE-keyed router cannot express the facts that actually decide ownership:
the same Tomcat CVE is the platform team's problem in a golden base image,
the app team's problem in an app-layer Dockerfile install, and the
middleware lane's problem on a bare host. Deployment context is per-finding
by nature, so the routing decision must be too. The "hundreds of variables"
(build vs image vs package vs dependency vs endpoint-packaged vs Mac
software…) all collapse into values of one context object rather than new
mechanisms.

## D2. Deterministic rules, no ML

**Decision:** first-match rule evaluation over ordered YAML. The learning
is in the *accumulated data*, not in a model.

**Rejected:** classifier/embedding-based routing.

Routing decisions feed ticket assignment and SLA clocks — they must be
explainable ("rule X, appended on date Y, by person Z, because trigger T")
and reproducible (same input, same route, forever). A model gives neither,
and drifts silently — precisely the failure this registry exists to
prevent. At July-2026 cohort scale (~10k CVEs/month) the deterministic
engine routes the month in seconds; there is no performance argument for
anything heavier.

## D3. Advisory-first identity matching, not CPE

**Decision:** identity rules match on CNA, vendor, package, purl, and
description keywords.

**Rejected:** CPE-based applicability matching as the primary key.

Measured on the July 2026 cohort: **67% of the month's CVEs had no CPE data
at NVD at disclosure time** (3,592 Deferred, 1,431 Awaiting Analysis, 941
Undergoing, 510 Received). CPE matching is structurally blind exactly when
routing matters most — at disclosure. CNA identity is available on day
zero (the assigning authority is part of the record), and purl is
version-precise for the OSS half. CPE remains fine as an *additional*
signal once NVD catches up; it cannot be the spine.

## D4. Absent context never matches

**Decision:** a context predicate only fires when the context key is
present on the finding. Absence fails the predicate — including `not`.

**Rejected:** treating absent context as "unknown, allow match" or
defaulting keys.

A correction that could fire on unknown context would hijack every finding
that hasn't been enriched yet, silently rerouting the estate on missing
data. The safe default is the identity rule; the correction earns its
override only when the deployment fact is actually known. Cost: enrichment
coverage directly bounds correction coverage — acceptable, because it makes
enrichment gaps *visible* (findings landing on identity defaults that
corrections should have caught show up in the survived-cycle query).

## D5. Append-only corrections; git is the database

**Decision:** corrections are appended, never rewritten; superseding means
adding a new entry. Review is a pull request; audit is `git blame`;
rollback is `git revert`. The appender preserves existing file bytes.

**Rejected:** a database with an admin UI and edit-in-place.

The registry's value is its trustworthiness as a record of decisions. Git
gives review, attribution, tamper-evidence, and rollback with zero
infrastructure — the same reasoning as an immutable audit-events table,
implemented socially. Edit-in-place destroys the very history that makes a
correction defensible in an audit ("who decided Visual Studio doesn't ride
the bundle, and on what evidence?").

## D6. Every correction ships a regression fixture

**Decision:** `propose-correction` writes a fixture; CI replays all of them
on every change.

**Rejected:** trusting rule review alone.

Hand-maintained routing tables die by decay: a later rule reordering or an
overbroad new match silently re-breaks last quarter's learned routing, and
nobody notices until the misroute recurs. Fixtures make the past
corrections *executable* — the registry can only move forward. This is the
mechanism that turns "we keep a spreadsheet of exceptions" into a system
that converges.

## D7. Channels are delivery mechanisms, not owners

**Decision:** the registry routes findings → channels. Owner names are
channel metadata for the org to fill; the engine never resolves owners.

**Rejected:** routing directly to teams/CMDB entries.

Ownership resolution is the genuinely hard, org-specific problem (GitLab
sidesteps it by routing from repo ownership; most estates can't). Keeping
it out of the engine keeps the engine portable and makes the ownership
problem tractable: a channel taxonomy needs ~13 owner names, not a
per-finding CMDB join. The CMDB join belongs in your context enrichers,
feeding predicates like `internet_facing` — not inside the router.

## D8. Screens are a separate stage, before everything

**Decision:** drop/park rules run before corrections and identity.

**Rejected:** modeling screens as routes to a "screened" pseudo-channel.

21% of the July 2026 cohort should never reach a channel decision at all
(rejected records, out-of-program ecosystems, bulk-feed noise). Screening
first keeps channel stats honest — `unroutable_pct` measures genuine
routing gaps, not noise — and keeps screens coarse and auditable. A screen
that wants deployment context is a correction wearing the wrong hat; the
loader's file layout makes that visible.

## D9. Priorities are explicit, ties break on id

**Decision:** total ordering `(kind, priority, id)`; first match wins.

**Rejected:** specificity scoring (most-specific-rule-wins).

Specificity scoring is clever until two rules tie in non-obvious ways and
the route flips on a YAML reordering. Explicit priority is cruder and
completely predictable, and D6's fixtures make any ordering mistake a test
failure instead of a production misroute. The seeded example: Oracle's
vendor match (priority 10) deliberately outranks the middleware keyword
match (priority 50), so WebLogic lands in the CPU channel.

## D10. Stdlib + PyYAML, no framework, no service

**Decision:** a small Python package with a CLI; data files travel with it.

**Rejected:** a web service, a workflow engine, or embedding into a larger
platform as the only form.

The primary consumer is an analyst workflow and a CI gate, both of which
want a command, not an endpoint. Zero-infrastructure is what makes the
module liftable into a private org repo unchanged — the explicit
translation path (see `workplace-translation.md`). A platform can wrap the
package later; the reverse extraction never happens.

## Known limits (accepted, not accidental)

- **Enrichment-bounded:** corrections only help where context enrichers
  supply the facts (D4). The gap is visible by design, not closed.
- **One-month seed:** screens and identity rules encode the July 2026
  public cohort — a starting point to correct, not ground truth.
- **No SLA/clock logic:** the registry says *where* a finding goes, not
  *how fast* it must close. SLA policy (e.g. BOD-26-04-style exposure
  criteria) consumes routing output; it does not belong inside it.
- **Convergence is empirical:** the thesis — unroutable_pct falls month
  over month as adjudications become rules — is measured by the stats
  output, not guaranteed by the design. Chart it from run one.
