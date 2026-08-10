# CVE Routing — reference for the routing model

Written to be a grounding source for a Copilot notebook, **alongside an
existing environment prompt file**, not instead of it.

## Precedence — read this first

| Question | Authoritative source |
|---|---|
| Database schema, table and column names, existing reports, **existing routing queues**, real team names, what has already been built | **The existing environment prompt file.** It describes the live estate; it wins on every fact about it. |
| The fix-channel model, routing semantics (priority, first-match), SLA logic, the analyst loop, response conventions | **This document.** |
| Anything else in this bundle | Reference only. |

Where this document names a channel, a team or an SLA that conflicts with the
existing environment file, **the existing file wins** and the value here
should be treated as a placeholder to be replaced. See section 4a on mapping
to routing queues that already exist.

---

## 0. Response conventions

Answers about this system should follow these conventions:

- **Lead with the artifact.** If SQL, DAX or a rule line was requested, the
  code block comes first, with no preamble.
- **Explanation is capped at three sentences** unless more is explicitly
  requested. No introduction, no closing summary, no restating the question.
- **One option, not a survey.** Where there is a choice, pick one, state the
  reason in a single sentence, and do not list the alternatives.
- **State assumptions in one line** when a column name or value is uncertain,
  or ask a single clarifying question. Do not invent column names.
- **Cite the section** of this reference that supports the answer (e.g.
  "per section 5"), so a wrong grounding is visible immediately.
- No apologies, no caveat paragraphs, no "it depends" framing.

## 1. What the system does

Every vulnerability finding from our scanners is assigned a **fix channel** —
the delivery mechanism that will actually ship the fix (not a team, not a
severity). Each channel has an owning team and an SLA in days.

The purpose is to answer two questions on every finding: **who fixes this**,
and **by when**. Findings no rule can place are **UNROUTED** — that is the
analyst work queue.

**Success metric:** the percentage of findings that are UNROUTED, tracked
over time. It falls as analysts convert queue items into rules.

## 2. Environment (facts, not preferences)

- Database: **Oracle**, and access is **read-only** — `SELECT` only. No
  `CREATE TABLE`, no `CREATE VIEW`, no `INSERT`.
- All SQL must be **Oracle syntax**: `INSTR`, `NVL`, `||` for concatenation,
  `TRUNC(SYSDATE)`, `ROWNUM`/`ROW_NUMBER()`, `FROM DUAL`.
  SQL Server functions (`CHARINDEX`, `ISNULL`, `GETDATE`, `+` for string
  concatenation, `TOP`) are invalid here and must never be suggested.
- Reporting: **Power BI**, Import mode, scheduled refresh.
- Scanners feeding the data: **Qualys** (on-premises), **Wiz** (cloud),
  **GitHub** dependency alerts.
- Because the database is read-only, the channel and rule tables are **inlined
  as CTEs inside a single SELECT query**, which is pasted into Power BI's
  Oracle source (`Get Data → Oracle database → Advanced options → SQL
  statement`).

## 3. Routing logic

For each finding, every rule is tested. Rules are ordered by `priority`
ascending (**lower number wins**), then by `rule_id`. **The first matching
rule decides the channel** and no later rule is considered. If nothing
matches, the finding is `UNROUTED`.

Three match types:

| match_type | Meaning |
|---|---|
| `VENDOR` | case-insensitive substring of the finding's vendor column |
| `KEYWORD` | case-insensitive substring of product + description combined |
| `PURL_PREFIX` | the package URL starts with this string (e.g. `pkg:npm/`) |

Matching is deliberately simple substring matching. It will occasionally
misroute; that is handled by adding a **more specific rule at a lower
priority number**, not by making the matching cleverer. Example: `netscaler`
at priority 45 beats `citrix` at 52, so NetScaler appliances route to the
network channel rather than virtualisation.

## 4. Fix channels

| channel_id | Channel | Owning team | SLA days | DMZ SLA |
|---|---|---|---|---|
| `windows-endpoint` | Windows endpoints (EUC) | EUC team | 5 | 5 |
| `windows-server-onprem` | On-prem Windows servers | Windows server team | 30 | 7 |
| `euc-central-bundle` | EUC central bundle | EUC team | 30 | 7 |
| `euc-user-installed` | EUC user-installed (not bundled) | Per-exception owner | 30 | 7 |
| `mac-endpoint` | Mac endpoints | Jamf team | 14 | 7 |
| `mobile-ios` | iOS / iPadOS fleet | Mobile platform ops | 14 | 7 |
| `linux-onprem` | On-prem Linux | Linux team | 30 | 7 |
| `k8s-image` | Container base images | Cloud image team | 30 | 7 |
| `ami-rehydrate` | EC2 AMI rebuilds | Cloud team | 30 | 7 |
| `build-dependency` | App dependencies (CI) | Repo owner (per app) | 30 | 7 |
| `internal-app` | Internally-operated apps | App team (per app) | 30 | 7 |
| `middleware` | Middleware (host-installed) | App / hosting team | 30 | 7 |
| `database` | Database servers | DBA team | 30 | 7 |
| `network` | Network appliances | Network engineering | 30 | 7 |
| `virtualisation` | Virtualisation platforms | Platform / infra | 30 | 7 |
| `oracle-cpu` | Oracle Critical Patch Update | Oracle platform team | 90 | 7 |
| `vendor-product` | Enterprise vendor products | Vendor product owner | 30 | 7 |
| `cloud-managed` | Cloud-managed services | Cloud team | 30 | 7 |

An asset with `ZONE = 'DMZ'` (internet-facing) uses the **DMZ SLA** instead of
the normal one. `DUE_DATE = FIRST_SEEN + applicable SLA days`.

## 4a. Mapping onto routing queues that already exist

**The channel list above is a proposal, not a replacement.** Where routing
queues are already in use in existing reports, those names and their meanings
take precedence.

The reconciliation is one pass, done once:

1. List the existing routing queues from the current reports.
2. For each existing queue, decide which channel above is the same thing.
   Most will match closely — an existing "Windows Servers" queue is
   `windows-server-onprem`.
3. **Rename the channel to the existing queue's name and id**, rather than
   renaming the queue. Everything downstream — saved reports, bookmarks,
   team habits, any ticket references — keeps working.
4. Only the channels with **no existing equivalent** are genuinely new. These
   are usually the splits that the current queues do not make: endpoint
   versus server Windows, macOS versus iOS, container base image versus
   application dependency, bundled versus user-installed EUC. Add those.
5. Where an existing queue has **no channel equivalent**, keep the queue and
   add it to the channel list. Nothing is retired in this exercise.

Rule of thumb: this model should change *how findings are assigned*, not
*what the queues are called*. If the reconciliation renames a lot of existing
queues, it has been done the wrong way round.

## 5. Columns the report sees

The routing query returns exactly these columns. Any DAX or SQL written
against the report must use only these names:

| Column | Type | Values / meaning |
|---|---|---|
| `FINDING_ID` | text | unique row id |
| `CVE_ID` | text | e.g. `CVE-2021-44228` |
| `ASSET_ID` | text | host, image or repo |
| `VENDOR` | text | may be null |
| `PRODUCT` | text | may be null |
| `SEVERITY` | text | scanner severity |
| `SOURCE` | text | `QUALYS` / `WIZ` / `GITHUB` |
| `ZONE` | text | `DMZ` when internet-facing |
| `FIRST_SEEN` | date | when the finding first appeared |
| `ROUTING_STATUS` | text | `ROUTED` or `UNROUTED` |
| `CHANNEL_ID` | text | null when unrouted |
| `CHANNEL_NAME` | text | null when unrouted |
| `OWNER_GROUP` | text | owning team, null when unrouted |
| `DECIDED_BY_RULE` | text | which rule made the decision |
| `SLA_DAYS` | number | applicable SLA (DMZ-adjusted) |
| `DUE_DATE` | date | `FIRST_SEEN + SLA_DAYS` |
| `AGE_DAYS` | number | days since first seen |
| `OVERDUE_FLAG` | text | `Y` / `N` |

## 6. The two workflows

**Analyst (no coding, no database access).**
Exports unrouted findings from Power BI, pastes them into a local HTML tool
("CVE Routing Workbench"), which shows routed rows in green and the queue in
amber. For an amber group they decide the owning channel once, add a rule in
the tool, and click "Copy query rows". That produces `UNION ALL SELECT …`
lines which they send to the report owner.

**Report owner (weekly, about ten minutes).**
Pastes those lines into the routing query above the marker line
`-- >>> ADD ANALYST RULES BELOW THIS LINE <<<`, then refreshes the dataset.
The queue shrinks. No database privileges are required at any point.

Rule of practice: **decisions are recorded in the tool, not in the scanner
console.** A suppression or reassignment made directly in Qualys or Wiz helps
one scan and leaves no reusable record.

## 7. Report structure

Four pages, one question each:

1. **Are we on top of it** — cards for total findings, overdue, unrouted %;
   a line chart of unrouted % by month; a horizontal bar of findings by
   channel.
2. **Who owns the work** — matrix of owner group → channel with findings,
   overdue and overdue %, with conditional formatting on the overdue column.
3. **Analyst queue** — table of `ROUTING_STATUS = 'UNROUTED'` grouped by
   vendor and product, sorted by count descending, with slicers for source,
   zone and severity. This page is the work.
4. **Ageing / SLA** — findings past `DUE_DATE` by channel and owner.

Visuals to avoid: pie or donut charts (18 channels is unreadable), gauges,
dual-axis combo charts mixing counts and percentages, tables with more than
about eight columns.

Core measures: `Findings` (row count), `Unrouted` and `Unrouted %`,
`Overdue` and `Overdue %` (denominator is routed findings), `Avg age days`,
distinct counts of `ASSET_ID` and `CVE_ID`.

## 8. Vocabulary

- **Fix channel** — a delivery mechanism with a rhythm (Patch Tuesday, the
  quarterly Oracle CPU, a base-image rebuild), not a team or a severity.
- **Unrouted** — no rule matched; the analyst queue.
- **Certified cycle** — a channel whose owning team certifies its own patch
  cycle. Findings inside such a cycle are recorded, not issued as findings.
  Findings are issued for exceptions, for items past cycle plus SLA, and for
  actively exploited vulnerabilities.
- **Currency / overdue** — routed but still open past `DUE_DATE`. This is what
  the enforcement programme chases.
- **Suppression** — a recorded verdict that a detection is wrong or not
  applicable. Three verdicts: `FALSE_POSITIVE` (the detection is wrong),
  `NOT_APPLICABLE` (component real, this configuration not vulnerable),
  `RISK_ACCEPTED`. Evidence and a re-check date are **mandatory**; when the
  re-check date passes the finding automatically returns. Implemented in the
  read-only query as a `sup` CTE, producing
  `ROUTING_STATUS = 'SUPPRESSED'` and a `SUPPRESSION_VERDICT` column.
  Suppressions are never made in the scanner console — there they have no
  expiry, no evidence and no audit trail.

## 10. Evidence sources

Ranked by cost, cheapest first. Used to justify a suppression or confirm a
finding is real:

1. **SBOM graph (Neo4j)** — holds Mend, Artifactory X-Ray and Wiz
   container-image data, queried through an in-house HTML query builder.
   Authoritative for container and dependency findings: whether a component
   is genuinely present, **which image layer** it sits in (base image versus
   application layer — this decides whether the owner is the platform team or
   the app team), who owns the image, and whether the three tools agree.
   Disagreement between them is itself a signal, usually a false positive in
   the outlier tool.
2. **PowerShell evidence script** — read-only, no install, run by analysts.
   Opens jars to check whether the vulnerable class is actually present,
   distinguishing a patched artefact (class removed, version string unchanged)
   from a genuinely vulnerable one, and flags dead copies such as backups and
   crash dumps.
3. **Active testing** — passive egress/WAF log review first, then a
   canary-token callback test. Requires written authorisation and change
   control. Reserved for internet-facing findings that cannot be patched
   quickly.

**OpenVEX** is the standard machine-readable format for CVE-level
not-affected statements and is generated from the recorded suppressions.
QID-level suppressions have no VEX equivalent — a QID describes a scanner's
detection logic, not the software — and stay in the query only.

## 9. Known limits (do not present these as working)

- Rules live inside the query text; there is no rule table, so rule changes
  mean editing the query. This is a consequence of read-only access.
- There is no cross-scanner de-duplication. The same CVE on the same asset
  from Qualys and Wiz appears as two findings.
- Suppression handling is designed but not present in the read-only query.
- Substring matching has no precision measurement; misroutes are found by
  humans and fixed with priority ordering.
