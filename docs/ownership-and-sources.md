# Sources, ownership, and legacy bundles

The registry routes findings to **channels** (delivery mechanisms). This doc
covers the three process structures around that routing in a mixed estate:

1. **Sources** — findings arrive through three different lenses (GitHub for
   code, Qualys for on-prem runtime, Wiz for cloud runtime) that see
   different things and can supply different context.
2. **Ownership** — some channels have one central owner; others resolve to a
   different owner per finding. The registry handles both, differently.
3. **Legacy bundles** — CVEs on end-of-life assets should be grouped into
   asset-level risk records, not routed as per-CVE work.

Generic names throughout — map them onto your estate.

## 1. Three lenses, one finding stream

| Source | Estate | What it sees | Typical channels | Context it can natively supply |
|---|---|---|---|---|
| **GitHub** (Dependabot / GHSA) | code | manifests, lockfiles, purls, repos | `build-dependency` | `in_pipeline`, repo identity |
| **Qualys** (on-prem) | runtime, hosts + network | installed software, QID→CVE, network device firmware, EOL detections | `windows-os`, `linux-os`, `euc-*`, `middleware`, `database`, `network`, `virtualisation` | `managed`, `os_family`, asset group, `support_status` |
| **Wiz** (cloud) | runtime, workloads | container images with layer attribution, VMs, managed services, exposure paths | `platform-rehydrate`, `build-dependency` (app layer), `cloud-managed`, `linux-os` (VMs) | `image_layer`, `internet_facing`, cloud account, cluster |

**The registry already supports source-aware routing with zero code
changes**: findings carry a `source` field and it is a first-class match
field (`SUBJECT_FIELDS` in `routing_registry/models.py`). A rule can say
`match: {source: [wiz]}` today.

### Same CVE, two lenses: dedup and precedence

The same CVE will arrive from multiple sources — Wiz sees log4j in a running
image, GitHub sees it in the repo's lockfile. Two rules:

- **Dedup key is (cve, asset), not cve.** The Wiz finding on image X and the
  GitHub finding on repo Y are *different findings* if they're different
  deployments — that's the whole two-axis model. Only collapse findings that
  describe the same deployed instance.
- **When sources disagree about the same instance, runtime wins**:
  `runtime > artifact/registry > source manifest`. GitHub says fixed (the
  bump PR merged) but Wiz still sees the CVE in the running image → the
  image hasn't been rebuilt/redeployed; the finding is still open. This is
  the closure-mismatch misroute detector wearing its source hat.

### The GitHub ↔ runtime seam, as process

The seam between repo owners and the runtime scanners is where findings
leak. Make the contract explicit:

| Step | Actor | Signal |
|---|---|---|
| Fix | Repo owner | merges the version-bump PR (`build-dependency` channel) |
| Deploy | App team / pipeline | image rebuilt, workload redeployed |
| **Verify** | **Runtime scanner** (Wiz/Qualys) | CVE no longer detected on the instance |
| Close | Ticket system | only on runtime verification, never on PR merge |

Closing on PR merge is how "fixed" findings resurface next scan. Closing on
runtime verification makes the seam self-auditing: a merged fix that never
redeployed shows up as a closure-mismatch, which becomes a correction
(usually `image_layer` or `in_pipeline` context that was missing).

## 2. Central vs. distributed ownership

A channel is a delivery mechanism; mechanisms come in two ownership shapes:

- **Central** — one team owns the mechanism for the whole estate. Endpoint
  team owns the monthly bundle; network team owns device firmware; DBA team
  owns database patching; platform team owns base images. Ownership is a
  property of the *channel*: fill `owner:` in `channels.yaml` and you're
  done — this is the "13 names, not 10k decisions" promise.
- **Distributed** — the mechanism is a pattern repeated per team. Every repo
  has an owner (`build-dependency`); app-installed middleware belongs to the
  app team that installed it. Ownership is a property of the *finding*, and
  the channel's `owner:` field should name the **resolution mechanism**, not
  a team.

```yaml
# channels.yaml — central: a name; distributed: a resolution mechanism
- id: network
  owner: network-engineering          # central: one team, done

- id: build-dependency
  owner: "resolve: repo→team mapping (CODEOWNERS export)"   # distributed
```

Distributed channels need an **owner-resolution table** per source, built
from data you already have:

| Resolution table | Built from | Resolves owner for |
|---|---|---|
| repo → team | CODEOWNERS / GitHub team API export | `build-dependency` |
| cloud account / tag → team | Wiz projects, cloud tagging standard | cloud workloads, app-layer image findings |
| asset group → team | Qualys asset groups / CMDB | host-installed software on app servers |

Keep resolution tables **out of the registry** (they're org data, refreshed
from their systems of record) but **in the same database** the routing
results land in — owner assignment is a join, not a rule.

### Asset classifications without channel sprawl

Network devices, middleware, databases, web servers, hypervisors — the
temptation is a channel per asset class per owner. Resist it: **create a
channel per delivery mechanism**, and let context corrections split
ownership *within* a mechanism. Recommended shape for the classes named:

| Asset class | Channel | Ownership |
|---|---|---|
| Network devices | `network` | central (network engineering) |
| Hypervisors | `virtualisation` | central (platform/infra) |
| Databases | `database` *(add it — YAML below)* | central (DBA team); Oracle DB stays in `oracle-cpu` via the priority-10 vendor rule |
| Web/app servers, brokers | `middleware` | **mixed** — centrally-managed hosting vs. app-installed; split by context, not by channel |
| End-user software | `euc-central-bundle` / `euc-user-installed` | the shipped example of exactly this split |

The EUC pair is the template: same software, two channels, membership
decided by a context fact (`bundle_member`). Middleware gets the same
treatment with corrections rather than a channel split:

```yaml
# rules/corrections.yaml (via propose-correction) — central hosting carve-out
- id: corr-YYYYMMDD-tomcat-central-hosting
  match:
    keywords: ["tomcat"]
  context:
    centrally_managed: true        # from CMDB / asset-group enrichment
  route: middleware                # still middleware; owner join resolves to
  provenance: { ... }              # the central hosting team via asset group
```

Ready-to-paste `database` channel and identity rule:

```yaml
# channels.yaml
- id: database
  name: Database servers
  description: >-
    Host-installed database engines patched by the DBA function (SQL Server,
    PostgreSQL, MySQL/MariaDB, MongoDB, Redis, Elasticsearch...). Oracle DB
    deliberately excluded — the vendor-level rule routes it to oracle-cpu.
  cadence_type: ad_hoc
  owner: dba-team

# rules/identity.yaml — alongside the other priority-50 infrastructure classes
- id: id-database
  priority: 50
  match:
    keywords: ["sql server", "postgresql", "postgres", "mysql", "mariadb",
               "mongodb", "redis", "elasticsearch", "db2"]
  route: database
```

(Adding these changes `validate` output to `14 channels, … 15 identity
rules` — update anything that pins the seed counts.)

## 3. Legacy risk bundles

**Problem:** legacy and end-of-life assets accumulate CVEs that no channel
will ever ship a fix for. Routing them per-CVE produces noise (hundreds of
tickets nobody can action) and misstates the risk, which is asset-level:
*this system is unsupported*, not *this system has CVE-2019-XXXX*.

**Pattern: park, then bundle.** Don't route legacy findings to fix channels
— no fix is coming. Park them in one queue, then aggregate the queue into
**one risk record per asset/product** for the risk forum, not the patch
queue.

### Registry side

One context enricher plus one screen:

- Enrich findings with `support_status` (`supported` / `extended` / `eol`)
  from the CMDB, Qualys EOL/obsolete-software detections, or
  endoflife.date. Enrich **before the fork** (SQL doc §9.5) so both twins
  see it.
- Add the screen — screens run before corrections, so parking deliberately
  beats routing. An empty `match:` with a context predicate is the blessed
  screen shape for this (`router._match_subject` docstring):

```yaml
# screens.yaml
- id: screen-legacy-eol
  match: {}
  context:
    support_status: eol
  action: park
  queue: legacy-risk
  note: >-
    EOL software: no fix channel will ever ship this. Parked for asset-level
    bundling — the risk record is the asset, not the CVE. KEV escalation
    valve applies (see ownership-and-sources.md §3).
```

Context predicates only fire when the key is present, so findings without
support-status data route normally — safe by default, like every correction.

### Database / Power BI side

Bundle = group the parked queue by asset or product. One row per bundle,
CVE list attached:

```sql
CREATE VIEW vm.vw_pbi_legacy_bundles AS
SELECT
    f.vendor,
    f.product,
    COUNT(*)                                   AS cve_count,
    MIN(f.run_date)                            AS oldest_seen,
    SUM(CASE WHEN k.cve_id IS NOT NULL
             THEN 1 ELSE 0 END)                AS kev_count   -- escalation valve
FROM vm.vw_routing r
JOIN vm.findings f       ON f.finding_id = r.finding_id
LEFT JOIN kev_entries k  ON k.cve_id = f.cve_id              -- pattern-1 table
WHERE r.park_queue = 'legacy-risk'
GROUP BY f.vendor, f.product;
```

Power BI gets a **Legacy risk** page listing bundles, not CVEs: product,
CVE count, age, KEV count — sorted by KEV count then CVE count. Each bundle
is one line item for the risk forum: accept, isolate, or decommission, on a
quarterly review cadence, with the CVE list as the appendix rather than the
work items.

### The escalation valve — non-negotiable

A parked bundle must not become a place where actively-exploited findings
sleep. The valve: **any bundled CVE entering the act-now set (KEV /
exploited-in-the-wild — pattern 1's `act_now_union_sql()` composes exactly
this) triggers immediate bundle review**, off-cycle. `kev_count > 0` on the
bundle view is the alert condition — wire it to a data alert in Power BI.
The bundle stops being a quarterly line item the day one of its CVEs shows
up in KEV; isolation or emergency decommission becomes the conversation.

## 4. Who does what

| Role | Owns |
|---|---|
| Analysts | work the unroutable queue; propose corrections; flag misroutes |
| Routing owner | reviews every registry PR (CODEOWNERS on `registry/`); runs the monthly `review_by` hygiene sweep |
| Central channel teams (endpoint, network, DBA, platform…) | their channel's `owner:` entry; their cadence facts (bundle manifest exports, image digest tables) |
| Data/BI owner | export → reload → parity gate job; owner-resolution tables; Power BI dataset |
| Risk forum | legacy bundles: accept / isolate / decommission; KEV escalations |

Rollout order (extends `workplace-translation.md` §rollout): seed channels +
central owners → run read-only for a month → adjudicate the queue top-down →
wire the survived-cycle detector → **only then** let routing drive ticket
assignment, and only then wire owner-resolution joins for the distributed
channels.
