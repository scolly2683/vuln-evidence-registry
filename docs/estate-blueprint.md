# Estate blueprint — worked from real examples

This doc translates a concrete estate description into registry
configuration, operating process, and data design. It is grounded in a
**backtest**: 28 findings built from the notable KEV / high-EPSS CVEs of
2020–2025 (`examples/kev-backtest.jsonl`), routed through the seed registry
as-is. The gaps the backtest exposes drive every recommendation below.

Estate facts this blueprint encodes (as described 2026-08):

- Jenkins-class apps are run by **internal app teams** — findings go to the
  app team on a template, not to a generic vendor lane.
- Apple splits: **macOS → Jamf team**, **iOS → mobile platform ops**.
- Windows splits: **endpoints → EUC team, Patch Tuesday + 5 days**;
  **on-prem servers → Windows server team, 30 days — but DMZ assets 7 days**.
- Bundle teams **certify their own cycles** — no findings for in-cycle work.
  Exceptions are what the bundle doesn't package (Visual Studio, ASP.NET,
  SharePoint). The cloud image team manages its own builds.
- **Enforcement programs** pick up findings when owners don't patch; assets
  behind on older vulnerabilities must be caught from our queues and issued
  currency findings.
- Linux: kubernetes images and AMIs → cloud teams; on-prem has its own
  cycles covering Ubuntu / Red Hat errata; we spot what's missing.
- KEV / high-EPSS must be caught and routed to the correct owner regardless
  of cycles.
- Java/Spring carry huge legacy volume, much of it **config-dependent**
  (vulnerable only in specific configurations).
- Qualys log4j/spring4shell QID storms and similar false positives make
  **suppression a first-class need**, synced into Qualys and Wiz.
- Qualys SWCA is unacted-on (accuracy unknown). Wiz alert ownership is
  painful (layer attribution). Available: a **Neo4j SBOM graph** holding
  Mend, Artifactory, and Wiz container-image results.

## 1. The backtest: what the seed registry does with 5 years of KEV

`python -m routing_registry route --registry registry --findings examples/kev-backtest.jsonl --stats`

28 findings → **20 routed, 8 unroutable (28.6%)** — close to the July 2026
full-cohort 22%, on the hardest CVEs there are. Selected results:

| Finding | Seed result | Verdict for this estate |
|---|---|---|
| Log4Shell via GitHub (has purl) | `build-dependency` | ✅ correct — repo owner lane |
| Log4Shell via Qualys (no purl) | **unroutable** | ❌ same CVE, no SBOM context → §6 fixes this with enrichment, not keyword rules |
| Spring4Shell via GitHub (purl) | `build-dependency` | ✅ purl (prio 40) correctly beat the VMware vendor rule (prio 50) |
| Spring4Shell via Qualys | `middleware` | ⚠️ routed because the *description mentions Tomcat* — keyword matching on prose misfires; enrichment must outrank it |
| Citrix Bleed (NetScaler) | `virtualisation` | ❌ vendor rule too coarse: NetScaler is a **network appliance** |
| ProxyLogon (Exchange) | **unroutable** | ❌ Microsoft server products have no home → new rule below |
| SharePoint ToolShell (2025) | `euc-central-bundle` | ❌ exactly the "bundle doesn't package SharePoint" exception — needs the server-products rule |
| Zerologon / PrintNightmare / Follina | `windows-os` | ⚠️ right channel, but the estate needs the endpoint/server split + DMZ SLA |
| iOS BLASTPASS | `mac-endpoint` | ❌ should be mobile platform ops, not Jamf |
| macOS WebKit | `mac-endpoint` | ✅ Jamf |
| Jenkins CLI (CVE-2024-23897) | `vendor-product` | ⚠️ routed, but the estate wants the **internal-app** lane with app-team resolution |
| PAN-OS, FortiOS, Cisco IOS XE | `network` | ✅ |
| WebLogic console RCE | `oracle-cpu` | ✅ (see §7 for the 50-WebLogic-CVEs worklist treatment) |
| Outlook EoP | `euc-central-bundle` | ✅ certified bundle — record, no finding |
| regreSSHion raw NVD identity | **unroutable** | ❌ "OpenBSD / OpenSSH" means nothing to routing… |
| regreSSHion as RHEL package | `linux-os` | ✅ …but the distro-enriched twin routes fine → enrich to package identity before routing |
| MOVEit, Ivanti, PaperCut, ScreenConnect, sudo | **unroutable** | the appliance/product long tail — each becomes one rule at first adjudication; that *is* the loop working |

**The four lessons:**

1. **Enrichment beats rules.** The same CVE routes correctly or not
   depending on whether the finding carries purl/package/distro identity.
   Fix the finding (from the SBOM graph, §6), not the rule count.
2. **Prose keywords are the weakest signal** — Spring4Shell landing in
   `middleware` off the word "Tomcat" in a description. Keyword rules stay
   as fallback; package identity must outrank them.
3. **Vendor ≠ asset class.** Citrix sells hypervisors *and* network
   appliances; Microsoft ships endpoints *and* server products. Product
   rules at a higher priority fix each observed case.
4. **The unroutable tail is normal and convergent.** Eight famous CVEs
   unroutable on day one, each one adjudication away from never being
   unroutable again.

## 2. Target channel map

| Channel | Owner | Cycle / SLA | Assurance |
|---|---|---|---|
| `windows-endpoint` | EUC team | Patch Tuesday + **5 days** | certified bundle |
| `windows-server-onprem` | Windows server team | + **30 days**; **DMZ 7 days** (SLA modifier, §3) | certified + enforcement |
| `euc-central-bundle` | EUC team | monthly push | certified; exceptions via `bundle_member` corrections |
| `euc-user-installed` | per exception | ad hoc | findings issued |
| `mac-endpoint` | **Jamf team** | Apple release + MDM window | certified |
| `mobile-ios` *(new)* | **Mobile platform ops** | per release | certified |
| `linux-onprem` | on-prem Linux team | own cycles; Ubuntu/RHEL errata | certified — we spot what's missing |
| `k8s-image` (= `platform-rehydrate`) | cloud image team | rebuild cadence | certified builds |
| `ami-rehydrate` *(new)* | cloud team | AMI rebuild cadence | certified builds |
| `build-dependency` | repo owners (distributed) | continuous | Renovate/Dependabot lane |
| `internal-app` *(new)* | app teams (distributed, via app catalog) | per app | **finding template per app team** |
| `network` | network engineering | advisory-driven | includes the appliance long tail |
| `oracle-cpu`, `virtualisation`, `vendor-product`, `cloud-managed`, `database` | as per seed / ownership doc | | |

Ready-to-paste rules fixing every backtest failure (priorities chosen to
beat the seed rule that misrouted):

```yaml
# channels.yaml — additions
- id: windows-endpoint
  name: Windows endpoints (EUC)
  cadence: "Patch Tuesday + 5 days"
  cadence_type: scheduled
  owner: euc-team
- id: windows-server-onprem
  name: On-prem Windows servers
  cadence: "Patch Tuesday + 30 days (DMZ 7 days)"
  cadence_type: scheduled
  owner: windows-server-team
- id: mobile-ios
  name: iOS / iPadOS fleet
  cadence: "Apple release + MDM enforcement window"
  cadence_type: ad_hoc
  owner: mobile-platform-ops
- id: ami-rehydrate
  name: EC2 AMI rebuilds
  cadence_type: scheduled
  owner: cloud-team
- id: internal-app
  name: Internally-operated applications
  description: Apps run by internal app teams (Jenkins first). Owner resolved per app from the app catalog.
  cadence_type: ad_hoc
  owner: "resolve: app-catalog"

# rules/identity.yaml — additions (priority beats the seed rule that misrouted)
- id: id-apple-ios                 # beats id-apple (30): iOS to mobile ops
  priority: 25
  match: { vendor: [apple], keywords: ["ios", "ipados", "iphone", "ipad"] }
  route: mobile-ios
- id: id-msft-server-products      # beats id-msft-euc (30): Exchange/SharePoint
  priority: 25
  match: { vendor: [microsoft], keywords: ["exchange server", "sharepoint"] }
  route: windows-server-onprem
- id: id-citrix-netscaler          # beats id-virtualisation (50)
  priority: 45
  match: { keywords: ["netscaler"] }
  route: network
- id: id-jenkins-internal          # beats id-vendor-product (70)
  priority: 65
  match: { vendor: [jenkins] }
  route: internal-app
- id: id-appliance-longtail        # backtest unroutables, adjudicated once
  priority: 65
  match: { vendor: [ivanti, "pulse secure", barracuda, sonicwall] }
  route: network
- id: id-moveit
  priority: 65
  match: { vendor: ["progress software"], keywords: ["moveit"] }
  route: internal-app              # or vendor-product — whoever operates it
```

Windows endpoint/server is a **context split**, not a keyword split — the
CVE is identical; the asset class decides:

```yaml
# id-windows-os routes to windows-endpoint (the volume default), then:
- id: corr-YYYYMMDD-windows-server-class
  match: { vendor: [microsoft], keywords: [windows] }
  context: { asset_class: server }        # from Qualys asset groups / CMDB
  route: windows-server-onprem
  provenance: { ... }
```

## 3. SLA model: cycle + exposure modifiers

DMZ-7-days is not a channel — it's an SLA modifier on a context fact. Model
deadlines as data next to the channel, resolved per finding:

| Channel | Base SLA | `internet_facing`/`zone: dmz` | KEV / act-now |
|---|---|---|---|
| windows-endpoint | 5 days | n/a | exposure-based (below) |
| windows-server-onprem | 30 days | **7 days** | exposure-based |
| linux-onprem | cycle | 7 days | exposure-based |
| k8s-image / ami-rehydrate | rebuild cadence | 7 days | exposure-based |

This is pattern 2's shape (`vuln_evidence_registry/bod_26_04.py` — the
BOD 26-04 engine computes exposed and internal deadline branches from
exactly these booleans). Reuse it: **deadline = f(channel base SLA,
exposure, KEV, automatable)**, with the org table above replacing Table 1
where it's stricter.

**Act-now override:** KEV entry or EPSS above threshold (pattern 1's
`act_now_union_sql()` composes the trigger set) issues an immediate finding
with the exposure deadline **regardless of certified cycle status**. The
backtest set is precisely this class: certified cycles are how Outlook EoP
gets handled; ProxyLogon on a DMZ Exchange box is a 7-day finding the day
it publishes.

## 4. Certified cycles and the finding-issuance policy

The estate's key process fact: bundle teams certify their own cycles, so
routing into a certified channel is a **record, not a finding**. Findings
are the exception path. One table is the whole policy:

| Condition | Action | Recipient |
|---|---|---|
| Routed to certified channel, within cycle + SLA | **record only** — the cycle record covers it | — |
| Exception the bundle doesn't package (Visual Studio, ASP.NET, SharePoint → `bundle_member: false` corrections) | finding on the team's template | owning team |
| **Survived cycle + SLA** (the currency queue) | currency finding | **enforcement program** |
| KEV / high-EPSS act-now | immediate finding, exposure deadline | owner, enforcement visibility |
| EOL / legacy asset | bundle line, not per-CVE findings | risk forum (ownership doc §3) |

The currency queue is the "assets that are behind" catcher, and it's one
query — findings routed to a certified channel whose age exceeds the
channel's cycle + SLA:

```sql
CREATE VIEW vm.vw_currency_queue AS
SELECT r.finding_id, r.cve_id, r.channel_id, f.run_date,
       DATEDIFF(day, f.first_seen, GETDATE()) AS age_days,
       c.owner_group,
       CASE WHEN x.context_value IS NOT NULL THEN 7          -- DMZ modifier
            ELSE c.base_sla_days END          AS sla_days
FROM vm.vw_routing r
JOIN vm.findings f  ON f.finding_id = r.finding_id
JOIN reg.channels c ON c.channel_id = r.channel_id
LEFT JOIN vm.finding_context x
       ON x.finding_id = r.finding_id
      AND x.context_key = 'zone' AND x.context_value = 'dmz'
WHERE r.disposition = 'routed'
  AND DATEDIFF(day, f.first_seen, GETDATE()) >
      c.cycle_days + CASE WHEN x.context_value IS NOT NULL THEN 7
                          ELSE c.base_sla_days END;
```

(Requires `cycle_days` / `base_sla_days` columns on `reg.channels` — add
them to the export when the SLA table in §3 is agreed.) Everything in this
view becomes an enforcement finding; everything not in it stays a record.

## 5. The suppression registry — false positives as first-class data

The QID storms (log4j 1.x detections, Spring4Shell version-only matches)
and config-dependent Java/Spring CVEs need suppression that is **grouped,
evidenced, expiring, and synced** — not per-asset clicking in two consoles.

**Design: `rules/suppressions.yaml`**, same discipline as corrections
(append-only, provenance mandatory, `review_by` mandatory — a suppression
is a lease, not a tombstone):

```yaml
- id: sup-20260810-spring4shell-jdk8
  match:
    cve_id: ["CVE-2022-22965"]          # requires the schema extension below
  context:
    config_vulnerable: false             # computed by the enricher, not the rule
  verdict: not_applicable_config
  evidence: >-
    Spring4Shell requires JDK 9+, WAR packaging on Tomcat, and data binding.
    SBOM graph shows this deployment is JDK 8 / fat-jar. Qualys QID matches
    on spring-beans version alone.
  provenance: { date: "2026-08-10", decided_by: ..., trigger: "QID 730409 cluster, 1,900 detections" }
  review_by: "2027-02-01"

- id: sup-20260810-log4j1-qids
  match:
    qid: ["376157", "376178"]            # log4j 1.x QIDs — different product
  verdict: false_positive
  evidence: "Log4j 1.x is not vulnerable to CVE-2021-44228; detections are version-string matches on log4j-1.2.x jars."
  provenance: { ... }
  review_by: "2027-08-01"
```

Three verdicts, deliberately distinct because they age differently:
`false_positive` (the detection is wrong), `not_applicable_config` (real
component, config not vulnerable — **most Java/Spring legacy volume lives
here**), `risk_accepted` (real, accepted — shortest `review_by`).

**Engine change required (small):** `cve_id` and `qid` as match fields —
one line each in `SUBJECT_FIELDS` (`routing_registry/models.py`), plus the
columns on findings. Suppressions evaluate before screens in the pipeline.
Conditional logic (JDK version, WAR vs jar) stays **out of the rules**: the
enricher computes a boolean like `config_vulnerable` from the SBOM graph,
and the rule matches the boolean — the engine stays dumb, the evidence
stays queryable.

**Sync out, reconcile back.** The registry is the source of truth; the
scanners are sinks:

- **Qualys**: generate a dynamic search list / exclusion from the suppressed
  QID set (scoped by asset tags where the condition is config-specific).
- **Wiz**: create ignore rules via API from the suppressed CVE set with the
  matching resource scope.
- **Weekly reconciliation**: pull active exclusions/ignore rules from both
  tools and diff against the registry. A suppression live in a tool but
  absent from the registry is an **unmanaged risk acceptance** — the exact
  thing this design exists to eliminate. `review_by` expiry drops the rule
  from the next sync, so detections resurface automatically for re-verify.

Suppression happens at the **(QID/CVE, condition) group level** — one
verified verdict clears thousands of detections, with one audit record.

## 6. The evidence spine: the Neo4j SBOM graph

The graph (Mend + Artifactory + Wiz container results) is the answer to
four separate problems named in the estate description:

1. **Package identity for runtime findings** — the backtest's biggest fix.
   Log4Shell-via-Qualys was unroutable because the host finding carries no
   purl. Join the finding's asset/image to the graph, attach the purl, and
   it routes down the same `build-dependency`/image path as the GitHub
   twin. Enrich **before** routing (and before the SQL fork).
2. **Layer attribution for Wiz ownership pain** — base vs app layer is a
   graph walk, not a deep manual Wiz investigation:
   `(:Image)-[:HAS_LAYER]->(:Layer)-[:CONTAINS]->(:Component {purl})` plus
   the base-image chain → `image_layer: base|app` context, which the seed
   Tomcat corrections already consume. Ownership is the same walk continued:
   image → Artifactory build info → repo → team.
3. **Qualys SWCA accuracy, measured instead of distrusted** — join SWCA
   detections against the graph per (asset/image, component): agreement
   rate per QID gives trust tiers. Act on corroborated detections now;
   route uncorroborated ones to a verify queue; persistent disagreement per
   QID feeds either a suppression (`false_positive`) or an SBOM gap fix.
   The graph turns "we don't know how accurate it is" into a number per QID.
4. **Config-vulnerability evidence for §5** — JDK version, packaging type,
   presence of the actually-vulnerable artifact (log4j-core 2.x vs log4j
   1.x) are graph facts; the enricher distills them into the
   `config_vulnerable` boolean the suppression rules match.

## 7. The analyst worklist — the tool, not the doc

The guides describe the system; analysts need a **worklist**, and the
working unit is a *CVE-group × asset cohort*, never a single CVE. The
WebLogic case from the estate description, concretely: 50 WebLogic CVEs
collapse to **three work items**:

| Cohort | e.g. | Action |
|---|---|---|
| **In-cycle** — fixed by the next Oracle CPU | 35 CVEs on current-ish versions | record against the CPU cycle; no findings |
| **Overdue / currency** — assets behind cycles | a CVE with 30 assets past cycle+SLA | one currency finding batch → enforcement |
| **Legacy** — EOL versions no CPU covers | old CVEs with 5 assets each | one legacy bundle → risk forum |

```sql
CREATE VIEW vm.vw_pbi_worklist AS
SELECT r.rule_id, f.vendor, f.product,
       COUNT(DISTINCT f.cve_id)   AS cve_count,
       COUNT(DISTINCT a.asset_id) AS asset_count,
       COUNT(DISTINCT CASE WHEN x.context_value = 'true'
             THEN a.asset_id END) AS external_assets,     -- the risk split
       MAX(DATEDIFF(day, f.first_seen, GETDATE())) AS oldest_age_days,
       SUM(CASE WHEN cq.finding_id IS NOT NULL THEN 1 ELSE 0 END) AS overdue_count
FROM vm.vw_routing r
JOIN vm.findings f        ON f.finding_id = r.finding_id
JOIN vm.finding_assets a  ON a.finding_id = f.finding_id
LEFT JOIN vm.finding_context x
       ON x.finding_id = f.finding_id AND x.context_key = 'internet_facing'
LEFT JOIN vm.vw_currency_queue cq ON cq.finding_id = f.finding_id
WHERE r.disposition = 'routed'
GROUP BY r.rule_id, f.vendor, f.product;
```

`external_assets` is the column that splits actual risk across
internet-facing apps — sourced from Wiz exposure paths / EASM into
`finding_context`, it rolls up on every worklist row and every legacy
bundle, so an externally-reachable straggler can never hide inside a big
internal cohort. Sort the worklist by `external_assets DESC,
overdue_count DESC` and the top of the list *is* the day's work.

The natural next build on top of this view is an interactive triage board
(filter by product, expand a group to its CVE/asset detail, one-click
"draft correction request" prefilled with the group's match facts) — the
data shape above is designed so that tool is a rendering exercise, not a
data project.

## 8. Order of attack

1. **Channel map + owners** (§2) — one workshop; apply the YAML.
2. **SBOM enrichment join** (§6.1) — purl/package onto runtime findings;
   biggest single unroutable-killer the backtest found.
3. **Monthly cohorts read-only** — adjudicate top unroutable groups;
   corrections start accreting.
4. **Currency queue → enforcement feed** (§4) — the "assets behind" catcher.
5. **Suppression registry + Qualys/Wiz sync** (§5) — engine extension
   (`cve_id`/`qid` match fields), then the QID storms first.
6. **SWCA accuracy measurement** (§6.3) — decide with data whether to act
   on it.
7. **Worklist view → triage board** (§7).

Each step is independently valuable; nothing blocks on a big bang. The
backtest file re-runs at every step — `unroutable_pct` on the 28 hardest
CVEs of five years is a fine convergence metric to start with.
