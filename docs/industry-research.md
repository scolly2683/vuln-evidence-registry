# Industry research: what exists, what's novel, what to change

Researched 2026-08. Question: before proceeding, is this project new territory
or are we rebuilding something that exists? Honest answer: **the problem is a
crowded product category; our specific mechanism is not.** Several pieces we
designed independently have industry standards we should adopt rather than
compete with. Details and the resulting course corrections below.

## 1. What definitely exists (don't rebuild it)

### Routing findings to owners is a commercial product category

"Unified vulnerability management" / ASPM / RemOps platforms do aggregation,
dedup, ownership mapping, and ticket routing at scale, as their core pitch:

- **Seemplicity** — "Remediation Operations": dedup/normalize across
  scanners, map assets to owners via CMDB/directory, route tickets, enforce
  SLAs.
- **Tromzo** — "Intelligence Graph" for code-to-cloud context; automated
  assignment to the right team based on asset ownership.
- **Nucleus Security** — 200+ connectors, custom workflow rules for
  ownership assignment, prioritization, ticketing; publishes BOD 26-04
  guidance.
- **ServiceNow Vulnerability Response** — *vulnerability group rules* (auto
  grouping — our "bundling" concept) and *assignment rules* (auto-routing
  remediation tasks). If the org runs ServiceNow, this overlaps most.
- **DefectDojo** (open source, OWASP) — the closest OSS system: 200+ scanner
  parsers, dedup ("up to 90% noise reduction"), false-positive rules,
  SLA tracking, bi-directional Jira, and **risk acceptance with owner,
  reason, and expiration date** — our suppression-as-lease concept exists
  here as a UI workflow.

The "State of ASPM 2024" stat that 77% of orgs struggle to identify
ownership confirms the problem is real and unsolved-in-practice — but the
market answer is buy, not build.

### Suppression with justification has a standard: VEX

This is the biggest finding. **OpenVEX / CSAF VEX / CycloneDX VEX** are
machine-readable "this CVE does not affect this product, and here is why"
statements, with **fixed justification labels** — e.g.
`component_not_present`, `vulnerable_code_not_present`,
`vulnerable_code_not_in_execute_path`, `inline_mitigations_already_exist`.
Grype, Trivy, and other scanners **natively consume VEX documents to
suppress findings**; OpenSSF promotes exactly the "suppress false positives
via VEX in the pipeline" workflow. GitHub's Dependabot has auto-triage
rules (dismiss by package/CWE/severity, logged to the audit log);
Dependency-Track has vulnerability policies matched on component/version/
tags.

Our suppression verdicts map almost 1:1:

| Ours | VEX equivalent |
|---|---|
| `false_positive` | `not_affected` + `component_not_present` / `vulnerable_code_not_present` |
| `not_applicable_config` | `not_affected` + `vulnerable_code_not_in_execute_path` (etc.) |
| `risk_accepted` | `affected` + action statement (stays mostly internal) |

### The SBOM graph exists as an OpenSSF project: GUAC

**GUAC** (Google/Kusari/Purdue/Citi, OpenSSF incubating) aggregates SBOMs,
SLSA attestations, **VEX statements**, and OSV vulnerability data into a
graph database and answers exactly the queries we planned for the Neo4j
estate graph (artifact → dependencies → vulnerabilities → provenance).
The in-house Neo4j graph (Mend + Artifactory + Wiz) is the same idea,
already built — but GUAC's data model and its native VEX ingestion are
worth studying before extending it.

### Risk-tiered deadlines are now regulation-shaped

**BOD 26-04 is real** (issued 2026-06-10, guidance updated on a rolling
basis): a risk-tiered patching framework on four variables — publicly
exposed, KEV, automatable, technical impact — 3-day deadlines at the sharp
end, defer-to-next-upgrade at the other. Vendors are racing to align.
Pattern 2 of this repo encodes it directly; our exposure-modified SLA
model (DMZ 7-day) is the same shape. We're aligned with where the industry
is being pushed.

### Rules-as-code in git is an established discipline — in detection engineering

"**Detection-as-code**": SIEM/detection rules stored in git,
peer-reviewed, CI-tested (syntax, logic against sample events, and
**regression tests**), rolled back on failure — with the explicit argument
that rules edited in UIs accumulate undocumented changes. GitLab ships
YAML **vulnerability management policies** (e.g. auto-resolve when no
longer detected); GitHub has policy-as-code for repo security settings.
And GitLab's **VulnMapper** (closed source) runs the patch-cycle-lane
model internally — ingestion, normalization, tracking issues, SLA
exception automation.

## 2. What is genuinely uncommon (the differentiated core)

Nothing we found ships this **combination**:

1. **The append-on-misroute learning loop.** Correction-as-data with
   provenance → regression fixture frozen in CI → `unroutable_pct` as a
   convergence metric. Detection-as-code regression-tests *detection*
   rules; no product applies that discipline to *routing/triage decisions*.
   ASPM routing rules are UI/DB config: no diff review, no blame, no
   fixtures, no portability.
2. **Channel-cadence-aware routing.** Routing to a *delivery mechanism
   with a rhythm* (certified cycles, record-don't-assign, survived-cycle
   detection) rather than just to an owner. VulnMapper does a version of
   it internally; nothing open ships it; ASPM tools route to owners, not
   rhythms.
3. **Suppression-as-lease across tools.** Pieces exist (DefectDojo's
   expiring risk acceptance per finding; VEX documents per product;
   scanner-native exclusions per console) — but a git-audited registry of
   group-level verdicts that **syncs out to Qualys and Wiz and reconciles
   back** (flagging tool-side suppressions absent from the registry as
   unmanaged risk acceptance) is not a shipped pattern. Orgs do this ad
   hoc, per console, without expiry.
4. **The two-axis identity/context model as declarative data** — same CVE,
   three routes by deployment context, safe-by-default when context is
   absent. Exploitability vendors compute context via analysis; a
   reviewable declarative override registry is unusual.

## 3. Course corrections before proceeding

1. **Adopt VEX vocabulary; emit OpenVEX.** Add an exporter that turns
   `suppressions.yaml` into OpenVEX documents (and record the VEX
   justification label on each suppression). Cost: small. Payoff: Grype/
   Trivy/GUAC and increasingly Wiz-class tools consume it natively — our
   suppression registry becomes the *author* of a standard interchange
   format instead of a proprietary sidecar. Keep our three verdicts as the
   analyst-facing layer; map to VEX on export.
2. **Position the registry as the decision layer, not the execution
   layer.** Don't rebuild ticket routing, dedup-at-scale, or connectors —
   that's ServiceNow VR / Seemplicity / Nucleus / DefectDojo territory.
   The registry's job: hold the *reviewable, tested, portable rules* and
   export decisions into whatever executes (today: the SQL twin + Power
   BI; later: ServiceNow assignment rules or an ASPM's API). This also
   de-risks vendor churn — rules in git outlive any platform.
3. **Spike DefectDojo before building more execution machinery.** It's
   OSS and covers dedup, FP rules, SLA, Jira, risk-acceptance-with-expiry.
   Confirm what it lacks for us (channel cadences, certified-cycle
   record-don't-assign, git-native rules, regression fixtures, cross-tool
   suppression reconciliation) and decide consciously whether it becomes
   the execution layer under our decision layer.
4. **Evaluate GUAC alongside the in-house Neo4j graph.** Same idea,
   standardized, VEX-native. Even if the in-house graph stays, borrow its
   schema decisions; if GUAC fits, our OpenVEX export plugs straight in.
5. **Keep and double down on the differentiated core** (loop, cadences,
   suppression-as-lease, convergence metric) — that's the part with no
   off-the-shelf answer, and it's cheap: it's YAML, a small engine, and CI.

## 4. Sources

- Seemplicity — [platform](https://seemplicity.ai/platform/), [automated remediation](https://seemplicity.ai/automated-vulnerability-remediation/)
- Tromzo — [vulnerability remediation](https://tromzo.com/vulnerability-remediation), [governance](https://tromzo.com/vulnerability-management)
- Nucleus Security — [platform](https://nucleussec.com/), [remediation workflows](https://nucleussec.com/platform/remediation-workflows/), [BOD 26-04 guidance](https://nucleussec.com/blog/navigating-requirements-cisa-bod-26-04/)
- ServiceNow VR — [overview](https://blog.vsoftconsulting.com/blog/servicenow-vulnerability-response-everything-you-need-to-know), [features](https://www.reco.ai/hub/servicenow-vulnerability-response)
- DefectDojo — [site](https://defectdojo.com/), [auto-triage/dedup](https://defectdojo.com/blog/auto-triage-and-deduplicate-security-findings-to-reduce-alert-fatigue), [SLAs](https://defectdojo.com/blog/stop-setting-developers-up-to-fail-how-intelligent-slas-revolutionize-vulnerability-management), [OWASP project](https://owasp.org/www-project-defectdojo/)
- OpenVEX — [spec](https://github.com/openvex/spec/blob/main/OPENVEX-SPEC.md), [Grype support](https://www.chainguard.dev/unchained/vexed-then-grype-about-it-chainguard-and-anchore-announce-grype-supports-openvex), [OpenSSF on scanners + VEX](https://openssf.org/blog/2023/12/20/openvex-and-open-source-vulnerability-scanners-how-the-dynamic-duo-improves-vulnerability-management/)
- GUAC — [guac.sh](https://guac.sh/), [GitHub](https://github.com/guacsec/guac), [OpenSSF](https://openssf.org/projects/guac/)
- BOD 26-04 — [directive](https://www.cisa.gov/news-events/directives/bod-26-04-prioritizing-security-updates-based-risk), [implementation guidance](https://www.cisa.gov/news-events/directives/bod-26-04-implementation-guidance-prioritizing-security-updates-based-risk), [FedRAMP response](https://www.fedramp.gov/notices/0014/)
- GitLab — [VulnMapper/automation](https://handbook.gitlab.com/handbook/security/product-security/vulnerability-management/automation), [vulnerability management policy (YAML)](https://docs.gitlab.com/user/application_security/policies/vulnerability_management_policy/)
- Dependabot — [auto-triage rules](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-auto-triage-rules); Dependency-Track — [vulnerability policies](https://dependencytrack.github.io/docs/next/concepts/vulnerability-policies/)
- GitHub — [Advanced Security policy-as-code](https://github.com/advanced-security/policy-as-code)
