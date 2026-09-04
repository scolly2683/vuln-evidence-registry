# Standards landscape — what exists, what is empty, and what would make cited preconditions something the industry can rely on

*2026-09-02. Measured, not recalled: the numbers come from `scan_kev_cvelist.py` over every CVE
in the CISA KEV catalogue (1,687 records, catalog 2026.08.31), the CSAF aggregator listing, and
the standards' own texts. Data in `data/kev_cvelist_scan_2026-09-02.json`.*

## The question

Would CISA's ADP (Vulnrichment) help? And what would turn a citation-checked precondition record
from a private method into a standard others can rely on?

## 1. What the existing standards already provide — measured over KEV

| container / field | who writes it | KEV coverage | note |
|---|---|---|---|
| CVE 5.x **`configurations`** — *"Configurations required for exploiting this vulnerability"* | CNA | **1.2%** (21 / 1,687); 2.8% of 2023+ records | The schema-native home for preconditions. Almost never used. |
| CVE 5.x `workarounds` | CNA | 2.7% | Remediation-side twin. |
| CVE 5.x `solutions` / `exploits` | CNA | 5.1% / 5.0% | |
| CVE 5.x `descriptions` > 300 chars | CNA | 45.5% | The text everyone actually reads — NVD's description *is* this text. |
| CNA `affected[].cpes` / CNA CVSS | CNA | 3.0% / 42.0% | |
| **ADP (CISA Vulnrichment)** — any container | CISA | 99.9% | KEV is CISA's own catalogue, so this is the ceiling, not the norm. |
| ADP SSVC (Exploitation, Automatable, Technical Impact) | CISA | 99.9% | Mandatory for every ADP-analysed CVE. |
| ADP CVSS / CWE / CPE | CISA | 58.9% / 63.5% / 9.9% | CPE enrichment **discontinued 2024-12-10**. |
| ADP `configurations` / `workarounds` text | CISA | **0.2%** | The ADP does not write precondition text. |

**By CNA, for the CNAs that dominate KEV** (`configurations` / `workarounds` / `solutions`
presence): Microsoft (n=377) 0 / 0 / 0%; MITRE (322) 0.3 / 0.3 / 0.9%; Cisco (95) 0 / 0 / 0%;
Apple (94) 0 / 0 / 0%; Adobe (74) 0 / 0 / 0%; Fortinet (29) 0 / 0 / **69%**; Ivanti (17) 0 / 0 / 0%;
**Palo Alto (14) 71 / 93 / 93%**.

**Answer to "would ADP help": not as a source, yes as a consumer.** Vulnrichment adds SSVC
decision points, CVSS, CWE and a KEV tag; it never adds the sentence that says what must be true
for the CVE to apply. But SSVC is where preconditions *land*: `Automatable` (supplier/coordinator)
and, above all, **`System Exposure`** — a *deployer* decision point, "the accessible attack
surface of the affected system or service", valued small / controlled / open — is exactly the
question a cited "must reach" gate lets a deployer answer per component rather than per CVE.
SSVC's own guidance is that a deployer who does not know their exposure must assume *open*;
cited reachability gates are how they stop assuming.

## 2. The one CNA that fills the container is a validation of the method — and of its ceiling

Two Palo Alto records are in the 50-CVE reference set, and Palo Alto is the outlier CNA that
writes `configurations`. Side by side:

| CVE | Palo Alto's `configurations` (CNA-authored) | our text-only extraction from the description |
|---|---|---|
| CVE-2026-0257 | GlobalProtect portal or gateway configured **and** authentication-override cookies enabled **and** a specific certificate configuration | GlobalProtect portal/gateway reachable |
| CVE-2026-0300 | PA-/VM-Series **and** User-ID Authentication Portal enabled **and** an interface management profile with response pages on an internet-accessible interface | Authentication Portal reachable; PA-/VM-Series |

Two conclusions, both important:

- **The method is right about what a precondition is.** Where the CNA wrote structured gates,
  they are the same *kind* of thing the standard extracts — component reachable, feature
  enabled, platform — and the reachability/platform gates match exactly.
- **Extraction is bounded by the text it is given.** The description never mentions the cookie
  setting or the interface profile; only the `configurations` container does. So the source
  ladder must put **the CNA's `configurations` + `workarounds` containers above the description**
  when they exist — and they exist for ~1% of KEV. This corrects the earlier "rung 2" claim in
  `README.md`: the CNA's CVE record is only richer than NVD's copy when those containers are
  filled; its `descriptions` field *is* what NVD republishes.

## 3. Where cited preconditions fit the standards that deployers already use

Nothing here needs a new format. The record already maps onto three existing standards; the
gap is that none of them carries **checkable evidence** for the claim.

| existing standard | what it asks | what a cited precondition supplies |
|---|---|---|
| **CVE 5.x `configurations`** | free text: configurations required for exploiting | the sentence, with `cites` back to the advisory — the container's intended content, made verifiable |
| **SSVC `System Exposure`** (deployer) | small / controlled / open for *the affected system or service* | *which* service: the "must reach" gate names the component whose exposure is the one that matters |
| **VEX `not_affected` justifications** (OpenVEX / CSAF) | `component_not_present`, `vulnerable_code_not_in_execute_path`, `vulnerable_code_cannot_be_controlled_by_adversary`, `inline_mitigations_already_exist` | the gate that, when false in a deployment, *is* the justification: component-in-use → `component_not_present`; feature-enabled → `inline_mitigations_already_exist` / `not_in_execute_path`; attacker-position → `cannot_be_controlled_by_adversary`. OpenVEX "highly discourages" free-text `impact_statement` because it breaks automation — a cited precondition is the machine-checkable evidence a justification currently lacks. |
| **CVE Program Key Details Phrasing** | CNAs describe [problem type] in [component] in [vendor product version] on [platform] allowing [attacker] to [impact] via [vector] | the extractor is, in effect, a parser for this template; a CNA's **empty-rate** under the standard is a measure of how well its descriptions follow it |

## 4. What makes a standard something you can rely on — and which parts already exist

1. **A conformance test.** Standards without one are prose. The 50-record reference set plus
   `compare.py` is one: any extractor, model or source change is scored on the cited-sentence
   key, and the rule set is versioned by what the score does (Rule 8 was adopted because it
   moved edge recall from 0.65 to 0.86 blind). *Exists.* Needs to grow past 50, stratified by CNA.
2. **Evidence in the record, checked by machine.** `cites` + the validator's substring check.
   A record cannot carry a gate the text does not. *Exists.* Add a `sha256` of the captured text
   so a citation stays re-checkable after the vendor edits the page.
3. **Provenance that names the rung.** `source`, `source_url`, `retrieved`; the ladder in
   `README.md` now needs `cvelist` (configurations/workarounds) as a source value above the
   description. *Partly exists.*
4. **A published coverage metric that puts pressure where it belongs.** *(Now exists:
   `COVERAGE.md` + `coverage.py`, 2026-09-03 — the per-CNA table, the 1.2% headline, and the
   within-CNA deconfound showing the same assigner extracting 2.88 gates with the container and
   0.00 without it.)* The per-CNA empty-rate
   ("this text states no precondition") is both the ladder's promotion signal and a public
   number: Microsoft 80% empty from NVD text, 27% from its own Security Update Guide; Palo Alto
   fills the schema field 71% of the time; most CNAs 0%. Publishing that table monthly is what
   moved CNA behaviour on CVSS and CWE — the CVE Program and CISA both publish CNA quality
   metrics; applicability text is not yet one of them.
5. **An owner and a change process.** Versioned rules, a changelog, an adoption date per rule,
   and a route for proposals (Rules 9 and 10 are the first two). *Exists in embryo.*

## 5. Realistic routes to "industry standard" for a single practitioner

In order of effort-to-leverage:

1. **A GCVE Best Current Practice.** This repository already tracks GCVE BCP-07/10/11; CIRCL's
   BCP process accepts community proposals and has published consumer-facing practices before.
   *"BCP-xx: Cited applicability preconditions"* — the eight rules, the record shape, the
   conformance set — is the most direct venue, and the KEV coverage table is the motivating
   evidence.
2. **An OpenVEX extension.** OpenVEX is a GitHub-governed spec; a `preconditions[]` array with
   `cites` on a `not_affected` statement gives justifications the evidence the spec admits they
   lack. Small, concrete, and it puts the record where deployers already automate.
3. **Feed the CVE Program's own field.** Publish records in CVE 5.x `configurations` shape so
   any CNA — or an ADP — can adopt them verbatim; bring the 1.2% number to the CVE Quality
   Working Group. Becoming an ADP oneself is not realistic; making the container easy to fill is.
4. **Publish the coverage table** (per-CNA empty-rate and `configurations` rate) as a standing
   artefact of this repo. Measurement is the lever; it costs nothing and it is what nobody else
   has.

What is deliberately *not* on the list: a new file format, a new taxonomy, or an OASIS TC. The
standard is the seven-plus-one rules and the conformance set; the format is whatever the
consumer already reads.

## 6. Limits of this research

- KEV is the only population scanned. It is CISA-curated and exploited-by-definition, so ADP
  coverage (99.9%) is a ceiling; on the general CVE population it is lower. Container usage
  (1.2%) is unlikely to be *higher* elsewhere.
- CSAF adoption was checked against one aggregator (BSI: 15 publishers; Red Hat, Siemens and
  Schneider among the vendors relevant here). Cisco and Microsoft publish CSAF outside that
  aggregator; per-vendor `.well-known` discovery is the reliable check and was not run here.
- The Palo Alto comparison is two CVEs. It shows the *kind* of gap, not its rate.
