# Applicability coverage: the CVE field that answers "does this apply to me", and the 1.2%

*2026-09-03. Every figure here is reproduced by `python3 coverage.py` from two committed
files — `data/kev_cvelist_scan_2026-09-02.json` (1,687 KEV CVEs, catalogue 2026.08.31) and the
170-CVE extraction run in `../pipeline/runs/edge-2023plus/`. No network, no new inference.
`tests/test_coverage.py` fails if this document and that script ever disagree.*

## The finding

CVE Record Format 5.x has a container called **`configurations`**, defined as *"configurations
required for exploiting this vulnerability"*. It is the schema-native home for the question
every defender actually asks: **does this CVE apply to my deployment, or not?**

Across the whole CISA KEV catalogue it is filled on **1.2%** of records (21 of 1,687,
95% CI [1%, 2%]).

Where a CNA does fill it, applicability extraction never comes up empty — and where the same
CNA does not, it finds nothing at all.

## Prior art — this coverage number is not new, and the credit is Jerry Gamblin's

**[CNAScoreCard](https://github.com/RogoLabs/CNAScoreCard)** (RogoLabs / Jerry Gamblin, announced
at BSides Las Vegas) already tracks this field and already publishes a utilisation figure. From
its own generated data, `web/data/field_utilization.json`:

```json
{"field": "containers.cna.configurations", "percent": 9.1, "unique_cnas": 31,
 "importance": "Medium", "description": "Configuration requirements",
 "cna_scorecard_category": null}
```

**9.1% across its window (the most recent 6 months of CVE data), 31 CNAs.** Anyone repeating
"1.2%" as a novel discovery is wrong, and this note does not.

**The two numbers are not in conflict and must not be compared directly** — different
populations, different windows. Within KEV the rate is rising steadily by CVE year:

| KEV records by CVE year | n | filled | rate |
|---|---|---|---|
| pre-2020 | 555 | 0 | **0.0%** |
| 2020–2023 | 658 | 8 | 1.2% |
| 2024+ | 474 | 13 | **2.7%** |
| **all KEV** | **1,687** | **21** | **1.2%** |

So KEV's 1.2% is heavily weighted by a long pre-2020 tail where the field did not exist in
practice. Even the 2024+ slice (2.7%) sits below CNAScoreCard's 9.1%, but its window is
narrower still and its CNA mix is different, so **that residual gap is not established here** —
testing it needs the all-CVE population, which this repo does not hold.

**What is additive, then.** CNAScoreCard measures *presence*. Nothing measures *consequence* —
what a filled container is actually worth to someone trying to decide whether a CVE applies.
That is what the yield tables below do, and it is the only part of this note that is new.
A second, smaller addition: the KEV-specific rate and its trend by year.

## Who fills it

| container | filled | rate (Wilson 95%) |
|---|---|---|
| CNA `configurations` | 21 | **1.2%** [1%, 2%] |
| CNA `workarounds` | 45 | 2.7% [2%, 4%] |
| CNA `solutions` | 86 | 5.1% [4%, 6%] |
| **ADP (CISA Vulnrichment)** configurations + workarounds | 3 | **0.2%** [0%, 1%] |

CISA's own enrichment programme does not write precondition text either. Vulnrichment adds SSVC
decision points, CVSS, CWE and a KEV tag to essentially every KEV record — it never adds the
sentence saying what must be true for the CVE to apply.

Per CNA, every assigner with ten or more KEV entries:

| CNA | KEV entries | `configurations` | `workarounds` | `solutions` | median description |
|---|---|---|---|---|---|
| **palo_alto** | 14 | **71.4%** [45%, 88%] | 92.9% | 92.9% | 384 chars |
| mitre | 322 | 0.3% [0%, 2%] | 0.3% | 0.9% | 251 |
| **microsoft** | **377** | **0.0%** [0%, 1%] | 0.0% | 0.0% | **181** |
| cisco | 95 | 0.0% [0%, 4%] | 0.0% | 0.0% | 739 |
| apple | 94 | 0.0% [0%, 4%] | 0.0% | 0.0% | 324 |
| adobe | 74 | 0.0% [0%, 5%] | 0.0% | 0.0% | 324 |
| Chrome | 74 | 0.0% [0%, 5%] | 0.0% | 0.0% | 187 |
| oracle | 44 | 0.0% [0%, 8%] | 0.0% | 0.0% | 560 |
| **fortinet** | 29 | 0.0% [0%, 12%] | 0.0% | **69.0%** | 356 |
| ivanti | 17 | 0.0% [0%, 18%] | 0.0% | 0.0% | 191 |
| Citrix | 11 | 0.0% [0%, 26%] | 0.0% | 0.0% | 201 |

*(Full table of all 25 rateable CNAs: `coverage.py`, or `data/coverage_by_cna.csv`. 105 CNAs
appear in KEV; 25 have ten or more entries, and the other 249 entries sit with assigners too
small to give a rate.)*

**One CNA out of 25 uses the field.** Everyone else is at zero or rounding to it.

## Two rows that pre-empt the obvious objections

**"CNAs won't fill structured fields — too much overhead."** Fortinet fills `solutions` on
**69%** of its KEV records and `configurations` on **0%**. QNAP fills `solutions` on 42% and
`configurations` on 0%. The capability and the willingness are demonstrably there; this
particular field just isn't part of anyone's process.

**"The description already carries it."** Cisco writes the longest descriptions in KEV — a
median of **739 characters**, three times Microsoft's — and fills `configurations` 0% of the
time. Length is not the same as structure: prose that mentions a precondition somewhere cannot
be queried, diffed, or checked, and it is exactly what an extractor has to guess at.

## What the field is worth

From the 170-CVE extraction run over exploited edge/perimeter CVEs:

| population | CVEs | mean gates per CVE | records stating no precondition |
|---|---|---|---|
| container filled | 13 | **2.54** | **0 / 13 (0%)** |
| not filled | 157 | 1.15 | 50 / 157 (32%) |

That comparison is confounded with text length *by construction* — the container **is** the
extra text, which is the mechanism rather than a bias. The confound that would matter is CNA
identity: perhaps Palo Alto simply writes better advisories. So hold the assigner fixed:

| population | CVEs | mean gates per CVE | records stating no precondition |
|---|---|---|---|
| **palo_alto, container filled** | 8 | **2.88** | **0 / 8 (0%)** |
| **palo_alto, container NOT filled** | 3 | **0.00** | **3 / 3 (100%)** |
| juniper, container filled | 5 | 2.00 | 0 / 5 (0%) |
| juniper, container not filled | 1 | 1.00 | 0 / 1 |

**Same assigner. Same product family. With the field: 2.88 gates, never empty. Without it:
nothing, every single time.** Juniper points the same way on smaller numbers.

### The worked example

**CVE-2026-0257** (PAN-OS GlobalProtect authentication bypass). From the description alone, one
gate: *the GlobalProtect portal or gateway must be reachable*. From the description **plus** the
CNA's `configurations` container, three — the portal gate, plus **authentication-override
cookies enabled** and **a specific certificate configuration**.

Those last two exist nowhere in the description. A defender reading NVD cannot know that a
PAN-OS box without auth-override cookies is not exposed to this CVE. The CNA knew, wrote it
down in the right field, and almost nobody else does.

## Why it is empty: nobody was ever asked for it

The interesting question is not why CNAs skip the field but whether anyone ever told them to
use it. Traced end to end on 2026-09-03, every link is an absence rather than a refusal:

| where a CNA would look | what it says about `configurations` |
|---|---|
| **v4.0 draft** (`schema/archive/v4.0/DRAFT-JSON-file-format-v4.md`) | *"This is configuration information (**format to be decided**, we may for example support XCCDF or simple text based descriptions)."* A placeholder. |
| **The 5.x schema** ([`CVE_Record_Format.json`](https://raw.githubusercontent.com/CVEProject/cve-schema/master/schema/CVE_Record_Format.json)) | One line: *"Configurations required for exploiting this vulnerability."* `minItems: 1`, `uniqueItems: true`. No example. |
| **Rendered docs** ([anchor](https://cveproject.github.io/cve-schema/schema/docs/#oneOf_i0_containers_cna_configurations)) | Restates the schema, nothing more. For contrast `datePublic` gets *"**If known**, the date/time…"* — more usage guidance than the applicability field receives. |
| **CNA Operational Rules** [v4.0](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.0.pdf) and [v4.1.0](https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.1.0.pdf) | **Zero mentions.** The only applicable clause is §5.1.13: *"MAY contain optional elements supported by the CVE Record Format."* |
| [CVE Record Management Guidelines](https://www.cve.org/Resources/Roles/Cnas/CVE-Record-Management-Guidelines.pdf) | Zero mentions. |
| [Using Vulnogram with CVE Services](https://www.cve.org/Resources/Roles/Cnas/UsingVulnogramCVEServices.pdf) | Lists it under *"Additional optional fields … not included by default"*, labelled **"Required Configuration for Exposure"** — clearer than the schema's own wording, and hidden at the bottom of the editor. |
| [CPE Applicability Quick Start Guide](https://www.cve.org/Resources/Roles/Cnas/CPEinCVERecordsGuide.pdf) | Mentions it **only to route around it**: *"this array has been named `cpeApplicability` to avoid conflict with the existing and unrelated `configurations` array."* |
| **CNAScoreCard** | Tracked, `importance: Medium`, **scored zero** (null category). |

Two things follow.

**The Program writes quick-start guides for optional fields — just not this one.** The CPE
Applicability guide is 17 pages with worked examples, for an optional field, and it is the
template for what is missing here.

**1.2% is not negligence, it is an undocumented feature.** Palo Alto's 71% is what one vendor
reached unaided. Reading it as CNAs neglecting a duty gets the diagnosis, and therefore the
remedy, wrong.

> **A naming trap for anyone repeating this.** *Two different things are called
> "configurations".* NVD/CPE applicability statements use the term, and the CVE Program renamed
> its own new field `cpeApplicability` specifically to avoid the collision. This note is about
> `containers.cna.configurations`, the free-text container. Any argument that blurs the two
> will be dismissed on that alone.

## Limits

Stated plainly, because the numbers above are small.

- **13 CVEs with containers, across 2 CNAs.** The yield tables rest on that. They show the
  *kind* of gap and a within-CNA contrast; they do not establish its size across the ecosystem.
- **KEV only.** CISA-curated and exploited-by-definition. Container usage on the general CVE
  population is unlikely to be *higher* than 1.2%, but this does not measure it.
- **Gate counts come from an LLM extractor**, not from human reading. On a held-out set of 30
  unseen CVEs its gate agreement with an independent second annotator is 0.89 [0.74, 0.95]
  (kappa 0.93) — but both annotators are Claude models, so that is an upper bound and no human
  ceiling has been measured. See `README.md` → *Seventh pass*.
- **CNA rate intervals are wide where n is small.** Palo Alto's 71.4% is [45%, 88%] on 14
  records. The zeroes on large CNAs (Microsoft n=377, mitre n=322) are the tight ones.
- **The headline count is independently confirmed.** `scan_kev_cvelist.py` (1,687 CVEs) and
  `../pipeline/fetch_sources.py` (1,694, a later catalogue pull, different code path) both find
  **21** records with a filled `configurations` container, and they disagree on **none** of the
  1,687 CVEs they share. The denominator differs only by catalogue drift between fetch dates.
  The `workarounds` figures do *not* match across the two (45 vs 63) and should not be compared:
  the scan counts the CVE 5.x container only, while the fetch also counts Microsoft MSRC FAQ
  articles of type "Workaround", which are not in cvelistV5 at all. Only the `configurations`
  number is cross-validated.

## The ask

**CNAs should fill `configurations` when a precondition exists.** It is already in the schema,
it needs no new format, and the vendor best placed to know is the one already writing the
record.

Three routes, cheapest first:

1. **Ask CNAScoreCard to weight the field it already tracks.** This is the smallest possible
   change and the plumbing is done. In `cnascorecard_pipeline/config.py` the field is present
   in `CANONICAL_FIELDS` as `{"field": "containers.cna.configurations", "importance": "Medium",
   "cna_scorecard_category": null}` — **tracked and reported, but scored zero**, because a null
   category excludes it from the 100 points. Its scored siblings sit in the same list with a
   category attached. So the ask is not "build a metric", it is "give an existing tracked field
   a category" — plus the evidence for why it deserves one, which is what the yield tables
   above supply. `workarounds`, `solutions` and `exploits` are in exactly the same position.
2. **The CVE Quality Working Group**, with the 1.2% and the within-CNA contrast as the motivating
   evidence.
3. **A two-page quick-start guide**, modelled exactly on the CPE Applicability one — which
   proves the CVE Program writes these for optional fields — plus one line in CNA Rules §5.1
   naming the field. And/or **a GCVE Best Current Practice** on cited applicability
   preconditions (the ten rules, the record shape, the conformance set), as sketched in
   `STANDARDS.md` §5.

What is deliberately *not* proposed: a new file format, a new taxonomy, or a new standards body.
The field exists. It is empty.
