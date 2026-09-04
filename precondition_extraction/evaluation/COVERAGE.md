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

1. **Propose it as a metric to [cnascorecard.org](https://cnascorecard.org).** It already
   publishes per-CNA CVE-record quality grades against CVEDQAF. An "applicability" column —
   does this CNA fill `configurations` / `workarounds` when the vulnerability has a
   precondition — is a natural addition, the data pipeline already exists, and measurement is
   what moved CNA behaviour on CVSS and CWE.
2. **The CVE Quality Working Group**, with the 1.2% and the within-CNA contrast as the motivating
   evidence.
3. **A GCVE Best Current Practice** on cited applicability preconditions — the ten rules, the
   record shape and the conformance set — as sketched in `STANDARDS.md` §5.

What is deliberately *not* proposed: a new file format, a new taxonomy, or a new standards body.
The field exists. It is empty.
