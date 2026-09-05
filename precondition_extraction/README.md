# Precondition extraction

Extracting structured applicability data — CPE-style product identity plus the *preconditions*
under which a vulnerability actually applies — from CVE and GHSA advisory text.

## Where this stands — 5 September 2026

**What was built, and why, in one paragraph.** A vulnerability applies to a host only when the
conditions in the vendor's advisory are met, and no scanner reads those conditions; it reads
versions. This module turns the conditions into *cited preconditions* — a ten-rule standard where
every condition quotes the advisory sentence it rests on, checked mechanically, frozen in
`evaluation/PROMPT.md`, restated for people in `evaluation/RULES.md` with an eight-step recipe
that was executed end to end (three single-CVE commands in `tools/`). It is measured, not
asserted: 50 reference records, a 30-record held-out set (two model readers agree on 89% of
gates, 95% interval 74–95%; no human ceiling yet), and a coverage study (`evaluation/COVERAGE.md`)
showing the CVE Program's own `configurations` field is filled on 1.2% of CISA KEV — and that
where one vendor fills it, extraction never comes up empty (2.88 gates vs 0.00, same assigner).
That measurement is filed as a public comment on NIST's NVD RFI (`evaluation/rfi/`, docket
NIST-2026-0100, **deadline 13 October 2026**, no repository link by decision). The layer below
is proven on one CVE: `checks/CVE-2024-38475/` compiles the record's three gates into a
deterministic script that quotes the config line it matched (two gates decidable, one honestly
`not_assessed`), with eight fixtures, 37 tests and the Tenable / Qualys / Wiz / Defender /
Ansible ways to run it fleet-wide — each labelled "per published docs, not run on a live
tenant". Findings that bound the next step: **no product evaluates a precondition natively**
(all four are version-tier; Cisco's advisories are the closest prior art, in prose, for their own
kit; OVAL has been able to express this since 2005 and nobody writes it); the join from "gate
absent on host X" to "not_affected for the version finding on host X" is the registry's
suppression stage, not any vendor's; and appliances — where the exploited "93" actually live —
are unreadable by every product. **What was deliberately not built:** no platform, no findings
store, no tier-0 run sheet (the owner's database already carries KEV/EPSS). **The next decision
needs one input:** the distinct CVE ids in the owner's exploitable bands (public identifiers,
nothing else), intersected with these records, to say how many have a decidable gate — that
number decides whether the five-CVE Qualys pilot (measure the *absent* rate) is worth doing.
The only build worth considering after that is a record→OVAL compiler, which would let existing
scanners evaluate preconditions with no product change.

## Why

The routing registry's identity matching is advisory-first for a reason: in a measured month,
67% of published CVEs had **no CPE data at NVD at disclosure time**. The information is usually
*in* the advisory — vendor, product, affected version ranges, and the conditions that gate
exploitability ("only when the optional X module is enabled", "requires non-default configuration
Y", "Windows only") — but as prose, not as structured data anything downstream can match on.

That gap costs twice:

1. **Identity**: without structured product/version data, findings can't be routed or deduplicated
   until NVD catches up (days to weeks later, sometimes never).
2. **Applicability**: even with a CPE match, a CVE that only applies under a non-default
   configuration is routinely triaged as if it applies everywhere — the precondition lived in a
   sentence nobody encoded.

This module extracts both into a structured, reviewable form at disclosure time, from the
advisory text itself (CVE descriptions, CNA-supplied affected data, GHSA advisories).

## The pattern

This follows the same registry style as patterns 1–2 elsewhere in this repo
(`vuln_evidence_registry/` — the evidence-source registry and the BOD 26-04 timeline engine):

- **One declarative registry as the single source of truth.** Extraction rules and precondition
  vocabularies are data, not scattered conditionals; outputs (structured applicability records,
  match predicates) are *composed* from the registry so there is no second place to update.
- **Pure stdlib where possible**, small and dependency-light.
- **Tests pin the behaviour**, including the known failure modes — extractions are only useful if
  regressions can't creep in silently. Every fielded misextraction should become a permanent
  fixture, in the same spirit as the routing registry's correction fixtures.

## Layout

```
precondition_extraction/
├── README.md              # this file
├── extractor.py            # first-pass version-range + precondition extractor
├── verifier.py              # second-pass Claude review of the extractor's candidates
├── schema.py                # loads/validates fixtures against tests/fixtures/schema.json
├── evaluation/              # the 50-record KEV reference set, model runs scored against it,
│                            # the scorer (compare.py), the runner, and the source ladder — README.md
└── tests/
    ├── test_extractor.py
    ├── test_fixture_schema.py
    ├── test_evaluation_reference.py
    └── fixtures/
        ├── README.md        # the fixture schema, explained in plain English
        ├── schema.json       # the same schema as a formal JSON Schema document
        ├── CVE-2021-44228.yaml
        ├── CVE-2014-6271.yaml
        └── CVE-2020-14343.yaml
```

## What's actually built vs. still a stub — read this before trusting any output

Following this repo's own honesty rule (see `STATUS.md`): here is exactly what works today.

- **Version-range extraction (`extract_version_range`) is solid** for the phrasings NVD/GHSA
  commonly use ("X through Y", "before X", "From version X ... completely removed", "excluding
  releases A, B, and C") — it reproduces the three original fixtures exactly, and is tested
  against them (`tests/test_extractor.py`). The wider fixture corpus (13 CVEs) deliberately
  includes phrasings it does NOT handle yet — "prior to X", per-branch fix lists like Drupal's,
  product enumerations like Windows SKUs — so the fixtures are the target to grow into, not a
  score the current code already achieves.
- **Precondition extraction (`extract_precondition_candidates`) is a first pass only.** It splits
  advisory text into sentences and tags each with a category by keyword — a starting point for a
  human to confirm or correct, never a final verdict. Categorization is score-based: the category
  with the most keyword hits in a sentence wins, with a fixed priority order breaking ties. That
  design came out of a real miss: an earlier version took the first category with *any* hit, so
  CVE-2014-6271's one precondition sentence was tagged "configuration" off a single incidental
  word ("...in which *setting* the environment occurs..." — "setting" as a plain verb), outranking
  seven genuine deployment cues in the same sentence. Scoring fixed that
  (`test_shellshock_categorized_as_deployment` pins it), but keyword matching remains inherently
  approximate — e.g. "function" still matches inside "functionality" — so treat every candidate as
  "worth a human's second look," not a verdict.
- **The Claude review pass (`verifier.py`) is built and unit-tested, but the tests use a
  stand-in for the API** — the live call has not been exercised from CI (it needs an
  `ANTHROPIC_API_KEY` and costs money per call, so it never belongs in the automated test run).
  What it does: one read-only API call — no tools of any kind offered to the model — that takes
  the advisory text plus the extractor's candidates and returns, per candidate, genuine
  precondition vs. false match, a cited sentence, and a one-line reason. Claude's citation is
  re-checked locally against the advisory text; a quote that isn't actually in the advisory is
  flagged (`citation_found_in_advisory: false`) rather than trusted. Install with
  `pip install -e ".[verify]"`.
- **Identity extraction (turning "GNU Bash" or "the PyYAML library" into a CPE/purl identifier) is
  not attempted here at all.** That's a lookup-against-a-dictionary problem, not a text-extraction
  problem — it belongs with pattern 1's evidence-source registry, not duplicated here.

In short: trust the version ranges, treat the precondition candidates as "worth a human's second
look," and don't expect identity data yet.
