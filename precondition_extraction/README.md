# Precondition extraction

Extracting structured applicability data — CPE-style product identity plus the *preconditions*
under which a vulnerability actually applies — from CVE and GHSA advisory text.

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
└── tests/
    ├── test_extractor.py
    ├── test_fixture_schema.py
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
  releases A, B, and C") — it reproduces all three shipped fixtures exactly, and is tested against
  them (`tests/test_extractor.py`).
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
