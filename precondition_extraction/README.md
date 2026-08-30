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
└── tests/
    └── fixtures/          # one file per real CVE/GHSA: advisory text in, expected
                            # structured output out. See fixtures/README.md for the schema.
```

Implementation to follow — the fixtures come first so the extractor has a concrete target to be
graded against from day one, rather than a spec written in prose.
