# Fixture schema

A **fixture** here is one test case: one real advisory's text, paired with the structured
applicability data we expect a future extractor to pull out of it. One file per CVE, in YAML
(the same plain-text, human-readable data format the routing registry uses elsewhere in this
repo — a `.yaml` file is just a structured way of writing down key/value data that both people
and code can read).

Why YAML and not JSON: JSON is fine for machines but awkward for a human to read or edit by hand
(no comments, fussy commas). YAML lets us write comments explaining *why* a value is what it is —
useful here since precondition wording is often subtle — while still being easy for test code to
load.

## Fields

```yaml
cve_id: string                    # e.g. "CVE-2021-44228" — always required.
ghsa_id: string or null           # a GitHub Security Advisory ID, if the finding also has one.
source: nvd | ghsa | msrc         # which advisory database advisory_text was drawn from. msrc =
                                   # the Microsoft Security Update Guide per-CVE record (title +
                                   # FAQ articles, HTML stripped) — NVD is title-only for MSRC CVEs,
                                   # see ../../evaluation/README.md, "Source finding".
source_url: https://...           # the advisory page advisory_text came from — provenance is
                                   # mandatory here, same as everywhere else in this repo.
retrieved: YYYY-MM-DD              # date we captured advisory_text — advisory text can be revised
                                   # later (NVD entries get amended), so this pins what we tested
                                   # against.

advisory_text: |
  The advisory's own description, reproduced as published. This is the "raw material" — what
  an extractor would actually be given as input. Multiple paragraphs are fine.

expected:
  # --- the CPE-style "what software is this" half ---
  identity:
    vendor: string
    product: string
    cpe: string or null           # a CPE 2.3 identifier, if one applies. CPE is the industry
                                   # naming scheme for "vendor + product + version" — think of it
                                   # as a barcode for a specific piece of software.
    purl: string or null          # a "package URL" — the equivalent identifier for a package
                                   # ecosystem (npm, PyPI, Maven...), used when the advisory is
                                   # ecosystem-native (e.g. a GHSA) rather than CPE-native.

  # --- the version range the advisory says is affected ---
  affected_versions:
    introduced: string or null    # first vulnerable version (null if "always has been").
    fixed: string or null         # the version an ordinary upgrade should land on to be safe.
    excluded_fixed: [list]        # backport/point-release versions that ALSO fix it, out of
                                   # normal version order (Log4j's 2.12.2 is the textbook case:
                                   # numerically older than 2.15.0, but also a genuine fix, for
                                   # people who couldn't jump to Java 8+).
    notes: string or null         # anything about the version range that a simple
                                   # introduced/fixed pair can't capture cleanly.

  # --- the actual point of this module: does the CVE apply HERE? ---
  # An EMPTY list is valid and meaningful — an explicit claim, with two distinct readings the
  # fixture's notes must distinguish: "genuinely nothing gates applicability" (CVE-2018-7600 —
  # default configurations are exploitable) vs. "this advisory text states no precondition,
  # though one may truly exist" (CVE-2019-5418 — the render file: gate lives only in the Rails
  # release announcement, so a text-only extractor cannot recover it).
  preconditions:
    - id: short-machine-slug        # a stable short name for this one condition.
      statement: >-
        A plain-English sentence stating the condition, close to how the advisory phrases it.
      category: configuration | deployment | api-usage | network-reachability | platform
        # configuration     — a setting/flag/feature toggle (e.g. "JNDI lookups enabled")
        # deployment        — how/where the software is run (e.g. "reachable via CGI")
        # api-usage         — which function/method the calling code invokes
        # network-reachability — what the vulnerable host can reach or be reached by
        # platform          — which OS/runtime/environment it's running on
      enabled_by_default: true | false | null   # null = advisory doesn't say either way.
      required_for_exploit: true | false        # false = raises risk/impact but isn't strictly
                                                 # required for the CVE to be exploitable at all.
      cites: >-                                  # the advisory sentence this rests on, verbatim.
        Exact sentence from advisory_text.       # Optional for the first 13 fixtures; every
                                                 # record in ../../evaluation/ carries one, and the
                                                 # validator rejects a cites that is not a substring
                                                 # of advisory_text. Rule 2: no citation, no
                                                 # precondition — this is what makes a record
                                                 # checkable rather than plausible.

  # --- optional: advisory sentences that are NOT preconditions but shouldn't be dropped ---
  # A keyword extractor over-flags; hand review sorts its false matches into two useful bins
  # rather than discarding them. Both fields are optional — omit them when a fixture has none.
  remediation_notes:               # fix/workaround history, using CSAF's remediation vocabulary
    - category: vendor_fix | workaround | mitigation | none_available | no_fix_planned
        # CSAF — the Common Security Advisory Framework, the OASIS standard for
        # machine-readable advisories; these five categories are its remediation types.
      text: >-
        The advisory sentence, verbatim (e.g. "From log4j 2.15.0, this behavior has been
        disabled by default.").
  general_notes:                   # free-text: flaw/mechanism description worth keeping
    - >-
      An advisory sentence, verbatim, that describes the flaw or the attacker's mechanism
      rather than an applicability condition or a remediation.

  notes: string or null           # anything about the extraction itself worth flagging — e.g.
                                   # how and when advisory_text was verified against source_url,
                                   # or a quirk of the original wording worth preserving.
```

## Why this shape

- **identity** and **affected_versions** answer the same question pattern-1/2's evidence-source
  registry already answers well (KEV, EPSS, SSVC): *is this CVE in scope at all?* The gap this
  module targets is the 67%-of-CVEs-have-no-CPE-at-disclosure problem documented in
  `docs/ownership-and-sources.md` — this data is meant to exist even before NVD publishes CPEs.
- **preconditions** is new: it answers *does this CVE actually apply to THIS deployment?*, which
  a bare CPE match can't. A CVE that "requires the optional JNDI lookup feature to be enabled" and
  one that "always applies once you're on an affected version" should never be triaged the same
  way — but today that distinction lives only in advisory prose, unless someone reads it by hand.
- Every fixture is a **real, published CVE** with real advisory wording, not synthetic text — the
  same principle as the routing registry's regression fixtures (`fixtures/regression.yaml`):
  frozen real cases an extractor either handles correctly or doesn't.
