# Public comment — NIST RFI on Modernizing the National Vulnerability Database

**Docket:** NIST-2026-0100 · Federal Register 2026-16371 (12 August 2026)
**Deadline:** 13 October 2026, 11:59pm ET · submit at regulations.gov
**RFI topic area addressed:** Data and standards (one area only, per the notice's
"any or all")

> **DRAFT — not filed.** Fill the three placeholders marked `[…]` before submitting.
> Comments are posted publicly and without redaction: include no address, phone number
> or anything else you would not publish. See *Before you file* at the end.

---

**Submitted by:** `[NAME]`, `[independent vulnerability-management practitioner, Ireland —
adjust as you wish]`
**Basis:** an independent, non-commercial research project. No product, no vendor
interest, nothing for sale. All data, code and results cited below are public and
reproducible: <https://github.com/scolly2683/vuln-evidence-registry>

## Summary

One field in the CVE Record Format already answers the question every defender asks —
does this vulnerability apply to my deployment? — and it is almost always empty. Others
have measured how empty. This comment adds the measurement that is missing: **what the
field is worth when it is filled**, and it is worth a great deal. It also proposes one
narrow correction to how "structured" should be interpreted, and offers NIST a working
public benchmark of the kind the community has asked it to create.

Three points follow.

## 1. The field's presence is worth something measurable, and nobody had measured it

`containers.cna.configurations` is defined by the schema as *"Configurations required for
exploiting this vulnerability."*

Konvu's comment on this docket reports that it is populated in **1,211 of 360,436**
published records (0.34%), and that six organisations write 78% of those. CNAScorecard
(RogoLabs) tracks the field and reports how many assigners have ever used it. Both
measure **presence**. Neither measures **consequence**.

I ran a citation-checked extraction over 170 exploited (CISA KEV) edge/perimeter CVEs,
recording for each how many applicability conditions could be extracted from the text a
CNA actually published:

| population | CVEs | mean conditions extracted | records yielding none |
|---|---|---|---|
| CNA filled `configurations` | 13 | **2.54** | **0 (0%)** |
| CNA did not | 157 | 1.15 | 50 (32%) |

That comparison is confounded with text length by construction — the container *is* the
extra text — so the meaningful test holds the assigner fixed:

| population | CVEs | mean conditions | records yielding none |
|---|---|---|---|
| **Palo Alto, container filled** | 8 | **2.88** | **0 (0%)** |
| **Palo Alto, container NOT filled** | 3 | **0.00** | **3 of 3 (100%)** |
| Juniper, container filled | 5 | 2.00 | 0 (0%) |

**Same assigner, same product family.** With the field, every record yielded usable
applicability conditions. Without it, not one did. Juniper — the vendor Konvu cites as
using the field properly — behaves the same way.

This is the evidence a "require it" recommendation needs and does not currently have. The
field is not merely under-used; its absence is the difference between a defender being
able to scope a CVE and not.

## 2. "No special configuration is required" is not filler — and structure must preserve it

Konvu reports that the single most common value, in 62 records, is *"No special
configuration is required to be affected by this issue."*

I would ask NIST not to treat those records as noise. **An affirmative negative is a
different and useful claim from silence.** A record that says "nothing gates this" tells a
defender to stop investigating and patch. A record that says nothing tells them only that
the CNA did not write anything down — which may mean no precondition exists, or may mean
one exists and went unrecorded. Those are opposite operational instructions and they are
currently indistinguishable.

In the extraction standard used for the data above, this distinction is a first-class
rule: an empty result must declare which of the two readings it is. It is cheap to
implement and it removes a real ambiguity.

**Recommendation:** if `configurations` is given structure, the minimum viable structure
is not a taxonomy of conditions. It is a required, machine-readable distinction between
*"no precondition applies"*, *"a precondition applies and here it is"*, and *"not
assessed"*. Everything else can remain free text.

I would urge caution on richer structure, for a documented reason. This field's format was
left undecided once before: the v4.0 draft schema records it as *"configuration
information (format to be decided, we may for example support XCCDF or simple text based
descriptions)"*. That decision was never resolved, and the field has sat nearly unused
since. **Free text a CNA will actually write beats a schema that stalls.** Requiring the
three-way distinction now, and layering richer structure later, avoids repeating that
history.

## 3. A public exploitability benchmark of the kind being asked for already exists

Among the recommendations already on this docket is a call to *"publish a versioned public
benchmark of CVEs with ground-truth exploitability labels."* I support it, and offer a
working starting point rather than only a request.

The project cited above maintains:

- a ten-rule extraction standard in which **every extracted condition must quote the
  advisory sentence it rests on**, verified mechanically as a substring — a condition the
  text does not support cannot be stored;
- a **50-record development set** and a **30-record held-out set** drawn from CISA KEV,
  stratified, with the rule set frozen by hash against the held-out draw so it cannot be
  tuned after the fact;
- a scorer, and results published with confidence intervals and a written list of the
  method's own weaknesses.

On the held-out records, scored against an independently produced reference: **43 of 43
citations valid; the two "no precondition" readings agreed on 29 of 29 records;
condition-level agreement 0.89 (95% CI 0.74–0.95), Cohen's kappa 0.93.**

It is offered as a public artefact, under a non-commercial licence, for NIST or the CVE
Program to adopt, fork, criticise or replace.

## Limits of the evidence above

Stated plainly, because a comment that hides its own weaknesses is worth less than one
that does not.

- **The yield finding rests on 13 CVEs with filled containers, across two CNAs.** It
  demonstrates the kind of gap and a within-assigner contrast. It does not establish the
  size of the effect across the ecosystem. It should be replicated on a larger, non-KEV
  population before being relied on for policy.
- **The population is CISA KEV only** — curated, and exploited by definition. The
  container rate I measure there (21 of 1,687, 1.2%) is higher than Konvu's all-corpus
  0.34%, consistent with KEV skewing toward large vendors. Within KEV the rate rises by
  year: 0.0% pre-2020, 1.2% for 2020–2023, 2.7% for 2024 onward.
- **The condition counts come from an AI extractor, not from human reading.** Its
  agreement figure above is against a second AI annotator; both are models from the same
  family, so their errors may be correlated and 0.89 should be read as an upper bound. A
  human inter-annotator study is designed but not yet complete, and the absence is
  recorded in the project's own documentation.
- I am not a CNA and do not publish CVE records. This is a consumer's view of the data.

## What I am asking for

1. **Require `configurations` where the CNA already knows the answer** — supporting the
   recommendation already before you, with the evidence in section 1.
2. **Make the minimum structure a three-way distinction** — no precondition applies / a
   precondition applies / not assessed — before any richer schema, per section 2.
3. **Give the field a written home.** It is absent from the CNA Operational Rules (v4.0
   and v4.1.0 mention it zero times; only §5.1.13 "MAY contain optional elements"
   applies). The CVE Program has published a quick-start guide for another optional field
   (CPE Applicability Statements) — the same for this one would cost little. The current
   1.2%–0.34% is better explained by an undocumented field than by unwilling CNAs: the
   authoring tool (Vulnogram) already exposes it, under the clearer label "Required
   Configuration for Exposure", at the bottom of an optional-fields list.
4. **Publish enrichment and field-coverage as a rate by publication cohort** — supporting
   the recommendation already before you. Measurement is what moved CNA behaviour on CVSS
   and CWE.

## A note on terminology

Two different things in this ecosystem are called "configurations": NVD/CPE applicability
statements, and the CVE Record Format's free-text `containers.cna.configurations`
container. The CVE Program named its own newer field `cpeApplicability` explicitly *"to
avoid conflict with the existing and unrelated configurations array"*. This comment
concerns only the latter. Any structuring effort should resolve the name collision
rather than inherit it.

## Sources

- CVE Record Format schema: <https://cveproject.github.io/cve-schema/schema/CVE_Record_Format.json>
- Konvu, *"NIST is asking how to fix the NVD, go tell them"*, 18 Aug 2026:
  <https://konvu.com/blog/how-to-fix-the-nvd>
- CNAScoreCard (RogoLabs): <https://github.com/RogoLabs/CNAScoreCard>
- CNA Operational Rules v4.1.0:
  <https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.1.0.pdf>
- CPE Applicability Statements quick-start guide:
  <https://www.cve.org/Resources/Roles/Cnas/CPEinCVERecordsGuide.pdf>
- Data, code and full method for every figure above:
  `[REPO URL AT A PINNED COMMIT — see "Before you file"]`

---

## Before you file — checklist

- [ ] **Pin the repository link.** The data and code are currently on the
      `heldout-validation` branch. Merge to `main` first, or cite a commit SHA
      (`.../vuln-evidence-registry/tree/<sha>`) so the link cannot rot or shift under a
      reader. A federal comment is permanent; the URL in it should be too.
- [ ] **Fill `[NAME]` and the description of yourself.** "Independent vulnerability-
      management practitioner" is accurate and sufficient; a current employer is neither
      required nor, given the project's independence, desirable.
- [ ] **Re-read section 3's numbers against the repo** before filing. They are correct as
      of 2026-09-04; if the held-out work advances, update or delete the claim rather than
      letting it drift.
- [ ] **No personal data.** regulations.gov posts comments in full, without redaction.
- [ ] Optional: tell Konvu you filed. They asked people to, and a second independent
      submission on the same field is worth more than one.
