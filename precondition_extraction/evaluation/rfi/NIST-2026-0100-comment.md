# Public comment — NIST request for information on modernizing the National Vulnerability Database

**Docket:** NIST-2026-0100 · Federal Register 2026-16371 (12 August 2026)
**Deadline:** 13 October 2026, 11:59pm ET · file at regulations.gov
**Topic area:** Data and standards. The notice says a comment may address any or all
areas; this one addresses a single field.

> **DRAFT — not filed.** Fill in the two placeholders marked `[…]`, and read the
> checklist at the end. Comments are published in full and are never redacted, so
> include nothing you would not want public.

---

**From:** `[NAME]`, independent vulnerability-management practitioner, Ireland
**Interest to declare:** none. This is an independent, non-commercial project. I have no
product and nothing for sale. All the data and code behind the numbers below is public:
<https://github.com/scolly2683/vuln-evidence-registry>

## In short

The CVE record format already has a field for the one thing every defender needs to know:
**does this vulnerability actually apply to my systems?** The field is nearly always
empty.

Others have already told you *how* empty. What nobody has shown is **how much it matters
when it is filled in.** That is what I measured, and the answer is: it matters a lot.

I have three things to say, and I have put the weaknesses of my own evidence at the end
rather than leaving them out.

## 1. When the field is filled in, you can work out whether a CVE applies. When it is empty, usually you cannot.

The field is `configurations`. The schema describes it as *"Configurations required for
exploiting this vulnerability."*

Another comment on this docket reports that it is filled in on **1,211 of 360,436**
published records — about **0.34%** — and that six organisations write 78% of those. A
separate public project tracks how many CNAs have ever used it. Both count **how often the
field is present.** Neither asks **what difference it makes.**

So I took 170 vulnerabilities that CISA lists as actively exploited, on firewalls, VPNs
and similar edge equipment, and counted how many usable applicability conditions could be
pulled out of whatever text the vendor actually published:

| | vulnerabilities | average conditions found | records where nothing could be found |
|---|---|---|---|
| vendor filled in the field | 13 | **2.54** | **none (0%)** |
| vendor did not | 157 | 1.15 | 50 (32%) |

An obvious objection: of course you find more, the filled-in field is simply more text.
Fair. So here is the same question asked **of a single vendor**, comparing their own
records with and without it:

| | vulnerabilities | average conditions found | records where nothing could be found |
|---|---|---|---|
| **Palo Alto — field filled in** | 8 | **2.88** | **none (0%)** |
| **Palo Alto — field left empty** | 3 | **0.00** | **all 3 (100%)** |
| Juniper — field filled in | 5 | 2.00 | none (0%) |

Same company. Same products. Same people writing the advisories.

**When they filled the field in, every single record told me something I could act on.
When they left it empty, not one did.**

Juniper behaves the same way — and Juniper is the vendor another commenter singled out as
using the field well.

That is the missing piece in the argument for requiring this field. The problem is not
just that the field is rarely used. It is that without it, a defender usually cannot tell
whether a vulnerability applies to them at all.

## 2. "No special configuration is required" is a useful answer, not padding

Another comment notes that the most common value in the field, appearing in 62 records, is
*"No special configuration is required to be affected by this issue."* It is offered as an
example of low-quality filler.

I would ask you not to read it that way. **A vendor saying "nothing special is needed" is
telling you something. A vendor saying nothing at all is not.**

Those are opposite instructions in practice:

- *"Nothing gates this"* means: stop investigating, patch it.
- *Silence* means: nobody wrote anything down. There may be no condition, or there may be
  one that went unrecorded. You cannot tell which.

Today those two look identical to any tool reading the data, because both come out as an
empty field.

**What I would ask for:** if you give this field structure, the first and most important
piece is not a detailed catalogue of condition types. It is a simple, machine-readable
answer to three options:

- no condition applies — running the affected version is enough
- a condition applies, and here it is
- not assessed

Everything else can stay as ordinary prose.

I would be cautious about anything more ambitious, for a reason that is on the record. The
draft version 4 of this schema described the same field as *"configuration information
(format to be decided, we may for example support XCCDF or simple text based
descriptions)"*. That decision was never made, and the field has gone almost unused ever
since. **Plain text that a vendor will actually write beats a rich format that never gets
agreed.** Ask for the three-way answer now. Add structure later, if it is wanted.

## 3. A public test set of the kind being asked for already exists, and you are welcome to it

Another recommendation on this docket asks NIST to publish a versioned public benchmark of
CVEs with ground-truth exploitability labels. I support that, and rather than only ask for
it, I can offer a starting point.

The project linked above maintains:

- **A written standard** for pulling applicability conditions out of advisory text. Its
  central rule is that **every condition must quote the sentence it came from**, word for
  word. The quote is checked automatically against the original advisory. If a condition
  cannot be traced to the text, it is thrown away rather than stored.
- **Two sets of hand-checked records** drawn from CISA's exploited-vulnerabilities
  catalogue: 50 used to develop the standard, and a separate 30 held back and never used
  to tune it. The rules were locked before those 30 were touched, so they cannot be
  adjusted after the fact to flatter the result.
- **Published results, with the uncertainty shown** and a written list of the method's own
  weaknesses.

On the 30 held-back records, checked against a second, independently produced set of
answers:

- **every one of the 43 quoted sentences was genuine** — 43 of 43
- **the two readers agreed on all 29 records where the answer was "no condition"** —
  29 of 29
- **they agreed on 89% of the conditions themselves** (with a realistic range of 74%–95%,
  given only 30 records)

It is free to use, under a non-commercial licence. NIST, the CVE Program or anyone else is
welcome to adopt it, extend it, pull it apart, or replace it with something better.

## What is weak about my evidence

I would rather tell you this than have you find it.

- **The main result rests on 13 records, from two vendors.** It shows the *kind* of
  difference the field makes, and it holds up when I compare a single vendor against
  itself. It does not tell you the size of that difference across the whole ecosystem.
  Somebody should repeat this on a larger and less selective sample before it is used to
  justify policy.
- **I only looked at CISA's exploited-vulnerabilities catalogue.** That list is curated,
  and everything on it is known to be exploited. The fill rate I measure there — 21 of
  1,687, about 1.2% — is higher than the 0.34% measured across all CVEs, which fits, since
  that list leans towards large vendors. Within it the rate is rising: 0% before 2020,
  1.2% for 2020–2023, 2.7% from 2024 onward.
- **The conditions were extracted by an AI system, not read by a person.** The 89%
  agreement figure above is agreement with a second AI system from the same family, so the
  two may share blind spots and 89% should be treated as a best case, not a fair estimate.
  A comparison against a human reader is designed but not yet done, and that gap is written
  down in the project's own documentation.
- **I am not a CNA.** I do not publish CVE records. This is the view from someone who
  consumes this data, not someone who produces it.

## What I am asking for

1. **Require the `configurations` field where the vendor already knows the answer.** This
   supports a recommendation already before you. Section 1 is the evidence for it.
2. **Start with the three-way answer** — no condition / condition, here it is / not
   assessed — before any richer format. Section 2 explains why.
3. **Write the field down somewhere a CNA will see it.** It is not mentioned at all in the
   CNA Operational Rules (versions 4.0 and 4.1.0 mention it zero times; only the general
   clause 5.1.13, "MAY contain optional elements", applies). The CVE Program has already
   published a short quick-start guide for another optional field, CPE applicability
   statements. The same for this one would cost very little. I think the near-zero usage
   is better explained by a field nobody was told about than by unwilling vendors: the
   main authoring tool, Vulnogram, already offers it — under the clearer name "Required
   Configuration for Exposure" — tucked at the bottom of a list of optional extras.
4. **Publish coverage as a rate, by year of publication, and keep the series going.** Also
   supports a recommendation already before you. Publishing the measurement is what moved
   vendor behaviour on severity scores and weakness classifications.

## One point about naming

Two different things in this ecosystem are called "configurations": the CPE applicability
statements used by the NVD, and this free-text field in the CVE record format. The CVE
Program named its own newer field `cpeApplicability` specifically *"to avoid conflict with
the existing and unrelated configurations array"*. This comment is only about the second
one. Any work to structure it should fix that name clash rather than inherit it.

## Sources

- CVE record format schema:
  <https://cveproject.github.io/cve-schema/schema/CVE_Record_Format.json>
- Konvu, *"NIST is asking how to fix the NVD, go tell them"*, 18 August 2026:
  <https://konvu.com/blog/how-to-fix-the-nvd>
- CNAScoreCard (RogoLabs): <https://github.com/RogoLabs/CNAScoreCard>
- CNA Operational Rules v4.1.0:
  <https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.1.0.pdf>
- CPE applicability statements quick-start guide:
  <https://www.cve.org/Resources/Roles/Cnas/CPEinCVERecordsGuide.pdf>
- All data, code and method behind the figures above:
  `[REPO LINK, PINNED — see checklist]`

---

## Checklist before filing

- [ ] **Pin the link.** The data and code are on a branch that has not been merged yet.
      Merge it, or link to a specific commit (`.../vuln-evidence-registry/tree/<commit>`),
      so the link still works years from now. This comment is permanent.
- [ ] **Fill in `[NAME]`.** "Independent vulnerability-management practitioner" is accurate
      and enough. Leave out any employer — the independence is the point.
- [ ] **Re-check the numbers in section 3** against the repository before filing. They are
      correct as of 4 September 2026. If the work moves on, update them or cut the claim.
- [ ] **No personal details.** Comments are posted in full, without redaction.
- [ ] Optional: let Konvu know you filed. They asked people to, and two independent
      comments about the same field carry more weight than one.
