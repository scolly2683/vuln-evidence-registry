# Public comment — NIST request for information on modernizing the National Vulnerability Database

**Docket:** NIST-2026-0100 · **Deadline:** 13 October 2026 · **Topic area:** Data and standards

**Interest to declare:** none. I am an independent vulnerability-management practitioner
in Ireland; non-commercial, no product, nothing for sale. The figures below are from my own
measurement, described in each section.

## In short

The CVE record format has a field for the one thing a defender needs to know — **does this
vulnerability apply to my systems?** — and it is almost always empty. Konvu's comment on
this docket shows how empty: filled in on 1,211 of 360,436 records (0.34%).

What nobody has shown is what the field is worth when it *is* filled in. I measured that.
Same vendor, same products: **with the field, every record told me whether the
vulnerability applied. Without it, none did.**

I am asking for three things: require the field where the vendor knows the answer; make the
first piece of structure a plain three-way answer rather than a rich schema; and write the
field down somewhere a CNA will actually see it, because today nothing does.

## 1. What the field is worth

The field is `configurations` — in the schema's words, *"Configurations required for
exploiting this vulnerability."*

I took 170 vulnerabilities that CISA lists as actively exploited, on firewalls, VPNs and
similar edge equipment, and counted how many usable applicability conditions could be
extracted from the text the vendor published.

| | records | average conditions found | records yielding nothing |
|---|---|---|---|
| vendor filled in the field | 13 | **2.54** | **0 (0%)** |
| vendor did not | 157 | 1.15 | 50 (32%) |

The obvious objection is that the filled-in field is simply more text. So here is one
vendor compared with itself:

| Palo Alto Networks | records | average conditions found | records yielding nothing |
|---|---|---|---|
| **field filled in** | 8 | **2.88** | **0 (0%)** |
| **field left empty** | 3 | **0.00** | **3 (100%)** |

Same assigning organisation, same product family. **Eight filled records: every one yielded
a usable condition. Three empty ones: none did.** Three is a small number and I say so
again below; the pattern is consistent with the wider sample, and Juniper — the vendor
Konvu cites as using the field well — shows the same result on its five filled records.

Without the field, roughly a third of records yield nothing at all. With it, none did.
That is the evidence a "require it" recommendation needs.

## 2. "No special configuration is required" is an answer, not filler

Konvu reports that the most common value, in 62 records, is *"No special configuration is
required to be affected by this issue,"* and presents it as low-quality filler.

It is the opposite. **A vendor saying "nothing special is needed" tells you to stop
investigating and patch. A vendor saying nothing tells you only that nobody wrote anything
down.** Those are opposite instructions, and today they look identical to every tool,
because both arrive as an empty field.

So if the field is given structure, the first and most valuable piece is not a catalogue of
condition types. It is a machine-readable three-way answer:

- no condition applies — running the affected version is enough
- a condition applies, and here it is
- not assessed

Everything else can stay as prose. The draft version 4 of this schema left the field's
format *"to be decided"*, and it has gone unused since. My view — a view, not a finding —
is that a simple requirement vendors will meet is more useful than a richer format that takes years to
agree.

## What is weak about this evidence

- **The key contrast rests on 13 filled records from two vendors, and the within-vendor
  row on three empty ones.** It shows the kind of difference the field makes, not its size
  across the ecosystem. Someone should repeat it on a larger, less selective sample before
  it is used to set policy.
- **The population is CISA's exploited-vulnerabilities list only** — curated, and skewed
  towards large vendors, which is why its fill rate (21 of 1,687, 1.2%) is higher than the
  0.34% across all CVEs.
- **Conditions were extracted by an AI system, not read by a person.** I checked its output
  against a second, independent AI reader on 30 records it had not been tuned on; they
  agreed on 89% of conditions (a realistic range of 74–95%, given only 30). Both are models
  of the same family, so treat 89% as a best case. A check against a human reader is not
  yet done.
- **I am not a CNA.** This is a consumer's view of the data.

## What I am asking for

1. **Require `configurations` where the vendor already knows the answer.** Section 1 is the
   evidence.
2. **Start with the three-way answer** — no condition / condition, here it is / not assessed
   — before any richer format. Section 2 is the reason.
3. **Write the field down where a CNA will see it.** The CNA Operational Rules, versions 4.0
   and 4.1.0, **mention it zero times**; only the general clause 5.1.13 ("MAY contain
   optional elements") applies. The authoring tool Vulnogram already offers it, under the
   clearer name "Required Configuration for Exposure", at the bottom of an optional-extras
   list. The CVE Program has published a short quick-start guide for another optional field
   (CPE applicability); one for this field would close the gap. Near-zero usage looks less
   like unwilling vendors than like a field nobody was told about.
4. **Publish coverage as a rate, by year of publication, and keep the series.** The
   community-run CNAScoreCard already tracks this field, but assigns it no weight in a CNA's
   score, and reports it as the share of CNAs that have ever used it rather than the share of
   records that carry it. A repeated public measurement, as a record-level rate, gives CNAs
   something to be measured against.

## One point about naming

Two different things are called "configurations": NVD's CPE applicability statements, and
this free-text CVE field. The CVE Program named its newer field `cpeApplicability`
specifically *"to avoid conflict with the existing and unrelated configurations array."*
This comment is about the latter only. Structuring it should resolve that clash, not
inherit it.

## Sources

- CVE record format schema: <https://cveproject.github.io/cve-schema/schema/CVE_Record_Format.json>
- Konvu, *"NIST is asking how to fix the NVD, go tell them"*, 18 Aug 2026: <https://konvu.com/blog/how-to-fix-the-nvd>
- CNA Operational Rules v4.1.0: <https://www.cve.org/Resources/Roles/Cnas/CNA_Rules_v4.1.0.pdf>
- CNAScoreCard field-utilisation data: <https://github.com/RogoLabs/CNAScoreCard>
- CPE applicability quick-start guide: <https://www.cve.org/Resources/Roles/Cnas/CPEinCVERecordsGuide.pdf>
