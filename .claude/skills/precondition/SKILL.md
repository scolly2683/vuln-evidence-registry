---
name: precondition
description: Extract structured applicability preconditions from a vulnerability advisory, following this repo's precondition_extraction schema and citation discipline. Use whenever the user invokes /precondition, asks what conditions gate a CVE's exploitability, gives a CVE ID to analyze, or pastes advisory/disclosure text to be broken down — including pre-CVE disclosures with no identifier assigned yet.
---

# Precondition extraction

Turn one vulnerability advisory into the structured applicability record defined by
`precondition_extraction/tests/fixtures/schema.json`: what software, what versions, and —
the heart of it — the **preconditions** that gate whether the vulnerability actually applies
to a given deployment. The standard to hold yourself to is the one the shipped fixtures were
built to; the three worked examples at the bottom of this file show it end to end.

## Getting the advisory text

**Given a CVE ID** (anything matching `CVE-YYYY-NNNN…`): fetch the official description from
the NVD API and use it verbatim:

```bash
curl -sS "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-XXXX-XXXXX"
```

The advisory text is the `descriptions` entry with `lang == "en"` inside
`vulnerabilities[0].cve`. Record `source: nvd` and
`source_url: https://nvd.nist.gov/vuln/detail/CVE-XXXX-XXXXX`. If the fetch fails or the CVE
isn't in NVD yet (common in the first days after disclosure), say so plainly and ask the user
to paste the advisory text instead — never reconstruct advisory wording from memory, because
every downstream citation depends on having the real text.

**Given pasted text** (a vendor bulletin, a mailing-list disclosure, a GHSA body): use it
exactly as pasted. Record `source_url` if the user names one. For a disclosure with no CVE
assigned yet, set `cve_id: null` and note that the record can't become a repo fixture until
an ID exists (the fixture schema requires one) — the analysis is still fully usable.

## The rules

These are what make the output trustworthy rather than plausible:

1. **Everything must be derivable from the text in front of you.** Outside knowledge —
   "everyone knows SMBv1 was on by default" — does not go into the structured record. If it's
   worth saying, say it in `notes`, clearly labeled as not from the advisory.
2. **Every precondition cites its sentence, verbatim.** Quote the exact sentence (or clause)
   from the advisory that the precondition rests on. Character-for-character — check your
   quote is a real substring of the advisory before presenting it. No citation, no
   precondition.
3. **A sentence is evidence, not a unit.** One sentence can carry several preconditions
   (Log4Shell's second sentence carries three); several sentences can carry none.
4. **Not everything flagged is a precondition.** Sentences describing the flaw or the
   attacker's mechanism go to `general_notes`; fix/workaround history goes to
   `remediation_notes` with a CSAF category (`vendor_fix`, `workaround`, `mitigation`,
   `none_available`, `no_fix_planned`). Both hold verbatim advisory sentences. Nothing is
   silently dropped.
5. **Empty is a claim, and there are two different empty claims.** `preconditions: []` means
   either "genuinely nothing gates this — running an affected version is enough" (say so,
   citing the sentence that shows it, e.g. "default or common module configurations") or
   "this text states no precondition" (say so, and if you happen to know a precondition
   exists outside the text, flag that in `notes` as exactly that: outside the text).
6. **When you can't determine something, say so plainly.** `enabled_by_default` is `null`
   unless the text states the default. Version fields are `null` when the text gives no
   range, with the messy reality ("fixes are per-branch", "no patched version exists") in
   `affected_versions.notes`. Never guess to fill a field.
7. **`required_for_exploit` follows the advisory's own hedging.** `true` when the condition
   gates the vulnerability itself; `false` when it gates only the known exploit and the
   advisory allows for other paths (Spring4Shell's Tomcat/WAR condition is the model case).

Precondition `category` is one of: `configuration` (a setting/toggle), `deployment` (how or
where it runs), `api-usage` (what the calling code invokes), `network-reachability` (what
the attacker can reach or the host can reach out to), `platform` (OS/runtime requirement).

## Output format

Present two things, in this order:

**1. The reading** — a short walkthrough: each precondition as a line with its verbatim cited
sentence quoted beneath it, then anything routed to remediation/general notes with its
sentence. This is what a colleague checks your work against.

**2. The record** — a YAML block in the fixture shape (top-level `cve_id`, `ghsa_id`,
`source`, `source_url`, `retrieved` (today's date), `advisory_text`, then `expected` with
`identity`, `affected_versions`, `preconditions`, optional `remediation_notes` /
`general_notes`, `notes`). Field-by-field reference:
`precondition_extraction/tests/fixtures/README.md`; machine-checkable definition:
`precondition_extraction/tests/fixtures/schema.json`.

When working inside this repo with a real CVE ID, validate the record before presenting it:

```bash
python3 -c "
import sys, yaml; sys.path.insert(0, '.')
from precondition_extraction.schema import validate_fixture
validate_fixture(yaml.safe_load(open('/path/to/draft.yaml')))
print('valid')"
```

Offer (don't assume) to save the result as a new fixture under
`precondition_extraction/tests/fixtures/` — that's how a one-off analysis becomes a permanent
regression test.

## Worked examples — the standard, end to end

These are the three hand-verified fixtures. Advisory text abridged here only where marked
with `[…]`; the full verified text lives in the fixture files.

### CVE-2021-44228 (Log4Shell) — one sentence, three preconditions

> "An attacker who can control log messages or log message parameters can execute arbitrary
> code loaded from LDAP servers when message lookup substitution is enabled."

That one cited sentence yields **three** preconditions:
- `message-lookup-substitution-enabled` — configuration, `enabled_by_default: true` (the
  *next* sentence, "From log4j 2.15.0, this behavior has been disabled by default.", is what
  establishes the default — and that sentence itself is fix history, so it also becomes a
  `vendor_fix` remediation note).
- `attacker-influenced-log-input` — deployment ("who can control log messages or log message
  parameters").
- `outbound-jndi-reachability` — network-reachability ("code loaded from LDAP servers").

The advisory's opening sentence ("…JNDI features used in configuration, log messages, and
parameters do not protect against attacker controlled LDAP and other JNDI related
endpoints.") describes the flaw, not a condition — it goes to `general_notes`. "From version
2.16.0 […] completely removed." is the fix boundary — `vendor_fix` remediation note, and it
feeds `affected_versions` (introduced 2.0-beta9, fixed 2.16.0, excluded_fixed 2.12.2 /
2.12.3 / 2.3.1).

### CVE-2014-6271 (Shellshock) — a precondition with no flag to point at

> "…as demonstrated by vectors involving the ForceCommand feature in OpenSSH sshd, the
> mod_cgi and mod_cgid modules in the Apache HTTP Server, scripts executed by unspecified
> DHCP clients, and other situations in which setting the environment occurs across a
> privilege boundary from Bash execution…"

Two deployment preconditions, both resting on that clause: something else must feed an
attacker-controlled environment variable across a privilege boundary
(`attacker-controlled-env-var-crosses-privilege-boundary`), and the vulnerable Bash must
actually be invoked on it (`bash-actually-invoked-on-tainted-environment`). No configuration
toggle exists — don't invent one. `affected_versions` is honest nulls: "through 4.3" has no
clean introduced/fixed pair, and the first fix was itself incomplete (CVE-2014-7169) — that
goes in `affected_versions.notes`.

### CVE-2020-14343 (PyYAML) — the precondition lives in the caller's code

> "…it is susceptible to arbitrary code execution when it processes untrusted YAML files
> through the full_load method or with the FullLoader loader."

Two preconditions from one sentence: the calling application uses `full_load`/`FullLoader`
rather than `safe_load` (`fullload-or-fullloader-used`, api-usage,
`enabled_by_default: false` — safe usage is the documented default posture), and the YAML
comes from an untrusted source (`untrusted-yaml-source`, deployment). The sentence "This
flaw allows an attacker to execute arbitrary code on the system by abusing the
python/object/new constructor." is the attacker's mechanism, not a condition the deployer
controls — `general_notes`, not a precondition. A bare version match would wrongly flag
every consumer of PyYAML < 5.4, including ones that only ever call `safe_load()` — which is
the whole reason this record type exists.
