# False positives, suppression, and proving it

The playbook (file 8) says how to *judge* a detection. This file is where the
judgement gets *recorded* so it applies to every future scan — and what
evidence to gather before recording it.

---

## 1. Three verdicts, and why they're different

| Verdict | Means | Typical evidence | Re-check |
|---|---|---|---|
| **False positive** | The detection itself is wrong | "log4j 1.x has no JndiLookup class; the QID matches on version string only" | 12 months |
| **Not applicable** | Component is real, this configuration isn't vulnerable | "JDK 8 and fat-jar packaging — Spring4Shell needs JDK 9+ and WAR on Tomcat" | 6 months |
| **Risk accepted** | Real, applicable, consciously accepted | Owner, business reason, compensating control | 3 months |

They're separated because they **age differently**. A false positive stays
true until the scanner changes its check. A not-applicable verdict dies the
moment someone redeploys on a different JDK. Risk acceptance should be the
most uncomfortable and shortest-lived of the three.

## 2. Two non-negotiable rules

**Evidence is mandatory.** A suppression without a checkable reason is an
unaudited risk acceptance wearing a false-positive costume. "Not exploitable"
is not evidence; "class absent, verified with `Test-VulnerableJar` on 12 of 12
sampled hosts" is.

**Every suppression has an expiry.** A suppression is a *lease*, not a
tombstone. When the re-check date passes, the finding automatically comes back
into the queue. This is enforced in the query (`sup.review_by >= TRUNC(SYSDATE)`)
and in the tool — expired entries stop suppressing and show as `EXPIRED`.

Corollary: **never suppress in the scanner console.** A console dismissal
helps one scan, has no expiry, no evidence field, and nobody can find it in
six months. That's the behaviour this whole design exists to replace.

## 3. How it works end to end (read-only, no DB privileges)

1. Analyst proves a detection is wrong — evidence from the PowerShell script
   (file 9), the SBOM graph, or a documented product fact.
2. In the **triage tool**, they switch the decision selector to **Suppress**,
   pick a verdict, paste the evidence and set a re-check date. Both fields are
   required — the tool refuses without them.
3. They click **Copy suppression rows** and send the lines.
4. You paste them into the routing query above:
   `-- >>> ADD ANALYST SUPPRESSIONS BELOW THIS LINE <<<`
5. Refresh. Those findings now show `ROUTING_STATUS = 'SUPPRESSED'` with the
   verdict in `SUPPRESSION_VERDICT`.

**Keep suppressed rows in the dataset** and filter them out on the report
pages instead of deleting them — that's what makes the suppression ledger
page (what did we silence, why, and when does it expire) possible.

## 4. Where VEX fits

**OpenVEX** is the industry-standard machine-readable form of exactly these
statements: *this CVE does not affect this product, and here is the reason
code*. Scanners like Grype and Trivy consume it natively to suppress findings,
and it's the format to hand another team or an auditor.

The tool's **Download VEX** button emits your CVE-level suppressions as an
OpenVEX file. Mapping:

| Your verdict | OpenVEX status | Justification |
|---|---|---|
| False positive | `not_affected` | `component_not_present` |
| Not applicable | `not_affected` | `vulnerable_code_not_in_execute_path` |
| Risk accepted | `affected` | action statement instead |

**When to bother:** if you're sharing verdicts with another team or tool, or
being asked to evidence your suppressions. **When not to:** QID-level
suppressions have no VEX equivalent — a QID is a statement about a *scanner's
detection logic*, not about a product — so those stay in the query only. Don't
force them into VEX; it would be a false statement about the software.

## 4a. Scaling to thousands of rows: decide by group, verify by sample

PowerShell answers one host well. It does not answer three thousand rows —
and it doesn't need to. The workflow that scales:

1. **Classify in bulk, touching nothing.** Open `11-evidence-triage-tool.html`
   and paste the scanner export. Each row is tested against what the CVE
   actually *requires* to be exploitable, using only the text already in the
   export. Thousands of rows collapse into a handful of groups.
2. **Verify a sample per group** — 3 to 10 hosts, not all of them. The tool
   generates the scoped PowerShell command for exactly those hosts.
3. **Record the group verdict once**, citing the sample as evidence:
   *"log4j-api artefact has no JndiLookup class; verified on 10 of 412
   sampled hosts."*

The four classifications and what to do with each:

| Class | Meaning | Action |
|---|---|---|
| **Not applicable** | A precondition is contradicted by the scan data — Spring4Shell on JDK 8, or a Spring Boot executable jar rather than a WAR on Tomcat | Verify sample → record `NOT_APPLICABLE` |
| **Dead copy** | Artefact sits in a backup, crash, temp or archive path | **Cleanup finding, not a suppression** — deleting removes it permanently |
| **Needs check** | Scan data doesn't settle it — the Java-8-on-disk-but-never-loaded case lives here | This is what the sample is for |
| **Likely real** | Preconditions satisfied | Route to a fix channel |

**The coverage rule.** A group that covers only *some* rows for a CVE cannot
be turned into a CVE-level suppression — that would silence the exploitable
rows for the same CVE too. The tool marks each group **full** or **partial**
and only emits suppression rows for full-coverage groups. Partial groups get
handled as an exception list or fixed at source. This is the same lesson as
never letting a config-conditional verdict become a blanket mute.

**The honest caveat, worth repeating to analysts:** classification reads text
from your export, so it can be wrong about any individual row. It proposes;
the sample proves. Never blanket-suppress off pattern matching alone.

## 5. Evidence sources, cheapest first

**a. The PowerShell script (file 9)** — every analyst has PowerShell, nothing
to install, entirely read-only. It answers the question version-string
detections can't:

```powershell
. .\9-Get-CveEvidence.ps1
Get-CveEvidenceReport -Path 'D:\apps' | Export-EvidenceCsv -Out .\evidence.csv
```

Per artefact it returns `VULNERABLE` (class present), `PATCHED` (class removed
— stale detection, close it), `NOT_AFFECTED_ARTIFACT` (log4j-api or 1.x — the
suppression evidence writes itself), plus whether the path is a `DEAD_COPY`
(backup/crash/temp → cleanup finding, *not* a suppression). Paste the CSV
straight into the triage tool.

**b. The Neo4j SBOM graph** — you already have an HTML query builder over
Mend, Artifactory X-Ray and Wiz container-image data. **That is the strongest
evidence source in the set**, and it answers things PowerShell cannot:

- Is the component genuinely present in *this* image or repo — or is the
  scanner matching a filename?
- Which **layer**: base image (→ `k8s-image`, platform team rebuilds) or
  application layer (→ `build-dependency`, app team bumps)? Same CVE, different
  owner — this is the single most common misroute.
- **Who owns it** — image → build info → repo → team, which is exactly the
  ownership lookup the routing model otherwise leaves to guesswork.
- Do Mend, X-Ray and Wiz *agree*? Disagreement is itself a finding: usually a
  false positive in whichever tool is the outlier.

Use it in this order: graph first for container and dependency findings
(it's authoritative on presence and layer), PowerShell for host and file-share
findings (it's authoritative on what's actually inside the jar on that box).

The two tools compose: the **graph** answers *is it really there, and whose is
it*; the **triage tool** answers *which channel, or suppress with this
evidence*. Paste the graph result into the evidence field — a suppression
citing a graph query is one nobody has to re-litigate.

**c. Active testing** — last resort, for internet-facing findings you cannot
patch quickly. Passive first (egress/WAF logs for outbound LDAP/RMI/DNS), then
a canary-token callback test. Written authorisation and change control before
any packet is sent. See file 8.

## 6. What to check monthly

- Suppressions within 30 days of expiry — re-verify or let them lapse.
- Anything suppressed in Qualys or Wiz that has **no matching record here** —
  that's an unmanaged risk acceptance and the reason it exists is nowhere.
- Findings that came back after a suppression expired — did the world change,
  or was the verdict wrong?
