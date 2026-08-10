# How do we know if a host or app is genuinely vulnerable?

The honest answer, and the one the industry has converged on: **for most
findings you will not prove it, and you should not try.** You be right about
the big groups, and you make the residual small enough that patching is
cheaper than proving. Hosts and apps are answered differently.

This page is grounded in current research, cited at the end.

---

## First, the settled facts (so we stop re-deciding)

1. **Remote PowerShell is not a path for an analyst without host access.**
   PowerShell Remoting (WinRM) requires administrative rights on the target
   by default; non-admin remote querying needs specially configured
   constrained endpoints that your platform team would have to build. So
   "query the host remotely" is not something a read-only analyst can do.
   Do not design around it. (Sources 4, 5.)

2. **Authenticated scanning is the single biggest accuracy lever, and it is
   not ours to build — it is a scanner setting.** Authenticated/agent Qualys
   findings are ~99.9% accurate; unauthenticated scans are "no better than
   90%" and are the source of most host-level false positives. (Sources 1, 2.)

3. **Version-match findings are wrong ~9 times in 10 at the library level.**
   A recent empirical study measured a **92% false-positive rate** in
   SBOM/version-based vulnerability matching, because "component version Y is
   present" is not "the vulnerable code is reached." This is why app findings
   feel so noisy — the noise is real and measured. (Sources 3, 6.)

4. **VEX + reachability is the industry answer to that noise** — exactly the
   suppression-with-evidence and SBOM-graph approach in this bundle. We are
   not inventing; we are applying the current consensus. (Sources 3, 6.)

---

## Hosts — largely solvable, and mostly not by you

A host finding asks: *is this OS package or service at a fixed level?* That is
answerable with near-certainty by an **authenticated scan**, which reads
installed versions rather than guessing from a banner.

So the real question is not "is it vulnerable" but **"was this an
authenticated scan?"**

- **Authenticated / agent finding** → trust it. ~99.9% accurate. If it says
  the patch is missing, it is.
- **Unauthenticated finding** → treat as a lead, not a fact. If a meaningful
  slice of the estate scans unauthenticated, **getting those hosts
  credentialed does more for accuracy than any triage tool**, this one
  included. That is the highest-value fix available and it is a scanner
  configuration, owned by whoever runs Qualys.
- **Config-dependent host CVEs** (PrintNightmare needs the Spooler running;
  a service may be disabled) → version alone is insufficient; the service
  state is the answer, and that is a question for the system owner.

You can tell authenticated from unauthenticated in the scan data itself
(Qualys records the authentication result per host). Surface that column —
it tells you which findings you can trust outright.

## Apps — you cannot know from scan data alone, and that is expected

For a library/app CVE, the scanner sees "package present at version X." The
92% false-positive figure is precisely the gap between that and "exploitable
here." Three things narrow it **without host access**, in order of strength:

1. **Reachability (Mend)** — is the vulnerable function actually called by
   your code? This is the strongest signal available to you and the one the
   research points to as the real fix for version-match noise.
2. **The SBOM graph (Mend + X-Ray + Wiz)** — is the component in the app
   layer or the base image, and is the image actually running? Kills a large
   share with data you already query.
3. **Tool disagreement** — Mend, X-Ray and Wiz on the same component; the
   outlier is usually the false positive.

When those do not settle it, the resolving move is **not** to gain access —
it is to route the owner a *precise* question. The finding is the
evidence-gathering mechanism:

> "Spring4Shell affects apps on JDK 9+ deployed as a WAR on Tomcat. You are
> recorded as spring-beans 5.3.17. Which JDK, and WAR or executable jar? If
> JDK 8 or a Spring Boot jar, we will close it with your answer as evidence."

A specific question gets a next-day answer and a defensible verdict. A
generic "please assess" does not. This is why routing to the correct owner
is the load-bearing part of the whole system.

## The decision rule that saves the most time

Confidence is not the driver. **Exposure and exploitation are.**

| Situation | Action |
|---|---|
| In CISA KEV / actively exploited **and** internet-facing | **Patch. Do not investigate.** Proving non-exploitability costs more than the fix. |
| Internal, not exploited, version-match only | Ride the patch cycle — record, do not raise a finding. |
| Precondition contradicted (wrong artefact, JDK 8, dead path, service disabled) | Suppress **with evidence and an expiry date**. |
| Large, genuinely ambiguous group | One targeted question to the owner — the cheapest evidence you have. |
| Host, unauthenticated scan only | Fix the scan coverage; do not triage guesses. |

A KEV CVE on a DMZ box gets patched whether or not you proved reachability.
An internal library CVE with no known exploit does not deserve a week of
investigation.

## What "good" looks like

You will reach real confidence on perhaps **60–70%** of findings — hosts via
authenticated scans, apps via reachability plus targeted owner questions. The
rest defaults to *treat as vulnerable and let the cycle fix it*, which is the
correct default because it is cheap and safe.

The failure mode is not uncertainty. It is **spending analyst time proving
things about findings nobody was ever going to exploit.** Everything in this
bundle exists to stop that: route to an owner, suppress the provable false
positives with evidence, and let exposure-and-exploitation decide where the
human effort goes.

---

## Sources

1. [Authenticated vs unauthenticated scan accuracy](https://dfarq.homeip.net/authenticated-scan-vs-unauthenticated/) — authenticated ~99.9%, unauthenticated ≤90%.
2. [Qualys: unified view of unauthenticated and agent scans](https://blog.qualys.com/product-tech/2021/01/21/unified-vulnerability-view-of-unauthenticated-and-agent-scans) — agent scans remove the authentication gap; unauth lacks the attacker perspective.
3. [A Reality Check on SBOM-based Vulnerability Management (arXiv 2511.20313)](https://arxiv.org/html/2511.20313v2) — measured 92% false-positive rate from version-only matching; reachability as the path forward.
4. [PowerShell Remoting without administrator rights (4sysops)](https://4sysops.com/archives/powershell-remoting-without-administrator-rights/) — WinRM needs admin or specially configured constrained endpoints.
5. [WinRM PowerShell Remoting security hardening](https://www.decryptiondigest.com/blog/winrm-powershell-remoting-security-hardening-guide) — remote local-admin access is restricted by default.
6. [OpenSSF / VEX + scanners](https://openssf.org/blog/2023/12/20/openvex-and-open-source-vulnerability-scanners-how-the-dynamic-duo-improves-vulnerability-management/) — VEX contextualises SBOM findings to cut false positives.
