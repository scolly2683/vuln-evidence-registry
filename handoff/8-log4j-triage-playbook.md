# Playbook: triaging a detection storm (worked on Log4Shell)

Use when one CVE produces hundreds or thousands of detections. Log4Shell
(CVE-2021-44228) is the worked example; the same five steps work for
Spring4Shell, Struts, OpenSSL and whatever lands next.

**The principle: 500 detections is not 500 questions.** It is about six
groups, and most of them can be sorted without an analyst looking at a single
host.

---

## Step 0 — Split by *how it was detected*, not by host

In Qualys one CVE can carry dozens of QIDs. They are not dozens of opinions
about the same thing — they are **different detection methods**, and the
method tells you how far to trust the result.

| Detection method | What it actually proved | Trust |
|---|---|---|
| Remote / unauthenticated check (sent a payload, got a callback) | The service responded to an exploit probe | **Near-proof** — top of the queue |
| Class-presence check (found `JndiLookup.class` inside the jar) | The vulnerable code is present | **Strong** |
| Version-string / file scan (found a filename or manifest saying 2.14.1) | A file exists on disk | **Weakest** — this is where `/var/crash`, backups and old release folders come from |
| Product-specific (vendor bundles the library) | Vendor product contains it | Real, but the fix is the **vendor patch**, not a jar swap |

Do this first. It usually collapses the pile more than any other single step.

---

## The waterfall — cheapest evidence first

Work top to bottom. Each step is mechanical until the last one.

### 1. Dead files
Jar exists on disk, no process ever loads it: crash dumps, backups, `.bak`,
old release directories, extracted tmp copies.

- **Not exploitable.**
- **Do not suppress these** — raise a **cleanup finding**: "delete stale
  vulnerable artefacts on these N hosts." Deleting kills the noise
  permanently; suppressing preserves it forever.
- One finding per host group, low priority.

### 2. Wrong artefact
- `log4j-api-*.jar` **alone is not vulnerable** — the API jar contains no
  JndiLookup. Classic scanner false positive.
- **Log4j 1.x is not vulnerable to CVE-2021-44228** at all. (Its related
  issue, CVE-2021-4104, needs a specifically configured JMSAppender.)
- → **False positive**, recorded per QID, not per host. One verified decision
  clears the whole cluster.

### 3. Already fixed, still detected
The official mitigation was **removing `JndiLookup.class` from the jar** — but
version-string QIDs cannot see inside, so a patched jar still reports
"2.14.1".

- If a class-presence check (or the SBOM data) says the class is gone →
  **close as remediated**. The detection is stale, the risk is not real.

### 4. Present but not running
Vulnerable jar on disk or in an image, but no running process loads it
(runtime "in use" flags, process maps).

- → Cleanup, or **not-applicable** with the reason recorded **and a re-check
  date** — unlike a crash dump, this one can change when the app is
  redeployed.

### 5. What's left is the real list
Running, vulnerable class present. Realistically **well under 10%** of the
original count, often a couple of dozen.

- Vendor product → vendor patch channel.
- Our own application → upgrade through the dependency channel.

---

## Two traps worth telling analysts explicitly

**"It's on old Java so it's blocked" is a myth for Log4Shell.**
The JDK `trustURLCodebase` protection is bypassable via deserialisation
gadget chains. **JDK version is not a valid reason to dismiss
CVE-2021-44228.**

Contrast with **Spring4Shell (CVE-2022-22965)**, where JDK 9+ *is* a hard
precondition — there, "we're on JDK 8" is a legitimate not-applicable
verdict. Same-shaped argument, opposite validity. This is exactly why a
recorded verdict must carry **evidence**, not just a conclusion.

**The mitigation flag has a bypass.** `formatMsgNoLookups=true` was partially
bypassed (CVE-2021-45046). Only **class removal** or **upgrade** are verdicts
that hold up in evidence.

---

## Don't try to prove unreachability

For a logging library, attacker-controlled data reaching *any* log line makes
it exploitable — that is close to impossible to rule out statically.

**Upgrading is cheaper than the proof.** Default to affected and fix it.
Reserve the effort below for the handful you genuinely cannot upgrade quickly.

---

## Testing the residual safely

For the small set that is internet-facing and cannot be patched now:

- **Passive first** — check egress/proxy/WAF logs for outbound LDAP/RMI/DNS
  from those hosts. Zero cost, no packets sent.
- **Canary token test** — inject a harmless payload carrying a unique token
  (`${jndi:ldap://<token>.<your-canary-domain>/}`) into headers/parameters,
  then watch DNS logs for that token resolving. A callback is near-proof of
  exploitability with no exploitation. Canarytokens and open-source Log4Shell
  scanners do this out of the box; CISA published one too.
- **Guardrails, non-negotiable:** written authorisation and change control
  before any active test; non-destructive payloads only; agreed test window;
  never against third-party-hosted services.

---

## Turning the work into rules

Each bucket becomes something reusable, so next quarter's storm arrives
pre-sorted:

| Bucket | What to record |
|---|---|
| Wrong artefact (log4j 1.x, api-only) | Suppression **per QID**, with the evidence line |
| Dead files | Cleanup finding + a note of the path patterns |
| Already fixed | Close; if it recurs, the scanner check is the problem — raise with the scanning team |
| Not running | Not-applicable **with a re-check date** |
| Real | Route to the fix channel via the workbench |

Record decisions where they persist — in the routing tool / rule set — **not
in the scanner console**. A console dismissal helps one scan and leaves no
reusable record of why.

---

## Reusing this for the next storm

Answer these five in order and you have the playbook for any CVE:

1. What are the **detection methods** in play, and which are weak?
2. What is the **wrong artefact** for this CVE (sibling package, old major
   version, API-only jar)?
3. What does **"fixed" look like** to a scanner — does the version string
   still change? (If not, expect stale detections.)
4. Is there a **hard precondition** (JDK version, packaging, configuration
   flag) that is genuinely checkable? Verify it is real, not folklore.
5. What is the **cheapest safe test** for the residual — passive logs first,
   canary token second?
