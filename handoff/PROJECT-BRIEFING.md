# Vulnerability routing project — briefing

*Upload this file to a Claude chat (or paste it as your first message) and then
ask your questions. It explains what the project is, the problem it solves,
how it works, and where it stands, so the assistant has full context.*

---

## What I'm trying to do

I work on the **detections side** of vulnerability management in a large org.
Scanners (Qualys on-prem, Wiz for cloud, Mend/Artifactory X-Ray for
dependencies) produce huge volumes of findings. My job is to get those
findings to the **right team to fix**, and to cut out the noise (false
positives, things that aren't actually exploitable) before they waste
anyone's time. A separate remediation team tracks closure once findings are
issued.

The core problem in one line:

> My reports today show **CVE, asset, severity, age**. They don't show the two
> things that actually drive action: **who fixes this**, and **is it even
> real**.

This project adds those two things.

## The central idea: route to a "fix channel", not a team

A **fix channel** is the *delivery mechanism* that will actually ship the fix
— not a person, not a severity. Examples: Windows Patch Tuesday, the monthly
EUC software bundle, the quarterly Oracle Critical Patch Update, a container
base-image rebuild, an app team's dependency pipeline. Each channel has an
owning team and a fix cadence/SLA.

Why channels instead of assigning owners directly: an estate has ~15 delivery
mechanisms but hundreds of thousands of findings. Deciding "which of 15
channels" is tractable; deciding an owner per finding is not. Internet-facing
(DMZ) assets get a shorter SLA than internal ones.

## How routing works (deliberately simple)

A list of **technology rules** maps text → a channel. Each rule has a
priority (lowest number wins), a match type (vendor name, product/description
keyword, or package-URL prefix), a match value, and a target channel. For each
finding, the **first matching rule by priority** decides the channel. If
nothing matches, the finding is **UNROUTED** — that's the analyst queue.

Two axes matter:
- **Identity** — *what software is this?* (per-CVE; e.g. anything from Oracle
  → the Oracle CPU channel).
- **Context** — *how is it deployed here?* (per-finding; the same Tomcat CVE
  goes to different channels if it's baked into a base image vs installed by
  an app).

The learning loop: every UNROUTED finding an analyst adjudicates becomes a new
rule. So the unrouted percentage falls month over month — that falling number
is the metric that proves the system is working.

## Dealing with false positives (this is a big part)

Scanners are noisy. Research puts version-only matching at a **~92% false
positive rate** — "component version X is present" is not "the vulnerable code
is reachable here." So the system also records **suppressions**: an analyst
proves a detection is wrong or not applicable and records a verdict, which
then applies to every matching finding.

Three verdicts, because they age differently:
- **False positive** — the detection itself is wrong (e.g. the scanner matched
  log4j 1.x, which isn't vulnerable to Log4Shell at all).
- **Not applicable** — the component is real but this configuration isn't
  vulnerable (e.g. Spring4Shell needs JDK 9+; a JDK-8 deployment is safe).
- **Risk accepted** — real, applicable, consciously accepted.

Two non-negotiable rules: every suppression must carry **evidence** and an
**expiry date**. When the expiry passes, the finding automatically comes back.
And suppressions are recorded in the system, **never in the scanner console** —
a console dismissal has no evidence, no expiry, and nobody can find it later.
The recorded suppressions can also be exported as **OpenVEX**, the industry
standard format other tools consume.

## How do we know something is genuinely vulnerable? (given I have no host access)

- **Hosts:** an *authenticated* scan reads installed versions and is ~99.9%
  accurate — trust it. Unauthenticated scans guess from banners (≤90%) and
  cause most false positives; the fix there is scan configuration, not triage.
- **Apps:** you can't tell from scan data alone. Narrow it with reachability
  (Mend), the SBOM graph (is the component in the running image, and which
  layer?), and whether the tools agree. When that doesn't settle it, route the
  owner a *specific* question ("which JDK, WAR or executable jar?") — the
  finding itself becomes the evidence-gathering mechanism.
- **The decision rule:** exposure and exploitation drive effort, not
  certainty. KEV + internet-facing → patch, don't investigate. Internal +
  version-match-only → let the patch cycle handle it. You'll get real
  confidence on ~60–70%; the rest safely defaults to "treat as vulnerable."

## The constraints I'm working within

- **Read-only** access to the Oracle database where all the scanner data
  lives. I can't create tables or views — only run SELECT queries.
- I build reports in **Power BI** off that database, and use **Copilot** to
  help write queries and DAX.
- **No access to hosts** — I can't run anything on the boxes.
- My **analysts don't code.**

Because of read-only access, the whole routing ruleset is inlined into a
single SQL query (channels and rules as CTEs), which I paste into Power BI as
the source. Adding a rule = pasting one more line into that query. Analysts
never touch it — they use a self-contained HTML tool that classifies findings
and generates the rule lines for me to paste.

## What actually exists right now

- **A routing SQL query** (Oracle, read-only) that adds who-fixes-it columns
  to my report: routing status, channel, owner, SLA, due date, overdue flag.
- **An HTML "routing calculator"** analysts open in a browser: paste findings,
  see routed (green) vs queue (amber), add a rule once per unknown technology,
  export the rule lines. Nothing installs; nothing leaves the page.
- **A second HTML tool** that bulk-classifies scanner exports against what each
  CVE actually needs to be exploitable, so thousands of rows become a handful
  of decisions, verified by sampling rather than checking every host.
- **Suppression handling** in the query and the tool, with evidence + expiry.
- **Docs**: a false-positive/evidence guide, a Log4Shell triage playbook, and
  Copilot prompts.

It's been tested against ~55 known-exploited CVEs (headless, driving the real
tool code): after fixing several bugs it routed 55/55 as expected. It has NOT
yet run against my real data, my real Oracle instance, or in a real browser —
those are the next validation steps.

## Honest status and open questions

The design matches where the industry has landed (route to owner, VEX-style
suppression, reachability over version-matching). Its known weakness is that
keyword matching is fragile and will misroute occasionally — that's what the
analyst queue and rule priorities are for. It's a **decision layer** that
would ideally sit on top of a proper VM platform, but it stands alone at my
current scale.

**Things I want to think through / ask about:**
- Is routing-to-channel the right model, or should I map to my existing report
  queues differently?
- How should I sequence this — what's the smallest first win?
- How do I handle the same CVE arriving from Qualys, Wiz and Mend as three
  separate findings (no dedup today)?
- What's the right way to bring analysts and the remediation team along?
- Is there a simpler path I'm missing given my constraints (read-only, no host
  access, non-coding analysts)?
