You are extracting structured applicability data from a vulnerability advisory, following
the precondition-extraction standard from my vuln-evidence-registry project. I will give you
either a CVE ID or pasted advisory text (possibly a disclosure with no CVE assigned yet).
If I give only a CVE ID and you can fetch the web, get the official description from
https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=<ID> and use it verbatim; if you
cannot fetch, ask me to paste the text — never reconstruct advisory wording from memory.

Rules:
1. Everything in the record must be derivable from the advisory text in front of you.
   Outside knowledge goes only in notes, labeled as outside the text.
2. Every precondition cites the exact sentence it rests on, quoted character-for-character.
   No citation, no precondition.
3. One sentence can carry several preconditions; several sentences can carry none.
4. Sentences that are NOT preconditions are kept, not dropped: fix/workaround history goes
   to remediation_notes with a CSAF category (vendor_fix, workaround, mitigation,
   none_available, no_fix_planned); flaw/attacker-mechanism description goes to
   general_notes. Both hold verbatim sentences.
5. An empty preconditions list is a claim with two distinct readings — say which applies:
   "genuinely nothing gates this; an affected version is enough" or "this text states no
   precondition" (and flag it if you know a real gate exists outside the text).
6. Say plainly when something can't be determined: enabled_by_default is null unless the
   text states the default; version fields are null when the text gives no range, with the
   messy reality explained in notes. Never guess to fill a field.
7. required_for_exploit is false when a condition gates only the known exploit and the
   advisory hedges that other paths may exist; true when it gates the vulnerability itself.
8. A sentence that names what the attacker must already hold (an account, a privilege level,
   local access, a prior compromise, a specific artefact) or must be able to reach (a named
   service, interface, port or component) IS a precondition, even when it restates a CVSS
   metric in prose, provided it names the specific thing. File "must hold" gates under
   deployment and "must reach" gates under network-reachability. A bare metric restatement
   that names nothing ("an unauthorized attacker over a network") remains a general note.
9. A sentence naming a specific artefact the victim must open, execute, load or process (a
   file type, a link, a document, a web site) IS a precondition — file it under deployment
   until the standard gains a user-interaction category. "User interaction is required"
   naming nothing remains a general note.
10. A sentence that locates the flaw in a named optional component, service, feature, module
   or protocol IS a precondition that the component is present or enabled — deployment for
   presence ("the Remote Access SSL VPN service is running"), configuration for an
   enable/disable state ("mod_rewrite is loaded", "the remoting CLI protocol is enabled").

Precondition categories: configuration (a setting/toggle), deployment (how/where it runs),
api-usage (what the calling code invokes), network-reachability (what the attacker can
reach or the host reaches out to), platform (OS/runtime requirement).

Output two parts, in order:
1. THE READING — each precondition on one line (short-slug-id, category, required?,
   default?) with its verbatim cited sentence quoted beneath, then each remediation/general
   note with its sentence.
2. THE RECORD — one YAML block: cve_id (null if unassigned), ghsa_id, source, source_url,
   retrieved (today), advisory_text (verbatim), then expected: identity {vendor, product,
   cpe, purl}, affected_versions {introduced, fixed, excluded_fixed, notes},
   preconditions [{id, statement, category, enabled_by_default, required_for_exploit}],
   remediation_notes, general_notes, notes.

Calibration example (Log4Shell, CVE-2021-44228): the sentence "An attacker who can control
log messages or log message parameters can execute arbitrary code loaded from LDAP servers
when message lookup substitution is enabled." yields THREE preconditions — the config
toggle, attacker-influenced log input, and outbound JNDI/LDAP reachability — while "From
log4j 2.15.0, this behavior has been disabled by default." is fix history (vendor_fix
remediation note) that also establishes the toggle's earlier default, and the advisory's
opening flaw-description sentence is a general_note, not a precondition.

Here is the advisory (or CVE ID):
