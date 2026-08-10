# OpenVEX export — the suppression registry speaks the standard

The suppression registry (`registry/rules/suppressions.yaml`) is the audited
source of truth for "this detection is wrong / not applicable" verdicts.
[OpenVEX](https://github.com/openvex/spec) is the industry interchange format
for exactly those statements, consumed natively by scanners (Grype, Trivy,
and increasingly commercial tools). `tools/export_vex.py` makes the registry
the **author** of that format:

```bash
python tools/export_vex.py --registry registry \
    --author "vuln-mgmt@your-org" --out export/openvex.json
```

## Verdict mapping

| Registry verdict | OpenVEX status | Default justification |
|---|---|---|
| `false_positive` | `not_affected` | `component_not_present` |
| `not_applicable_config` | `not_affected` | `vulnerable_code_not_in_execute_path` |
| `risk_accepted` | `affected` + `action_statement` | — |

A suppression opts in with a `vex:` block (products are mandatory — VEX
speaks CVE × product):

```yaml
vex:
  cve: CVE-2021-44228            # optional if match.cve_id is set
  products: ["pkg:maven/log4j/log4j"]
  justification: vulnerable_code_not_present   # overrides the default
```

`provenance.evidence` becomes the `impact_statement` — the human-readable
why. The exporter validates justification labels against the spec's fixed
list and fails loudly on anything it can't translate.

## What is deliberately NOT exported

- **QID-only rules** (no CVE): those are statements about *scanner
  detection logic*, not about a product — they sync to Qualys's own
  exclusion mechanism (search lists), and the exporter says so in a
  warning rather than forcing them into the wrong format.
- **Expired suppressions**: anything past `review_by` is excluded from the
  export with an `EXCLUDED` warning — an expired suppression must not keep
  silencing scanners. (The routing engine itself keeps flagged-but-active
  semantics, same as corrections, so runs stay reproducible; expiry is
  enforced at every sync boundary.)

## Where this fits the operating model

The org runs a **detections side** (us) sending findings into an **internal
findings tool**, with a remediation team tracking closure. The registry sits
on the detections side as the decision layer:

```
scanners (Qualys / Wiz / GitHub) ──▶ registry decides ──▶ internal findings tool
                                       │                    (remediation team
                                       │                     tracks closure)
                                       ├─ suppressed  → never becomes a finding;
                                       │                verdict exported as OpenVEX
                                       │                + scanner exclusions
                                       ├─ in certified cycle → record only
                                       └─ exception / currency / act-now
                                                      → finding issued
```

One OpenVEX document, regenerated on every registry merge, is the single
statement of "what we don't act on and why" — shareable with the
remediation team, auditors, and any VEX-aware tool, with git history as
the change log.
