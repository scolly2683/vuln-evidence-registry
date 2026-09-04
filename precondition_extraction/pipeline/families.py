"""Bucket a precondition into a family — the ONE implementation.

`analyse.py` and `bundle.py` both import this, and downstream consumers (VulnBrief's
ingest) take the family from the bundle rather than re-deriving it, so a change here is a
change everywhere at once and the numbers in FINDINGS.md stay reproducible.

Bucketing is keyword-based over the precondition's id + statement, gated by its category
first. The category gate matters: rule 8 files "the attacker must already hold X" under
`deployment` and "the attacker must be able to reach X" under `network-reachability`, so a
`network-reachability` gate can never be attacker-already-holds however its statement is
worded ("reach the admin portal" mentions admin; it is still a reach gate). The first
version of this bucketing had no category gate and misfiled exactly that case.

This is a reading aid, not a measurement. The categories on the records are exact; the
families are a triage grouping, and the `other` pile is printed in full by `analyse.py`
because that is where the next family comes from.
"""
from __future__ import annotations

import re

FAMILIES = (
    "attacker-already-holds",
    "victim-must-act",
    "management-surface-exposed",
    "network-reachable",
    "optional-component-present",
    "platform-specific",
    "other",
)

_HOLD = re.compile(
    r"\b(authenticat|credential|password|account|logged[- ]in|privileg|administrat|"
    r"admin\b|root\b|local access|locally|physical|prior(ly)? compromis|"
    r"already compromis|foothold|valid (user|login)|api[- ]?(key|token)|"
    r"session|community string|shell access|integrity level|low.privileg|"
    r"attacker (must|already|holds|possess|has|needs|requires))",
    re.I,
)
_VICTIM = re.compile(
    r"\b(victim|convince|entice|lure|trick|persuade|user must|user would|"
    r"user (opens?|clicks?|visits?|executes?|runs?)|opens? (a|an|the) |"
    r"executes? (a|an|the) |clicks? (a|an|the) |visits? (a|an|the) )",
    re.I,
)
_ARTEFACT = re.compile(
    r"\b(file|document|link|url|web ?site|web ?page|attachment|e-?mail|message|"
    r"image|archive|workbook|spreadsheet|\.lnk|html|pdf|application|package|"
    r"template|shortcut|payload)\b",
    re.I,
)
_SURFACE = re.compile(
    r"\b(portal|gateway|management (interface|plane|port|access)|"
    r"admin(istrative|istration)? (interface|console|panel|ui|web)|"
    r"web (interface|console|ui|management|admin)|ssl.?vpn|vpn|captive portal|"
    r"remote access|webui|control panel|dashboard|"
    r"user[- ]interface|web-based management|https? (interface|service|server))\b",
    re.I,
)
_COMPONENT = re.compile(
    r"\b(installed|present|enabled|configured|in use|deployed|running|loaded|"
    r"provisioned|activated|module|plug-?in|add-?on|extension|feature|package|"
    r"service|subsystem|component|protocol)\b",
    re.I,
)
_PLATFORM = re.compile(
    r"\b(windows|linux|macos|series|appliance|hardware|model|architecture|"
    r"x86|arm|firmware|form factor)\b",
    re.I,
)


def family(pc: dict) -> str:
    blob = f"{pc.get('id', '')} {pc.get('statement', '')}"
    cat = pc.get("category")
    if cat == "network-reachability":
        return "management-surface-exposed" if _SURFACE.search(blob) else "network-reachable"
    if cat == "platform":
        return "platform-specific"
    if _VICTIM.search(blob) and _ARTEFACT.search(blob):
        return "victim-must-act"
    # Rule 8 files "the attacker must already hold X" under `deployment`. A
    # `configuration` gate is a deployer's setting, never something the attacker
    # holds — without this gate "Security Fabric enabled" was bucketed here on the
    # word "authentication" in "authentication-bypass path".
    if cat == "deployment" and _HOLD.search(blob):
        return "attacker-already-holds"
    if _SURFACE.search(blob):
        return "management-surface-exposed"
    if _COMPONENT.search(blob):
        return "optional-component-present"
    if _PLATFORM.search(blob):
        return "platform-specific"
    return "other"
