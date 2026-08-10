"""Data model for the learning routing registry.

Two-axis routing: identity rules answer "what software is this?" (per-CVE),
context rules answer "how is this instance deployed here?" (per-finding).
Corrections are context rules accreted from observed misroutes.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Subject fields a rule may match on. Anything else in a `match:` block is a
# validation error, so typos fail loudly instead of silently never matching.
SUBJECT_FIELDS = (
    "cna",
    "vendor",
    "product",
    "package",
    "source",
    "nvd_status",
    "cve_id",
    "qid",
)
# Identifier fields matched by EXACT equality only. The default
# equality-or-contained semantics would make "CVE-2021-4428" match
# "CVE-2021-44228" — catastrophic for suppressions.
EXACT_SUBJECT_FIELDS = ("cve_id", "qid")
# Virtual matchers with their own semantics (see router._match_subject).
VIRTUAL_MATCHERS = ("purl_prefix", "keywords")

RULE_KINDS = ("suppression", "screen", "identity", "correction")
SCREEN_ACTIONS = ("drop", "park")
CADENCE_TYPES = ("scheduled", "continuous", "ad_hoc")
# Suppression verdicts age differently: false_positive (the detection is
# wrong), not_applicable_config (real component, config not vulnerable),
# risk_accepted (real, accepted — shortest review_by).
SUPPRESSION_VERDICTS = ("false_positive", "not_applicable_config", "risk_accepted")


@dataclass
class Channel:
    """A fix channel: a delivery mechanism that ships fixes on some rhythm.

    A channel is NOT an owner — it still needs one (`owner` stays a
    placeholder until the org's D8 enumeration fills it in).
    """

    id: str
    name: str
    description: str = ""
    cadence: str = ""
    cadence_type: str = "ad_hoc"
    owner: str = "UNASSIGNED"
    parent: str | None = None


@dataclass
class Rule:
    id: str
    kind: str  # suppression | screen | identity | correction
    match: dict = field(default_factory=dict)
    context: dict = field(default_factory=dict)
    route: str | None = None  # channel id (identity / correction)
    action: str | None = None  # drop | park (screen only)
    queue: str | None = None  # park queue name (screen only)
    priority: int = 100  # lower fires first within a kind
    provenance: dict = field(default_factory=dict)
    review_by: str | None = None  # ISO date; stale rules are flagged, not disabled
    note: str = ""
    verdict: str | None = None  # suppression only: see SUPPRESSION_VERDICTS


@dataclass
class RouteResult:
    finding_id: str
    cve_id: str
    disposition: str  # suppressed | screened | routed | unroutable
    channel: str | None = None
    rule_id: str | None = None
    stage: str | None = None  # suppression | screen | correction | identity
    queue: str | None = None
    verdict: str | None = None  # suppressed only

    def to_dict(self) -> dict:
        return {
            "finding_id": self.finding_id,
            "cve_id": self.cve_id,
            "disposition": self.disposition,
            "channel": self.channel,
            "rule_id": self.rule_id,
            "stage": self.stage,
            "queue": self.queue,
            "verdict": self.verdict,
        }


@dataclass
class Registry:
    channels: dict[str, Channel]
    rules: list[Rule]
    warnings: list[str] = field(default_factory=list)

    def rules_of_kind(self, kind: str) -> list[Rule]:
        return sorted(
            (r for r in self.rules if r.kind == kind),
            key=lambda r: (r.priority, r.id),
        )
