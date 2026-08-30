"""First-pass precondition/version extractor — regex and keyword heuristics only.

Deliberately NOT machine-learning based, and deliberately narrow in scope:

* ``extract_version_range`` pulls a version range out of advisory prose using
  a handful of regex patterns matched to how NVD/GHSA commonly phrase things
  ("X through Y", "before X", "From version X ... removed"). Verified against
  the three original fixtures (CVE-2021-44228, CVE-2014-6271, CVE-2020-14343)
  in ``tests/test_extractor.py``; the wider fixture corpus deliberately
  includes phrasings these regexes do NOT handle yet ("prior to X",
  per-branch fix lists, product enumerations) — the fixtures are the target,
  not the current score.

* ``extract_precondition_candidates`` flags CANDIDATE precondition sentences
  by keyword, tagged with a best-guess category. These are a starting point
  for a human to confirm or correct, not a final verdict: free-text
  precondition wording is open-ended, and no fixed keyword list will ever
  cover it completely. Categorization is score-based — the category with the
  most keyword hits in a sentence wins, priority order breaking ties — so a
  single incidental word can't outrank a sentence full of genuine cues for
  another category (the Shellshock "setting"-as-a-verb case pinned in
  ``tests/test_extractor.py``).

Identity (vendor/product/CPE/purl) is intentionally NOT extracted here.
Reliably turning "the PyYAML library" or "GNU Bash" into a CPE identifier
means cross-referencing an external CPE/purl dictionary — that is a lookup
problem, not a text-extraction problem, and belongs with pattern 1's
evidence-source registry rather than duplicated here.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_THROUGH_RE = re.compile(
    r"(?P<introduced>[0-9][\w.\-]*)\s+through\s+(?P<upper>[0-9][\w.\-]*)",
    re.IGNORECASE,
)
_BEFORE_RE = re.compile(r"\bbefore\s+(?P<fixed>[0-9][\w.\-]*)", re.IGNORECASE)
_REMOVED_RE = re.compile(
    r"[Ff]rom\s+(?:version\s+)?(?P<fixed>[0-9][\w.\-]*).{0,120}?(?:completely removed|removed)"
)
_EXCLUDED_RE = re.compile(
    r"excluding\s+(?:security\s+)?releases?\s+(?P<list>[0-9][\w.\-,\sand]*)",
    re.IGNORECASE,
)


@dataclass
class VersionRange:
    introduced: str | None = None
    fixed: str | None = None
    excluded_fixed: list[str] = field(default_factory=list)


def _clean_version(raw: str) -> str:
    # The version regexes allow "." and "-" inside a version, so a capture at
    # the end of a sentence would otherwise keep the sentence's final period
    # ("before 5.4." -> "5.4.").
    return raw.rstrip(".-")


def extract_version_range(text: str) -> VersionRange:
    vr = VersionRange()

    through = _THROUGH_RE.search(text)
    if through:
        vr.introduced = _clean_version(through.group("introduced"))

    removed = _REMOVED_RE.search(text)
    if removed:
        vr.fixed = _clean_version(removed.group("fixed"))
    else:
        before = _BEFORE_RE.search(text)
        if before:
            vr.fixed = _clean_version(before.group("fixed"))

    excluded = _EXCLUDED_RE.search(text)
    if excluded:
        parts = re.split(r",|\band\b", excluded.group("list"))
        vr.excluded_fixed = [_clean_version(p.strip()) for p in parts if p.strip()]

    return vr


_CATEGORY_KEYWORDS: dict[str, tuple[str, ...]] = {
    "configuration": (
        "enabled by default",
        "disabled by default",
        "is enabled",
        "configuration",
        "setting",
        "option",
        "flag",
        "toggle",
    ),
    "api-usage": (
        "method",
        "function",
        "calling",
        "loader",
        "constructor",
        "load(",
    ),
    "network-reachability": (
        "reachable",
        "network",
        "outbound",
        "endpoint",
        "ldap",
    ),
    "deployment": (
        " via ",
        "vector",
        "privilege boundary",
        "cgi",
        "ssh",
        "environment variable",
        "script",
    ),
    "platform": (
        "operating system",
        "platform",
        "windows",
        "linux",
        "macos",
    ),
}

_CATEGORY_PRIORITY = (
    "configuration",
    "api-usage",
    "network-reachability",
    "deployment",
    "platform",
)

_SENTENCE_SPLIT_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z(])")


def _split_sentences(text: str) -> list[str]:
    return [s.strip() for s in _SENTENCE_SPLIT_RE.split(text.strip()) if s.strip()]


@dataclass
class PreconditionCandidate:
    statement: str
    category: str
    enabled_by_default: bool | None


def extract_precondition_candidates(text: str) -> list[PreconditionCandidate]:
    candidates: list[PreconditionCandidate] = []
    for sentence in _split_sentences(text):
        lowered = f" {sentence.lower()} "
        # Strongest signal wins: count keyword hits per category rather than
        # taking the first category with any hit. A single incidental word
        # ("...in which setting the environment occurs..." — "setting" as a
        # verb) must not outrank a sentence full of genuine cues for another
        # category. Priority order only breaks ties.
        scores = {
            c: sum(1 for kw in _CATEGORY_KEYWORDS[c] if kw in lowered)
            for c in _CATEGORY_PRIORITY
        }
        best = max(scores.values())
        if best == 0:
            continue
        category = next(c for c in _CATEGORY_PRIORITY if scores[c] == best)
        enabled_by_default: bool | None = None
        if "disabled by default" in lowered or "not enabled by default" in lowered:
            enabled_by_default = False
        elif "enabled by default" in lowered:
            enabled_by_default = True
        candidates.append(
            PreconditionCandidate(
                statement=sentence,
                category=category,
                enabled_by_default=enabled_by_default,
            )
        )
    return candidates


@dataclass
class ExtractionResult:
    cve_id: str
    version_range: VersionRange
    precondition_candidates: list[PreconditionCandidate]


def extract(cve_id: str, advisory_text: str) -> ExtractionResult:
    return ExtractionResult(
        cve_id=cve_id,
        version_range=extract_version_range(advisory_text),
        precondition_candidates=extract_precondition_candidates(advisory_text),
    )
