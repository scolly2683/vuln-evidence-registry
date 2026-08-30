"""Second-pass candidate review: ask Claude which candidates are genuine preconditions.

The keyword extractor (``extractor.py``) deliberately over-flags — it hands every
suggestive sentence to a human. This module is the step between the two: one
Claude API call that reads the advisory text and the candidate list and returns,
per candidate, a verdict (genuine precondition vs. false match), a verbatim
cited sentence from the advisory, and a one-line reason.

Scope and safety properties, by construction:

* **Read-only, no tools.** The request passes no ``tools`` at all — Claude can
  only reason over the text it is given; it cannot browse, run code, or touch
  files.
* **Verdicts are advisory, citations are checked.** Claude's cited sentence is
  verified locally against the advisory text (whitespace-normalized substring
  check); a citation that is not actually in the advisory is flagged on the
  verdict rather than trusted.
* **Optional dependency.** The ``anthropic`` SDK is imported only inside
  ``verify_candidates`` — the rest of this package works without it. Install
  with ``pip install -e ".[verify]"`` and set ``ANTHROPIC_API_KEY``.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

from .extractor import PreconditionCandidate

DEFAULT_MODEL = "claude-opus-5"

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdicts": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "candidate_index": {"type": "integer"},
                    "is_genuine_precondition": {"type": "boolean"},
                    "cited_sentence": {"type": "string"},
                    "reasoning": {"type": "string"},
                },
                "required": [
                    "candidate_index",
                    "is_genuine_precondition",
                    "cited_sentence",
                    "reasoning",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["verdicts"],
    "additionalProperties": False,
}

_SYSTEM_PROMPT = """\
You are reviewing output from a keyword-based extractor that flags candidate
"precondition" sentences in vulnerability advisory text. A genuine precondition
is a condition that gates whether the vulnerability actually applies or is
exploitable in a given deployment — e.g. a configuration setting that must be
enabled, a specific API/function the calling code must use, a deployment path
that must exist (CGI, SSH, an attacker-reachable input), a required platform.

A false match is a sentence the keywords flagged that does NOT state such a
condition — e.g. a sentence merely describing the flaw, the fix, affected
versions, or history.

For each numbered candidate, decide is_genuine_precondition, quote the exact
sentence from the advisory text (verbatim, character-for-character) that your
verdict rests on as cited_sentence, and give a one-sentence reasoning. Return
one verdict per candidate, using each candidate's given index."""


class VerificationError(Exception):
    """Raised when the review call fails or returns an unusable response."""


@dataclass
class CandidateVerdict:
    candidate_index: int
    statement: str
    is_genuine_precondition: bool
    cited_sentence: str
    citation_found_in_advisory: bool
    reasoning: str


def _normalize_ws(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def _build_user_prompt(advisory_text: str, candidates: list[PreconditionCandidate]) -> str:
    lines = ["Advisory text:", "", advisory_text.strip(), "", "Candidates:"]
    for i, cand in enumerate(candidates):
        lines.append(f"{i}. [{cand.category}] {cand.statement}")
    return "\n".join(lines)


def verify_candidates(
    advisory_text: str,
    candidates: list[PreconditionCandidate],
    *,
    client=None,
    model: str = DEFAULT_MODEL,
) -> list[CandidateVerdict]:
    """Ask Claude to separate genuine preconditions from false matches.

    ``client`` is injectable for tests; when None, an ``anthropic.Anthropic()``
    client is constructed (requires the ``verify`` extra and an API key).
    """
    if not candidates:
        return []

    if client is None:
        try:
            import anthropic
        except ImportError as exc:
            raise VerificationError(
                'the "anthropic" package is not installed — '
                'install it with: pip install -e ".[verify]"'
            ) from exc
        client = anthropic.Anthropic()

    response = client.beta.messages.create(
        model=model,
        max_tokens=16000,
        # Server-side fallback: if the primary model declines the request
        # (advisory text can trip safety classifiers), the API retries it on a
        # fallback model in the same call instead of returning nothing.
        betas=["server-side-fallback-2026-07-01"],
        fallbacks="default",
        system=_SYSTEM_PROMPT,
        messages=[{"role": "user", "content": _build_user_prompt(advisory_text, candidates)}],
        output_config={"format": {"type": "json_schema", "schema": _RESPONSE_SCHEMA}},
        # Deliberately no `tools=` — see module docstring: read-only review.
    )

    if response.stop_reason == "refusal":
        detail = getattr(response, "stop_details", None)
        raise VerificationError(
            "Claude declined to process this advisory text"
            + (f" (category: {detail.category})" if detail and detail.category else "")
        )

    text = next((b.text for b in response.content if b.type == "text"), None)
    if text is None:
        raise VerificationError(f"no text content in response (stop_reason={response.stop_reason})")
    try:
        raw_verdicts = json.loads(text)["verdicts"]
    except (json.JSONDecodeError, KeyError) as exc:
        raise VerificationError(f"response was not the expected JSON shape: {exc}") from exc

    by_index = {v["candidate_index"]: v for v in raw_verdicts}
    missing = [i for i in range(len(candidates)) if i not in by_index]
    if missing:
        raise VerificationError(f"response is missing verdicts for candidates {missing}")

    normalized_advisory = _normalize_ws(advisory_text)
    verdicts: list[CandidateVerdict] = []
    for i, cand in enumerate(candidates):
        raw = by_index[i]
        cited = raw["cited_sentence"]
        verdicts.append(
            CandidateVerdict(
                candidate_index=i,
                statement=cand.statement,
                is_genuine_precondition=bool(raw["is_genuine_precondition"]),
                cited_sentence=cited,
                citation_found_in_advisory=_normalize_ws(cited) in normalized_advisory,
                reasoning=raw["reasoning"],
            )
        )
    return verdicts
