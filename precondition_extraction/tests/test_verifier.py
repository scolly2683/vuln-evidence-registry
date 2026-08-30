import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from precondition_extraction.extractor import PreconditionCandidate
from precondition_extraction.verifier import VerificationError, verify_candidates

ADVISORY = (
    "An attacker who can control log messages can execute arbitrary code when "
    "message lookup substitution is enabled. From log4j 2.15.0, this behavior "
    "has been disabled by default."
)

CANDIDATES = [
    PreconditionCandidate(
        statement=(
            "An attacker who can control log messages can execute arbitrary code "
            "when message lookup substitution is enabled."
        ),
        category="configuration",
        enabled_by_default=None,
    ),
    PreconditionCandidate(
        statement="From log4j 2.15.0, this behavior has been disabled by default.",
        category="configuration",
        enabled_by_default=False,
    ),
]


class StubClient:
    """Stands in for anthropic.Anthropic() — records the request, returns a canned response."""

    def __init__(self, response):
        self.requests = []
        outer = self

        class _Messages:
            def create(self, **kwargs):
                outer.requests.append(kwargs)
                return response

        self.beta = SimpleNamespace(messages=_Messages())


def _response(verdicts, stop_reason="end_turn"):
    return SimpleNamespace(
        stop_reason=stop_reason,
        stop_details=None,
        content=[SimpleNamespace(type="text", text=json.dumps({"verdicts": verdicts}))],
    )


def _good_verdicts():
    return [
        {
            "candidate_index": 0,
            "is_genuine_precondition": True,
            "cited_sentence": (
                "An attacker who can control log messages can execute arbitrary code "
                "when message lookup substitution is enabled."
            ),
            "reasoning": "States a configuration condition gating exploitability.",
        },
        {
            "candidate_index": 1,
            "is_genuine_precondition": False,
            "cited_sentence": "From log4j 2.15.0, this behavior has been disabled by default.",
            "reasoning": "Describes the fix history, not a condition on the target.",
        },
    ]


def test_verdicts_parsed_and_paired_with_candidates():
    client = StubClient(_response(_good_verdicts()))
    verdicts = verify_candidates(ADVISORY, CANDIDATES, client=client)
    assert len(verdicts) == 2
    assert verdicts[0].is_genuine_precondition is True
    assert verdicts[1].is_genuine_precondition is False
    assert verdicts[0].statement == CANDIDATES[0].statement
    assert all(v.citation_found_in_advisory for v in verdicts)


def test_request_is_read_only_and_carries_the_inputs():
    client = StubClient(_response(_good_verdicts()))
    verify_candidates(ADVISORY, CANDIDATES, client=client)
    request = client.requests[0]
    assert "tools" not in request  # read-only: no tools offered at all
    prompt = request["messages"][0]["content"]
    assert ADVISORY.split(".")[0] in prompt
    assert "0. [configuration]" in prompt
    assert CANDIDATES[1].statement in prompt
    assert request["output_config"]["format"]["type"] == "json_schema"


def test_fabricated_citation_is_flagged_not_trusted():
    verdicts = _good_verdicts()
    verdicts[0]["cited_sentence"] = "A sentence that is not in the advisory at all."
    client = StubClient(_response(verdicts))
    result = verify_candidates(ADVISORY, CANDIDATES, client=client)
    assert result[0].citation_found_in_advisory is False
    assert result[1].citation_found_in_advisory is True


def test_citation_check_tolerates_whitespace_differences():
    verdicts = _good_verdicts()
    verdicts[1]["cited_sentence"] = "From log4j 2.15.0,  this behavior\nhas been disabled by default."
    client = StubClient(_response(verdicts))
    result = verify_candidates(ADVISORY, CANDIDATES, client=client)
    assert result[1].citation_found_in_advisory is True


def test_missing_verdict_for_a_candidate_raises():
    client = StubClient(_response(_good_verdicts()[:1]))
    with pytest.raises(VerificationError, match=r"missing verdicts for candidates \[1\]"):
        verify_candidates(ADVISORY, CANDIDATES, client=client)


def test_refusal_raises_with_category():
    response = SimpleNamespace(
        stop_reason="refusal",
        stop_details=SimpleNamespace(category="cyber", explanation="..."),
        content=[],
    )
    with pytest.raises(VerificationError, match="declined.*cyber"):
        verify_candidates(ADVISORY, CANDIDATES, client=StubClient(response))


def test_malformed_json_raises():
    response = SimpleNamespace(
        stop_reason="end_turn",
        stop_details=None,
        content=[SimpleNamespace(type="text", text="not json")],
    )
    with pytest.raises(VerificationError, match="expected JSON shape"):
        verify_candidates(ADVISORY, CANDIDATES, client=StubClient(response))


def test_empty_candidate_list_makes_no_api_call():
    client = StubClient(_response([]))
    assert verify_candidates(ADVISORY, [], client=client) == []
    assert client.requests == []
