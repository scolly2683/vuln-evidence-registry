import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from precondition_extraction.extractor import extract_precondition_candidates, extract_version_range
from precondition_extraction.schema import iter_fixtures

FIXTURES_DIR = Path(__file__).resolve().parent / "fixtures"
FIXTURES = {cve_id: data for _, data in iter_fixtures(FIXTURES_DIR) for cve_id in [data["cve_id"]]}


def test_log4shell_version_range():
    result = extract_version_range(FIXTURES["CVE-2021-44228"]["advisory_text"])
    assert result.introduced == "2.0-beta9"
    assert result.fixed == "2.16.0"
    assert result.excluded_fixed == ["2.12.2", "2.12.3", "2.3.1"]


def test_shellshock_version_range_correctly_finds_nothing_clean():
    # "GNU Bash through 4.3" has no digit-starting token before "through" and
    # no "before X" / "From version X ... removed" phrasing — there IS no
    # clean version boundary in this advisory's wording (see the fixture's
    # own notes on why). The extractor should say "I don't know" (None)
    # rather than guess, which is the correct behaviour here.
    result = extract_version_range(FIXTURES["CVE-2014-6271"]["advisory_text"])
    assert result.introduced is None
    assert result.fixed is None
    assert result.excluded_fixed == []


def test_pyyaml_version_range():
    result = extract_version_range(FIXTURES["CVE-2020-14343"]["advisory_text"])
    assert result.introduced is None
    assert result.fixed == "5.4"
    assert result.excluded_fixed == []


def test_every_fixture_yields_at_least_one_precondition_candidate():
    for cve_id, data in FIXTURES.items():
        candidates = extract_precondition_candidates(data["advisory_text"])
        assert candidates, f"{cve_id}: expected at least one candidate sentence"


def test_log4shell_candidates_flag_a_configuration_default():
    candidates = extract_precondition_candidates(FIXTURES["CVE-2021-44228"]["advisory_text"])
    disabled_by_default = [c for c in candidates if c.enabled_by_default is False]
    assert disabled_by_default, "expected at least one 'disabled by default' candidate"
    assert disabled_by_default[0].category == "configuration"


def test_pyyaml_candidates_flag_api_usage():
    candidates = extract_precondition_candidates(FIXTURES["CVE-2020-14343"]["advisory_text"])
    assert any(c.category == "api-usage" for c in candidates)


def test_shellshock_precondition_heuristic_known_limitation():
    """Pins a known WRONG categorization — not a target to preserve on purpose.

    Shellshock's precondition is really about DEPLOYMENT (some other system
    has to feed attacker data into Bash's environment across a privilege
    boundary), but the keyword heuristic tags its one candidate sentence as
    "configuration" — triggered by the word "setting" used as a plain verb
    ("...in which setting the environment occurs...") rather than in the
    "configuration setting" sense the keyword list was written for. This is
    a real limitation of keyword matching, pinned here on purpose (the same
    way pattern 2 pins tricky edge cases) so a future fix to the categorizer
    is a deliberate, visible change to this test — not a silent regression
    nobody notices.
    """
    candidates = extract_precondition_candidates(FIXTURES["CVE-2014-6271"]["advisory_text"])
    assert len(candidates) == 1
    assert candidates[0].category == "configuration"  # known wrong; see docstring above
