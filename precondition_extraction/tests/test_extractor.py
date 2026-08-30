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


def test_shellshock_categorized_as_deployment():
    """Shellshock's precondition sentence must be tagged DEPLOYMENT.

    History: the first-pass categorizer took the first category with ANY
    keyword hit, so the word "setting" — used as a plain verb here ("...in
    which setting the environment occurs...") — tagged this sentence
    "configuration", outranking seven genuine deployment cues in the same
    sentence (privilege boundary, cgi, ssh, environment variable, script,
    via, vector). That wrong result was pinned in an earlier version of this
    test as a documented limitation. The categorizer is now score-based (most
    keyword hits wins, priority order breaks ties), which resolves it; this
    test keeps the case pinned so the fix can't silently regress.
    """
    candidates = extract_precondition_candidates(FIXTURES["CVE-2014-6271"]["advisory_text"])
    assert len(candidates) == 1
    assert candidates[0].category == "deployment"


def test_version_capture_strips_trailing_sentence_period():
    # "[0-9][\w.\-]*" allows dots inside a version, so a version at the end
    # of a sentence would otherwise keep the sentence's final period.
    result = extract_version_range("This issue is fixed in releases before 5.4.")
    assert result.fixed == "5.4"
