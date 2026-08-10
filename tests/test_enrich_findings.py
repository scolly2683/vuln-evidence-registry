"""tools/enrich_findings.py — tier-0 exploitation-intel enrichment.

The band logic is the contract: KEV or high EPSS -> act_now; public PoC or
moderate EPSS -> verify; else standard.
"""

import importlib.util
import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

_spec = importlib.util.spec_from_file_location(
    "enrich_findings", REPO_ROOT / "tools" / "enrich_findings.py"
)
enrich_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(enrich_mod)


def test_band_thresholds():
    assert enrich_mod.band(True, None, False) == "act_now"
    assert enrich_mod.band(False, 0.30, False) == "act_now"
    assert enrich_mod.band(False, 0.29, False) == "verify"
    assert enrich_mod.band(False, 0.10, False) == "verify"
    assert enrich_mod.band(False, None, True) == "verify"
    assert enrich_mod.band(False, 0.05, False) == "standard"
    assert enrich_mod.band(False, None, False) == "standard"


def test_kev_beats_low_epss():
    assert enrich_mod.band(True, 0.01, False) == "act_now"


def test_load_kev_cisa_format(tmp_path):
    p = tmp_path / "kev.json"
    p.write_text(json.dumps({"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}), encoding="utf-8")
    assert enrich_mod.load_kev(p) == {"CVE-2021-44228"}


def test_load_epss_skips_comment_line(tmp_path):
    p = tmp_path / "epss.csv"
    p.write_text(
        "#model_version:v2025,score_date:2026-08-09\n"
        "cve,epss,percentile\n"
        "CVE-2021-44228,0.94,0.999\n"
        "CVE-2000-0001,0.02,0.400\n",
        encoding="utf-8",
    )
    scores = enrich_mod.load_epss(p)
    assert scores["CVE-2021-44228"] == (0.94, 0.999)
    assert scores["CVE-2000-0001"][0] == 0.02


def test_load_poc_ignores_blanks_and_comments(tmp_path):
    p = tmp_path / "poc.txt"
    p.write_text("# from nomi-sec\nCVE-2021-44228\n\ncve-2022-22965\n", encoding="utf-8")
    assert enrich_mod.load_poc(p) == {"CVE-2021-44228", "CVE-2022-22965"}


def test_enrich_one_tags_and_bands():
    finding = {"id": "f-1", "cve_id": "CVE-2021-44228", "product": "Log4j"}
    out = enrich_mod.enrich_one(
        finding,
        kev={"CVE-2021-44228"},
        epss={"CVE-2021-44228": (0.94, 0.999)},
        poc={"CVE-2021-44228"},
    )
    assert out["kev"] is True
    assert out["epss"] == 0.94
    assert out["poc_public"] is True
    assert out["triage_band"] == "act_now"
    assert out["id"] == "f-1"  # original fields preserved


def test_unknown_cve_is_standard():
    out = enrich_mod.enrich_one(
        {"id": "f-2", "cve_id": "CVE-2099-9999"}, kev=set(), epss={}, poc=set()
    )
    assert out["triage_band"] == "standard"
    assert out["epss"] is None


def test_cli_end_to_end(tmp_path, capsys):
    findings = tmp_path / "f.jsonl"
    findings.write_text(
        '{"id": "a", "cve_id": "CVE-2021-44228"}\n'
        '{"id": "b", "cve_id": "CVE-2000-0001"}\n',
        encoding="utf-8",
    )
    kev = tmp_path / "kev.json"
    kev.write_text('{"vulnerabilities": [{"cveID": "CVE-2021-44228"}]}', encoding="utf-8")
    out = tmp_path / "enriched.jsonl"
    rc = enrich_mod.main(
        ["--findings", str(findings), "--kev", str(kev), "--out", str(out), "--stats"]
    )
    assert rc == 0
    rows = [json.loads(ln) for ln in out.read_text(encoding="utf-8").splitlines()]
    assert rows[0]["triage_band"] == "act_now"
    assert rows[1]["triage_band"] == "standard"
    assert '"act_now": 1' in capsys.readouterr().err
