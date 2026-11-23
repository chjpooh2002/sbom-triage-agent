from pathlib import Path

import pytest

from triage.evaluation import GoldError, kendall_tau_b, load_gold, run_eval
from triage.models import Tier
from triage.priority import load_policy

ROOT = Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "eval" / "example_cases.csv"
HDR = (ROOT / "eval" / "gold_template.csv").read_text(encoding="utf-8")


def test_example_cases_load_and_score():
    cases = load_gold(EXAMPLE)
    assert [c.case_id for c in cases] == ["EX1", "EX2", "EX3"]
    assert cases[0].finding.signals.kev.listed and cases[0].asset.internet_exposed
    scores, results = run_eval(cases, load_policy())
    names = [s.name for s in scores]
    assert names[0].startswith("CVSS") and names[1].startswith("규칙")
    rule = scores[1]
    assert results["EX1"].tier == Tier.P1 and results["EX3"].tier == Tier.P4
    assert 0 <= rule.exact <= 1 and rule.p1_expected == 1


def test_template_header_matches_loader_columns():
    from triage.evaluation.gold import OPTIONAL, REQUIRED
    cols = HDR.strip().split(",")
    assert set(REQUIRED) <= set(cols) and set(cols) <= set(REQUIRED) | set(OPTIONAL)


@pytest.mark.parametrize("row,msg", [
    ("G1,CVE-1,pkg:maven/a/b,1.0,,Y,3,N,0.5,7,,affected,Y,,P5,,근거,,", "expected_tier"),
    ("G1,CVE-1,pkg:maven/a/b,1.0,,Y,3,N,1.5,7,,affected,Y,,P1,,근거,,", "epss"),
    ("G1,CVE-1,pkg:maven/a/b,1.0,,maybe,3,N,0.5,7,,affected,Y,,P1,,근거,,", "internet_exposed"),
    ("G1,CVE-1,pkg:maven/a/b,1.0,,Y,3,N,0.5,7,,affected,Y,,P1,,,,", "rationale"),
])
def test_invalid_gold_rejected(tmp_path, row, msg):
    p = tmp_path / "gold.csv"
    p.write_text(HDR + row + "\n", encoding="utf-8")
    with pytest.raises(GoldError, match=msg):
        load_gold(p)


def test_duplicate_case_id_rejected(tmp_path):
    row = "G1,CVE-1,pkg:maven/a/b,1.0,,Y,3,N,0.5,7,,affected,Y,,P1,,근거,,\n"
    p = tmp_path / "gold.csv"
    p.write_text(HDR + row + row, encoding="utf-8")
    with pytest.raises(GoldError, match="중복"):
        load_gold(p)


def test_kendall_tau():
    assert kendall_tau_b([1, 2, 3], [1, 2, 3]) == pytest.approx(1.0)
    assert kendall_tau_b([1, 2, 3], [3, 2, 1]) == pytest.approx(-1.0)
    assert kendall_tau_b([1, 1, 1], [1, 2, 3]) is None
