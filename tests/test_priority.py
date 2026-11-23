from datetime import date
from pathlib import Path

import pytest
import yaml

from triage.config import config_dir
from triage.models import AssetContext, Component, Finding, KevInfo, Signals, Status, Tier, TriageBundle, Vulnerability
from triage.priority import load_policy, prioritize
from triage.priority.engine import evaluate, interp

AS_OF = date(2026, 11, 24)
POL = load_policy()


def mk(vid="CVE-2099-0001", cvss=5.0, epss=None, kev=False, status=Status.affected, asset="A", fixed=("1.1",)):
    comp = Component(id=f"pkg:maven/g/{vid}@1.0", name=vid, version="1.0")
    return Finding(key=Finding.make_key(vid, comp.id, asset), component=comp, asset_id=asset, status=status,
                   vulnerability=Vulnerability(id=vid, cvss_score=cvss, fixed_versions=list(fixed)),
                   signals=Signals(kev=KevInfo(listed=kev, date_added="2021-12-10" if kev else ""), epss=epss))


EXPOSED_HIGH = AssetContext(asset_id="A", internet_exposed=True, criticality=5)
INTERNAL_LOW = AssetContext(asset_id="A", internet_exposed=False, criticality=1)


def test_kev_is_p1_even_with_low_scores_and_internal_asset():
    r = evaluate(mk(cvss=3.0, epss=0.001, kev=True), INTERNAL_LOW, POL, AS_OF)
    assert r.tier == Tier.P1 and r.layer == "kev"
    assert any(x.signal == "kev" for x in r.reasons)


def test_not_affected_beats_kev():
    r = evaluate(mk(kev=True, status=Status.not_affected), EXPOSED_HIGH, POL, AS_OF)
    assert r.tier == Tier.P4 and r.layer == "not_affected"


def test_score_layer_orders_by_context():
    hi = evaluate(mk(cvss=9.8, epss=0.6), EXPOSED_HIGH, POL, AS_OF)
    lo = evaluate(mk(cvss=9.8, epss=0.6), INTERNAL_LOW, POL, AS_OF)
    assert hi.score > lo.score
    assert hi.tier.rank < lo.tier.rank


def test_override_min_tier_for_exposed_high_epss():
    # 점수만으로는 P3 이지만 외부 노출 + EPSS ≥ 0.1 이면 최소 P2
    asset = AssetContext(asset_id="A", internet_exposed=True, criticality=1)
    r = evaluate(mk(cvss=4.0, epss=0.12), asset, POL, AS_OF)
    assert r.tier == Tier.P2
    assert any(x.signal == "override" for x in r.reasons)


def test_override_max_tier_for_internal_low_criticality():
    r = evaluate(mk(cvss=10.0, epss=0.97), INTERNAL_LOW, POL, AS_OF)
    assert r.tier == Tier.P3


def test_missing_values_are_explained_and_conservative():
    f = mk(cvss=None, epss=None)
    f.vulnerability.severity = "critical"
    r = evaluate(f, None, POL, AS_OF)
    texts = " ".join(str(x.value) for x in r.reasons)
    assert "EPSS 값 없음" in texts and "CVSS 없음" in texts and "외부 노출 여부 모름" in texts


def test_due_dates_exposed_halved():
    r = evaluate(mk(kev=True), EXPOSED_HIGH, POL, AS_OF)
    assert r.due_days == 4 and r.due_date == "2026-11-28"      # 7일 × 0.5 올림
    r = evaluate(mk(kev=True), INTERNAL_LOW, POL, AS_OF)
    assert r.due_days == 7


def test_ranking_is_deterministic_and_kev_first():
    b = TriageBundle(assets=[EXPOSED_HIGH], findings=[
        mk("CVE-2099-0003", cvss=9.8, epss=0.9), mk("CVE-2099-0002", cvss=5.0, epss=0.01, kev=True),
        mk("CVE-2099-0001", cvss=2.0, epss=0.0)])
    order1 = [r.finding_key for r in prioritize(b, POL, AS_OF).results]
    b.findings.reverse()
    order2 = [r.finding_key for r in prioritize(b, POL, AS_OF).results]
    assert order1 == order2
    assert order1[0].startswith("CVE-2099-0002")             # KEV 가 같은 P1 안에서도 먼저
    assert [r.rank for r in b.results] == [1, 2, 3]


def test_policy_change_changes_tier(tmp_path):
    data = yaml.safe_load((config_dir() / "policy.yaml").read_text(encoding="utf-8"))
    data["layers"]["kev"]["tier"] = "P2"
    p = tmp_path / "policy.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    pol2 = load_policy(p)
    assert evaluate(mk(kev=True), INTERNAL_LOW, pol2, AS_OF).tier == Tier.P2
    assert pol2.fingerprint != POL.fingerprint


def test_invalid_policy_rejected(tmp_path):
    data = yaml.safe_load((config_dir() / "policy.yaml").read_text(encoding="utf-8"))
    data["score"]["thresholds"] = {"P1": 0.3, "P2": 0.6, "P3": 0.35}
    p = tmp_path / "bad.yaml"
    p.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    with pytest.raises(Exception):
        load_policy(p)


def test_interp():
    assert interp(0.0, POL.score.epss_scale) == 0.0
    assert interp(0.1, POL.score.epss_scale) == pytest.approx(0.6)
    assert interp(0.3, POL.score.epss_scale) == pytest.approx(0.75)
