import json
from types import SimpleNamespace
from pathlib import Path

import pytest

from triage.ingest import ingest_paths
from triage.intel import enrich
from triage.models import Component, Finding, Vulnerability
from triage.priority import load_policy, prioritize
from triage.remediation import remediate, rule_pick, verify
from triage.remediation import service as svc
from triage.remediation.prompt import RemediationDraft
from triage.remediation.providers.anthropic_provider import AnthropicProvider
from triage.remediation.providers.base import ProviderError
from triage.remediation.providers.openai_provider import OpenAIProvider
from triage.remediation.versions import in_range, is_affected

FX = Path(__file__).resolve().parents[1] / "samples" / "fixtures"
LOG4J_AVAILABLE = ["2.3.1", "2.3.2", "2.12.2", "2.12.4", "2.14.1", "2.15.0", "2.16.0", "2.17.0", "2.17.1",
                   "2.20.0", "2.25.3", "2.25.4", "3.0.0-beta2"]


def log4j_group():
    comp = Component(id="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1", name="log4j-core",
                     group="org.apache.logging.log4j", version="2.14.1", ecosystem="maven")
    mk = lambda vid, fixed, ranges=(): Finding(key=vid, component=comp, vulnerability=Vulnerability(  # noqa: E731
        id=vid, fixed_versions=list(fixed), affected_ranges=list(ranges)))
    return [mk("CVE-2021-44228", ["2.3.1", "2.12.2", "2.15.0"], [">=2.13.0,<2.15.0"]),
            mk("CVE-2021-45046", ["2.3.1", "2.12.2", "2.16.0"]),
            mk("CVE-2021-44832", ["2.3.2", "2.12.4", "2.17.1"])]


def test_ranges_and_line_fix():
    assert in_range("2.14.1", ">=2.13.0,<2.15.0", "maven")
    assert not in_range("2.15.0", ">=2.13.0,<2.15.0", "maven")
    assert in_range("2.0", "<2.3.1 || >=2.4.0,<2.12.2", "maven")
    # 범위 정보가 없으면 '설치 버전대의 수정 버전'으로 판단: 2.14.1 의 다음 수정은 2.16.0
    assert is_affected("2.15.0", "2.14.1", [], ["2.3.1", "2.12.2", "2.16.0"], "maven")
    assert not is_affected("2.16.0", "2.14.1", [], ["2.3.1", "2.12.2", "2.16.0"], "maven")


def test_rule_pick_fixes_whole_group_and_skips_prerelease():
    target, notes = rule_pick(log4j_group(), LOG4J_AVAILABLE)
    assert target == "2.17.1"


@pytest.mark.parametrize("target,reason", [
    ("2.99.0", "레지스트리에 없는"),           # 존재하지 않는 버전(환각)
    ("2.15.0", "남는 급한 취약점"),                 # 존재하지만 다른 취약점 범위 안
    ("2.12.4", "높지 않음"),                   # 설치 버전보다 낮음
    ("3.0.0-beta2", "정식 버전이 아님"),
])
def test_verify_rejects(target, reason):
    c = verify(target, log4j_group(), LOG4J_AVAILABLE)
    assert not c.ok and reason in " ".join(c.notes)


def test_verify_accepts_and_offline_uses_scanner_fix_list():
    assert verify("2.17.1", log4j_group(), LOG4J_AVAILABLE).ok
    c = verify("2.17.1", log4j_group(), None)          # 레지스트리 모름 → 수정 버전 목록으로 존재 확인
    assert c.ok and "스캐너 수정 버전" in " ".join(c.notes)
    assert not verify("2.20.0", log4j_group(), None).ok


class FakeProvider:
    name, model = "fake", "fake-1"

    def __init__(self, target=None, fail=False):
        self.target, self.fail, self.calls = target, fail, 0

    def draft(self, ctx):
        self.calls += 1
        if self.fail:
            raise ProviderError("타임아웃")
        return RemediationDraft(target_version=self.target, summary_ko="요약", steps=[f"{self.target} 으로 올린다"],
                                workaround="완화")


@pytest.fixture
def bundle(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(tmp_path / "cache"))       # 발췌본 사용, LLM 캐시 격리
    monkeypatch.setattr(svc, "list_versions", lambda c, offline=False: None)   # 네트워크 없이
    b = ingest_paths([str(FX / "assets.csv"), f"{FX / 'grype.json'}=SVC-001"])
    enrich(b)
    return prioritize(b, load_policy())


def _log4j_rem(b):
    return next(r for r in b.remediations if "log4j-core" in r.finding_key)


def test_hallucinated_version_is_replaced_by_rule(bundle):
    p = FakeProvider(target="9.9.9")
    remediate(bundle, p)
    r = _log4j_rem(bundle)
    assert r.target_version != "9.9.9" and r.verified
    assert any("기각" in n for n in r.verify_notes)
    assert r.steps[0].startswith(r.target_version)                     # 단계 안의 버전도 교체
    assert bundle.meta["remediation"]["rejected_targets"] >= 1


def test_provider_failure_falls_back_to_template(bundle):
    remediate(bundle, FakeProvider(fail=True))
    r = _log4j_rem(bundle)
    assert r.fallback_used and r.provider == "template" and r.verified


def test_one_call_per_component_group_and_llm_cache(bundle):
    p = FakeProvider(target=None)
    remediate(bundle, p)
    groups = bundle.meta["remediation"]["groups"]
    assert p.calls == groups < len(bundle.findings)
    remediate(bundle, p)                                                 # 같은 입력 → 캐시
    assert p.calls == groups and bundle.meta["remediation"]["llm_cache_hits"] == groups


def test_llm_limit(bundle):
    p = FakeProvider()
    remediate(bundle, p, llm_limit=1)
    assert p.calls == 1


def test_no_key_falls_back_to_template(monkeypatch):
    from triage.remediation import get_provider
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    monkeypatch.setattr("dotenv.load_dotenv", lambda *a, **k: None)
    p = get_provider("anthropic")
    assert p.name == "template" and "ANTHROPIC_API_KEY" in p.init_warning


GOOD = {"target_version": "2.17.1", "summary_ko": "요약", "steps": ["a"], "workaround": "w"}


def test_anthropic_provider_parses_structured_output():
    sent = {}

    def create(**kw):
        sent.update(kw)
        return SimpleNamespace(stop_reason="end_turn", content=[SimpleNamespace(type="text", text=json.dumps(GOOD))])
    client = SimpleNamespace(messages=SimpleNamespace(create=create), beta=SimpleNamespace(messages=SimpleNamespace(create=create)))
    d = AnthropicProvider(model="claude-opus-5-5", client=client).draft({"x": 1})
    assert d.target_version == "2.17.1"
    assert sent["output_config"]["format"]["type"] == "json_schema" and sent["fallbacks"] == "default"


def test_anthropic_refusal_raises():
    resp = SimpleNamespace(stop_reason="refusal", content=[])
    client = SimpleNamespace(messages=SimpleNamespace(create=lambda **k: resp), beta=SimpleNamespace(messages=SimpleNamespace(create=lambda **k: resp)))
    with pytest.raises(ProviderError, match="거절"):
        AnthropicProvider(model="claude-opus-5-5", client=client).draft({})


def test_openai_provider_parses_json_schema_output():
    sent = {}

    def create(**kw):
        sent.update(kw)
        msg = SimpleNamespace(content=json.dumps(GOOD), refusal=None)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg, finish_reason="stop")])
    client = SimpleNamespace(chat=SimpleNamespace(completions=SimpleNamespace(create=create)))
    d = OpenAIProvider(model="m", client=client).draft({})
    assert d.steps == ["a"] and sent["response_format"]["json_schema"]["strict"] is True


def test_prefers_same_major_when_only_low_tier_issues_need_major_upgrade():
    comp = Component(id="pkg:maven/g/lib@5.3.13", name="lib", group="g", version="5.3.13", ecosystem="maven")
    urgent = Finding(key="u", component=comp, vulnerability=Vulnerability(id="CVE-U", fixed_versions=["5.3.18"]))
    low = Finding(key="l", component=comp, vulnerability=Vulnerability(id="CVE-L", fixed_versions=["6.0.0"],
                                                                       affected_ranges=["<6.0.0"]))
    avail = ["5.3.18", "5.3.39", "6.0.0", "6.1.0"]
    target, notes = rule_pick([urgent, low], avail, required={"CVE-U"})
    assert target == "5.3.18" and "메이저 업그레이드" in " ".join(notes)
    assert verify("5.3.18", [urgent, low], avail, required={"CVE-U"}).ok
    assert not verify("5.3.18", [urgent, low], avail, required={"CVE-U", "CVE-L"}).ok
    # 급한 건이 없으면 같은 메이저에서 줄일 수 있는 만큼 줄인다
    assert rule_pick([urgent, low], avail, required=set())[0] == "5.3.18"
    # 급한 취약점이 메이저 업그레이드로만 고쳐지면 메이저를 올린다
    assert rule_pick([urgent, low], avail, required={"CVE-L"})[0] == "6.0.0"
