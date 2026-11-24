import gzip
import importlib
import json
import re
from copy import deepcopy
from pathlib import Path

import httpx
import pytest

from triage.lookup import LookupResult, lookup
from triage.lookup import _http
from triage.models import Component, Status

LOOKUP = importlib.import_module("triage.lookup")
FIXTURE = Path(__file__).parent / "fixtures" / "finals" / "lookup.json"


@pytest.fixture
def setup(monkeypatch, tmp_path):
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    intel = tmp_path / "intel"
    intel.mkdir()
    (intel / "kev.json").write_text(json.dumps(fixture["kev"]), encoding="utf-8")
    with gzip.open(intel / "epss_scores.csv.gz", "wt", encoding="utf-8") as stream:
        stream.write("#model_version:test,score_date:2099-03-01\ncve,epss,percentile\nCVE-2099-1001,0.27,0.81\n")
    cache = tmp_path / "lookup"
    monkeypatch.setattr(LOOKUP, "CACHE_DIR", cache)
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(intel))
    client_type = httpx.Client

    def transport(handler):
        monkeypatch.setattr(httpx, "Client", lambda **kwargs: client_type(transport=httpx.MockTransport(handler), **kwargs))

    return fixture, cache, transport


def test_osv_batch_details_scoped_aliases_intel_and_offline_subset(setup, monkeypatch):
    fixture, cache, transport = setup
    lib = Component(id="a", name="Fixture_Lib", ecosystem="pypi", version="1.2.0", evidence_ids=["collect-0001"])
    other = Component(id="b", name="widget", group="@fixture", ecosystem="npm", version="1.2.0")
    requested = []

    def handle(request):
        requested.append(request.url.path)
        if request.url.path == "/v1/querybatch":
            results = []
            for query in json.loads(request.content)["queries"]:
                assert query["version"] == "1.2.0"
                if query.get("page_token") == "next":
                    results.append({"vulns": [{"id": "OSV-TEST-B"}]})
                    continue
                result = {"vulns": [{"id": "OSV-TEST-A"}]}
                if query["package"]["ecosystem"] == "PyPI":
                    assert query["package"]["name"] == "Fixture_Lib"
                    result["next_page_token"] = "next"
                else:
                    assert query["package"]["name"] == "@fixture/widget"
                results.append(result)
            return httpx.Response(200, json={"results": results})
        return httpx.Response(200, json=fixture["osv"][request.url.path.rsplit("/", 1)[-1]])

    transport(handle)
    result = lookup([other, lib])
    assert isinstance(result, LookupResult)
    first, second = result.findings
    assert requested.count("/v1/querybatch") == 2
    assert requested.count("/v1/vulns/OSV-TEST-A") == 1
    assert first.component.id == "a"
    assert first.vulnerability.id == second.vulnerability.id == "CVE-2099-1001"
    assert set(first.vulnerability.aliases) == {"OSV-TEST-A", "OSV-TEST-B", "OSV-TEST-LINK"}
    assert first.vulnerability.fixed_versions == ["1.3.0"]
    assert set(first.vulnerability.affected_ranges) == {">=1.0.0,<1.3.0", "<=1.2.0", ">=2.0.0,<3.0.0"}
    assert first.version_in_range is True and first.status == Status.unknown
    assert first.signals.kev.listed and first.signals.epss == pytest.approx(0.27)
    assert second.version_in_range is False and second.vulnerability.fixed_versions == []
    assert second.vulnerability.affected_ranges == ["==5.0.0"]
    assert len({item.id for item in result.evidence}) == len(result.evidence)
    assert all(re.fullmatch(r"lookup-\d{4}", item.id) for item in result.evidence)
    assert {i for finding in result.findings for i in finding.hints["evidence_ids"]} <= {i.id for i in result.evidence}
    assert any("collect-0001" in item.note for item in result.evidence)
    assert all(re.fullmatch(r"\d{4}-\d{2}-\d{2}", folder.name) for folder in cache.iterdir())
    assert any(json.loads(f.read_text(encoding="utf-8")).get("results") for f in cache.glob("*/*.json"))

    def no_network(**kwargs):
        pytest.fail("offline에서 HTTP 클라이언트를 만들었습니다")

    monkeypatch.setattr(httpx, "Client", no_network)
    replay = lookup([lib], offline=True)
    assert len(replay.findings) == 1
    assert replay.findings[0].model_dump(exclude={"hints"}) == first.model_dump(exclude={"hints"})


def test_nvd_pagination_matching_configurations_and_floating_tag(setup):
    fixture, _, transport = setup
    runtime = Component(id="r", name="node", kind="runtime", version="20.1.0")
    image = Component(id="i", name="docker.io/library/node:20-alpine", kind="base-image",
                      version="20", version_source="dockerfile")
    unrelated = Component(id="u", name="example.invalid/team/node", kind="base-image", version="20.1.0")
    second = deepcopy(fixture["nvd"])
    second["id"] = "CVE-2099-1003"
    second["configurations"][0]["nodes"][0]["cpeMatch"][0]["versionEndExcluding"] = "20.1.0"
    conditional = deepcopy(fixture["nvd"])
    conditional["id"] = "CVE-2099-1004"
    node = conditional["configurations"][0]["nodes"][0]
    node["operator"] = "AND"
    node["cpeMatch"][1]["vulnerable"] = False
    called = []

    def handle(request):
        assert request.method == "GET" and request.url.path == "/rest/json/cves/2.0"
        target = request.url.params["virtualMatchString"]
        offset = int(request.url.params["startIndex"])
        called.append((target, offset))
        rows = [[fixture["nvd"], conditional], [second]]
        return httpx.Response(200, json={"vulnerabilities": [{"cve": row} for row in rows[offset // 2]],
                                         "resultsPerPage": 2, "totalResults": 3})

    transport(handle)
    result = lookup([runtime, image, unrelated])
    versions = {(f.component.id, f.vulnerability.id): f.version_in_range for f in result.findings}
    assert versions == {
        ("r", "CVE-2099-1002"): True, ("r", "CVE-2099-1003"): False, ("r", "CVE-2099-1004"): None,
        ("i", "CVE-2099-1002"): None, ("i", "CVE-2099-1003"): None, ("i", "CVE-2099-1004"): None,
    }
    product = "cpe:2.3:a:nodejs:node.js"
    assert called == [(product + ":20.1.0", 0), (product + ":20.1.0", 2), (product, 0), (product, 2)]
    assert any("u: NVD 제품 CPE" in item.note for item in result.evidence)
    assert all(f.vulnerability.fixed_versions == [] for f in result.findings)
    assert all(f.vulnerability.references[0].startswith("https://nvd.nist.gov/vuln/detail/") for f in result.findings)
    assert all(f.vulnerability.affected_ranges[0].startswith(">=20.0.0,") for f in result.findings)


def test_retries_log_each_attempt_and_cache_miss_is_visible(setup, monkeypatch):
    _, cache, transport = setup
    component = Component(id="a", name="fixture-lib", ecosystem="pypi", version="^1.2", version_source="manifest_range")
    events, delays = [], []
    monkeypatch.setattr(_http.time, "sleep", delays.append)

    def fail(request):
        assert "version" not in json.loads(request.content)["queries"][0]
        if len(delays) < 2:
            raise httpx.ReadTimeout("timeout", request=request)
        return httpx.Response(503)

    transport(fail)
    result = lookup([component], log=lambda stage, event, **data: events.append((stage, event, data)))
    assert all(stage == "lookup" for stage, _, _ in events)
    assert [data["attempt"] for _, event, data in events if event == "attempt"] == [1, 2, 3, 4]
    assert delays == [1, 2, 4]
    assert not result.findings and not cache.exists()
    assert "응답을 확인할 수 없음" in result.evidence[0].note


def test_missing_osv_detail_remains_candidate_and_uses_stale_batch(setup, monkeypatch):
    _, _, transport = setup
    component = Component(id="a", name="fixture-lib", ecosystem="pypi", version="1.2.0")

    def handle(request):
        if request.method == "POST":
            return httpx.Response(200, json={"results": [{"vulns": [{"id": "OSV-TEST-MISSING"}]}]})
        return httpx.Response(404)

    transport(handle)
    initial = lookup([component])
    assert initial.findings[0].version_in_range is None
    assert initial.findings[0].vulnerability.id == "OSV-TEST-MISSING"
    assert any("상세 OSV-TEST-MISSING: 응답을 확인할 수 없음" in item.note for item in initial.evidence)

    def unavailable(request):
        raise httpx.ConnectError("offline", request=request)

    transport(unavailable)
    monkeypatch.setattr(_http.time, "sleep", lambda _: None)
    fallback = lookup([component])
    assert fallback.findings == initial.findings
    assert lookup([component], offline=True).findings == initial.findings
