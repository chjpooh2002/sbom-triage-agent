import json
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from triage.ingest import ingest_paths
from triage.intel import cache as cache_mod
from triage.intel import enrich, fetch_all, load_intel

ROOT = Path(__file__).resolve().parents[1]
SNAP = ROOT / "data" / "snapshot"
FX = ROOT / "samples" / "fixtures"


@pytest.fixture
def bundle():
    return ingest_paths([str(FX / "assets.csv"), f"{FX / 'trivy.json'}=SVC-001"])


@pytest.fixture
def no_network(monkeypatch):
    import httpx

    def boom(*a, **k):
        raise AssertionError("보강 단계에서 네트워크를 쓰면 안 됨")
    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.setattr(httpx.Client, "get", boom)


def _cache_from_snapshot(tmp_path, fetched_at=None):
    d = tmp_path / "cache"
    d.mkdir()
    for f in ("kev.json", "epss_scores.csv.gz"):
        shutil.copy(SNAP / f, d / f)
    ts = (fetched_at or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    (d / "manifest.json").write_text(json.dumps({
        "kev": {"fetched_at": ts, "date_released": "2026-11-20T00:00:00Z"},
        "epss": {"fetched_at": ts, "score_date": "2026-11-22"}}), encoding="utf-8")
    return d


def test_trivy_has_no_kev_hints_so_signals_come_from_cache(tmp_path, monkeypatch, bundle, no_network):
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(_cache_from_snapshot(tmp_path)))
    enrich(bundle)
    f = next(x for x in bundle.findings if x.vulnerability.id == "CVE-2021-44228")
    assert f.signals.kev.listed and f.signals.kev.date_added == "2021-12-10"
    assert f.signals.kev.ransomware is True
    assert f.signals.epss and f.signals.epss > 0.9 and "EPSS" in f.signals.epss_source
    other = next(x for x in bundle.findings if x.vulnerability.id == "CVE-2022-1471")
    assert other.signals.kev.listed is False and other.signals.kev.source   # 확인했지만 미등재
    assert bundle.meta["intel"]["kev"]["origin"] == "cache" and not bundle.meta["intel"]["warnings"]


def test_snapshot_fallback_when_no_cache(tmp_path, monkeypatch, bundle, no_network):
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(tmp_path / "empty"))
    enrich(bundle)
    assert bundle.meta["intel"]["kev"]["origin"] == "snapshot"
    assert any("발췌본" in w for w in bundle.meta["intel"]["warnings"])
    f = next(x for x in bundle.findings if x.vulnerability.id == "CVE-2021-44228")
    assert f.signals.kev.listed


def test_stale_cache_warns_but_is_used(tmp_path, monkeypatch):
    old = datetime.now(timezone.utc) - timedelta(days=10)
    src = load_intel(None, _cache_from_snapshot(tmp_path, old))
    assert src.kev and any("시간 전" in w for w in src.warnings)


def test_cache_beats_scanner_hint(tmp_path, monkeypatch, no_network):
    """grype 는 KEV 보조값을 주지만, 전체 캐시에서 확인한 값이 우선한다."""
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(_cache_from_snapshot(tmp_path)))
    b = ingest_paths([f"{FX / 'grype.json'}=A"])
    enrich(b)
    f = next(x for x in b.findings if x.vulnerability.id == "CVE-2021-44228")
    assert f.signals.kev.source.startswith("CISA KEV")


def test_failed_download_keeps_existing_cache(tmp_path, monkeypatch):
    d = _cache_from_snapshot(tmp_path)
    before = (d / "kev.json").read_bytes()

    def fail(*a, **k):
        raise RuntimeError("네트워크 없음")
    monkeypatch.setattr(cache_mod, "_download", fail)
    report = fetch_all(["kev"], d)
    assert report["kev"]["ok"] is False and report["kev"]["kept"] is True
    assert (d / "kev.json").read_bytes() == before
