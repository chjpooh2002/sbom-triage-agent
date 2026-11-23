"""본선 리허설: 처음 보는 형식(CSV 스캔 결과)을 변환기 하나로 붙이면 전체 흐름이 도는지 확인한다."""
import csv
from datetime import date
from pathlib import Path

from triage.ingest import register
from triage.ingest.common import component_id, make_purl
from triage.ingest.registry import ParsedInput
from triage.models import Component, Finding, Vulnerability
from triage.pipeline import run
from triage.remediation import service as svc

FX = Path(__file__).resolve().parents[1] / "samples" / "fixtures"


def _is_vendor_csv(path: Path, raw) -> bool:
    if path.suffix.lower() != ".csv":
        return False
    with path.open(encoding="utf-8-sig") as fh:
        return {"취약점ID", "패키지", "버전"} <= set(next(csv.reader(fh)))


@register("vendor-csv", kind="scan", sniff=_is_vendor_csv, priority=10)
def parse_vendor_csv(path: Path, raw=None) -> ParsedInput:
    findings = []
    with path.open(encoding="utf-8-sig") as fh:
        for row in csv.DictReader(fh):
            purl = make_purl("Maven", row["패키지"], row["버전"])
            g, _, a = row["패키지"].partition(":")
            comp = Component(id=component_id(purl), name=a, group=g, version=row["버전"], ecosystem="maven", purl=purl)
            vuln = Vulnerability(id=row["취약점ID"], cvss_score=float(row["CVSS"] or 0) or None,
                                 fixed_versions=[v for v in row["조치버전"].split(";") if v])
            findings.append(Finding(key=Finding.make_key(vuln.id, comp.id, None), component=comp,
                                    vulnerability=vuln, scanners=["vendor-csv"]))
    return ParsedInput(source=str(path), converter="vendor-csv", kind="scan", findings=findings, target=path.stem)


def test_new_format_runs_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("TRIAGE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setattr(svc, "list_versions", lambda c, offline=False: None)
    scan = tmp_path / "target.csv"
    scan.write_text("취약점ID,패키지,버전,CVSS,조치버전\n"
                    "CVE-2021-44228,org.apache.logging.log4j:log4j-core,2.14.1,10.0,2.15.0;2.17.1\n"
                    "CVE-2022-42889,org.apache.commons:commons-text,1.9,9.8,1.10.0\n", encoding="utf-8")
    res = run([str(FX / "assets.csv"), str(scan)], tmp_path / "out", "template", as_of=date(2026, 11, 24))
    b = res.bundle
    assert b.meta["inputs"][1]["converter"] == "vendor-csv" and b.meta["inputs"][1]["asset_id"] == "SVC-001"
    top = b.finding(b.results[0].finding_key)
    assert top.vulnerability.id == "CVE-2021-44228" and top.signals.kev.listed     # 발췌본 KEV 로 보강됨
    assert res.paths["xlsx"].exists() and "CVE-2022-42889" in res.report_md
