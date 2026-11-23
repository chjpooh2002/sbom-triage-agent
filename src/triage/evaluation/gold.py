"""정답 사례(gold.csv) 로드·검증과 사례 → 내부 구조 변환.

사례에는 KEV·EPSS·CVSS 값을 고정해 두므로, 외부 데이터가 바뀌어도 채점 결과가 흔들리지 않는다.
"""
from __future__ import annotations

import csv
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from ..ingest.common import component_id, parse_purl
from ..models import AssetContext, Component, Finding, KevInfo, Signals, Status, Tier, Vulnerability

REQUIRED = ["case_id", "vuln_id", "package", "version", "expected_tier", "rationale"]
OPTIONAL = ["ecosystem", "internet_exposed", "criticality", "kev", "epss", "cvss", "severity", "status",
            "has_fix", "direct", "expected_order_group", "source_url", "reviewed"]
YES, NO = {"y", "yes", "true", "1", "예", "o"}, {"n", "no", "false", "0", "아니오", "x"}


class GoldError(ValueError):
    pass


@dataclass
class GoldCase:
    case_id: str
    finding: Finding
    asset: AssetContext
    expected_tier: Tier
    expected_order_group: Optional[int]
    rationale: str
    reviewed: bool
    row: dict = field(default_factory=dict)


def _bool(v: str, name: str, errs: list[str], where: str) -> Optional[bool]:
    s = (v or "").strip().lower()
    if not s:
        return None
    if s in YES:
        return True
    if s in NO:
        return False
    errs.append(f"{where}: {name} 값 '{v}'는 Y/N 이어야 함")
    return None


def _num(v: str, name: str, lo: float, hi: float, errs: list[str], where: str) -> Optional[float]:
    s = (v or "").strip()
    if not s:
        return None
    try:
        x = float(s)
    except ValueError:
        errs.append(f"{where}: {name} 값 '{v}'는 숫자여야 함")
        return None
    if not lo <= x <= hi:
        errs.append(f"{where}: {name} 값 {x}는 {lo}~{hi} 범위여야 함")
    return x


def load_gold(path: str | Path) -> list[GoldCase]:
    p = Path(path)
    with p.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh))
    if not rows:
        raise GoldError(f"{p}: 사례가 없음")
    missing = [c for c in REQUIRED if c not in rows[0]]
    if missing:
        raise GoldError(f"{p}: 필수 열 없음 {missing}")
    errs: list[str] = []
    cases: list[GoldCase] = []
    seen = set()
    for i, r in enumerate(rows, 2):
        r = {k: (v or "").strip() for k, v in r.items() if k}
        where = f"{p.name}:{i}행({r.get('case_id', '?')})"
        for c in REQUIRED:
            if not r.get(c):
                errs.append(f"{where}: {c} 비어 있음")
        if r.get("case_id") in seen:
            errs.append(f"{where}: case_id 중복")
        seen.add(r.get("case_id"))
        tier_s = r.get("expected_tier", "").upper()
        if tier_s not in {"P1", "P2", "P3", "P4"}:
            errs.append(f"{where}: expected_tier '{tier_s}'는 P1~P4 여야 함")
            continue
        status_s = r.get("status", "affected") or "affected"
        if status_s not in {"affected", "not_affected"}:
            errs.append(f"{where}: status '{status_s}'는 affected/not_affected 여야 함")
        crit = _num(r.get("criticality", ""), "criticality", 1, 5, errs, where)
        og = r.get("expected_order_group", "")
        order_group = None
        if og:
            try:
                order_group = int(og)
            except ValueError:
                errs.append(f"{where}: expected_order_group '{og}'는 정수여야 함")
        pkg, ver, eco = r.get("package", ""), r.get("version", ""), r.get("ecosystem", "")
        purl = pkg if pkg.startswith("pkg:") else ""
        pp = parse_purl(purl)
        has_fix = _bool(r.get("has_fix", ""), "has_fix", errs, where)
        comp = Component(id=component_id(purl, eco, pkg, ver), name=pp.get("name") or pkg, group=pp.get("group", ""),
                         version=ver, ecosystem=pp.get("type", eco), purl=purl,
                         direct=_bool(r.get("direct", ""), "direct", errs, where))
        vuln = Vulnerability(id=r.get("vuln_id", ""), cvss_score=_num(r.get("cvss", ""), "cvss", 0, 10, errs, where),
                             severity=(r.get("severity") or "unknown").lower(),
                             fixed_versions=["(수정 버전 있음)"] if has_fix else [])
        epss = _num(r.get("epss", ""), "epss", 0, 1, errs, where)
        asset_id = f"gold-{r.get('case_id')}"
        f = Finding(key=Finding.make_key(vuln.id, comp.id, asset_id), component=comp, vulnerability=vuln,
                    asset_id=asset_id, status=Status(status_s) if status_s in {"affected", "not_affected"} else Status.affected,
                    signals=Signals(kev=KevInfo(listed=bool(_bool(r.get("kev", ""), "kev", errs, where)), source="gold"),
                                    epss=epss, epss_source="gold"))
        asset = AssetContext(asset_id=asset_id, internet_exposed=_bool(r.get("internet_exposed", ""), "internet_exposed", errs, where),
                             criticality=int(crit) if crit is not None else None)
        cases.append(GoldCase(case_id=r["case_id"], finding=f, asset=asset, expected_tier=Tier(tier_s),
                              expected_order_group=order_group, rationale=r.get("rationale", ""),
                              reviewed=(r.get("reviewed", "").lower() in YES), row=r))
    if errs:
        raise GoldError("정답 파일 검증 실패:\n  " + "\n  ".join(errs))
    return cases
