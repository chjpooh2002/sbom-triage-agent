"""발견 건에 KEV·EPSS 신호를 붙인다. 캐시(또는 발췌본) 값을 우선하고, 없을 때만 스캐너 보조값을 쓴다."""
from __future__ import annotations

from typing import Optional

from ..models import KevInfo, TriageBundle
from .cache import IntelSource, load_intel
from .hints import apply_hints


def _cves(ids: list[str]) -> list[str]:
    return [i.upper() for i in ids if i.upper().startswith("CVE-")]


def enrich(bundle: TriageBundle, source: Optional[IntelSource] = None) -> TriageBundle:
    wanted = {c for f in bundle.findings for c in _cves(f.vulnerability.all_ids)}
    src = source or load_intel(wanted)
    kev_label = f"CISA KEV ({src.kev_date or src.kev_origin})"
    epss_label = f"EPSS ({src.epss_date or src.epss_origin})"
    for f in bundle.findings:
        cves = _cves(f.vulnerability.all_ids)
        if src.kev:
            hit = next((src.kev[c] for c in cves if c in src.kev), None)
            if hit:
                f.signals.kev = KevInfo(listed=True, date_added=hit.get("dateAdded", ""), due_date=hit.get("dueDate", ""),
                                        ransomware=(str(hit.get("knownRansomwareCampaignUse", "")).lower() == "known"), source=kev_label)
            elif src.kev_origin == "cache":
                # 전체 목록을 확인했는데 없다 → 스캐너 보조값이 덮어쓰지 않게 출처를 남긴다
                f.signals.kev = KevInfo(listed=False, source=kev_label)
        if src.epss:
            hits = [src.epss[c] for c in cves if c in src.epss]
            if hits:
                e, p = max(hits)
                f.signals.epss, f.signals.epss_percentile = e, p
                f.signals.epss_date, f.signals.epss_source = src.epss_date, epss_label
    n_hint = apply_hints(bundle)
    bundle.meta["intel"] = {
        "kev": {"origin": src.kev_origin or "none", "date": src.kev_date, "records": len(src.kev)},
        "epss": {"origin": src.epss_origin or "none", "date": src.epss_date, "matched": len(src.epss)},
        "hints_used": n_hint, "warnings": src.warnings,
    }
    return bundle
