"""스캐너가 함께 준 보조 지표(grype 의 KEV·EPSS 등)를 신호로 옮긴다. 캐시 값이 이미 있으면 덮어쓰지 않는다."""
from __future__ import annotations

from ..models import KevInfo, TriageBundle


def apply_hints(bundle: TriageBundle) -> int:
    n = 0
    for f in bundle.findings:
        k = f.hints.get("kev")
        if k and not f.signals.kev.listed and not f.signals.kev.source:
            f.signals.kev = KevInfo(listed=True, date_added=k.get("date_added", ""), due_date=k.get("due_date", ""),
                                    ransomware=k.get("ransomware"), source="스캐너 보조값(grype)")
            n += 1
        e = f.hints.get("epss")
        if e and f.signals.epss is None and e.get("epss") is not None:
            f.signals.epss = float(e["epss"])
            f.signals.epss_percentile = float(e["percentile"]) if e.get("percentile") is not None else None
            f.signals.epss_date = e.get("date", "")
            f.signals.epss_source = "스캐너 보조값(grype)"
            n += 1
    return n
