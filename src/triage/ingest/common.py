"""변환기들이 함께 쓰는 정규화 도구: purl, 식별자, 심각도, CVSS."""
from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import unquote

# OSV 생태계 이름 → purl type
ECOSYSTEM_TO_PURL = {
    "maven": "maven", "npm": "npm", "pypi": "pypi", "go": "golang", "crates.io": "cargo",
    "nuget": "nuget", "rubygems": "gem", "packagist": "composer", "pub": "pub", "hex": "hex",
    "debian": "deb", "alpine": "apk", "ubuntu": "deb", "rocky linux": "rpm", "almalinux": "rpm",
}

_CVE = re.compile(r"^CVE-\d{4}-\d+$", re.I)


def normalize_purl(purl: str) -> str:
    """한정자(?...)·하위 경로(#...)를 떼고 type 을 소문자로. 같은 구성요소를 도구 간에 맞추는 기준."""
    if not purl or not purl.startswith("pkg:"):
        return ""
    p = unquote(purl.split("#", 1)[0].split("?", 1)[0])
    head, _, rest = p[4:].partition("/")
    return f"pkg:{head.lower()}/{rest}"


def parse_purl(purl: str) -> dict:
    """pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1 → type, group, name, version"""
    p = normalize_purl(purl)
    if not p:
        return {}
    body = p[4:]
    typ, _, rest = body.partition("/")
    path, _, version = rest.rpartition("@") if "@" in rest else (rest, "", "")
    group, _, name = path.rpartition("/")
    return {"type": typ, "group": group, "name": name, "version": version}


def make_purl(ecosystem: str, name: str, version: str) -> str:
    typ = ECOSYSTEM_TO_PURL.get((ecosystem or "").lower())
    if not typ or not name:
        return ""
    if typ == "maven" and ":" in name:
        g, a = name.split(":", 1)
        return f"pkg:maven/{g}/{a}@{version}" if version else f"pkg:maven/{g}/{a}"
    if typ == "npm" and name.startswith("@"):
        scope, _, n = name.partition("/")
        return f"pkg:npm/{scope.replace('@', '%40')}/{n}@{version}"
    return f"pkg:{typ}/{name}@{version}" if version else f"pkg:{typ}/{name}"


def component_id(purl: str, ecosystem: str = "", name: str = "", version: str = "") -> str:
    return normalize_purl(purl) or f"{(ecosystem or 'unknown').lower()}:{name}@{version}"


def pick_primary_id(ids: Iterable[str]) -> tuple[str, list[str]]:
    """CVE 를 대표 식별자로, 나머지는 별칭. 순서는 입력 순서를 유지해 결정적으로."""
    uniq = [i.strip() for i in dict.fromkeys(i for i in ids if i and i.strip())]
    cves = [i.upper() for i in uniq if _CVE.match(i)]
    primary = cves[0] if cves else (uniq[0] if uniq else "UNKNOWN")
    aliases = [i.upper() if _CVE.match(i) else i for i in uniq]
    return primary, [a for a in dict.fromkeys(aliases) if a != primary]


SEVERITY_MAP = {"critical": "critical", "high": "high", "important": "high", "medium": "medium",
                "moderate": "medium", "low": "low", "negligible": "low", "minimal": "low"}


def normalize_severity(s: Optional[str]) -> str:
    return SEVERITY_MAP.get((s or "").strip().lower(), "unknown")


def score_from_vector(vector: str) -> Optional[float]:
    """CVSS 벡터 → 기본 점수. v4·v3·v2 지원(cvss 라이브러리). 실패하면 None."""
    if not vector:
        return None
    try:
        if vector.startswith("CVSS:4"):
            from cvss import CVSS4
            return float(CVSS4(vector).base_score)
        if vector.startswith("CVSS:3"):
            from cvss import CVSS3
            return float(CVSS3(vector).base_score)
        from cvss import CVSS2
        return float(CVSS2(vector).base_score)
    except Exception:
        return None


def to_float(v) -> Optional[float]:
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def split_versions(s: str) -> list[str]:
    """'2.15.0, 2.12.2' 같은 문자열을 목록으로."""
    return [x.strip() for x in re.split(r"[,\s]+", s or "") if x.strip()]
