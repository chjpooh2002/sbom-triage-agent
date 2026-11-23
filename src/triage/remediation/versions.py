"""생태계별 버전 비교와 영향 범위 판정. univers 를 쓰고, 해석이 안 되는 문자열은 숫자 조각 비교로 대신한다."""
from __future__ import annotations

import re
from functools import total_ordering

from univers import versions as uv

_CLASS = {"maven": uv.MavenVersion, "pypi": uv.PypiVersion, "npm": uv.SemverVersion, "golang": uv.GolangVersion,
          "cargo": uv.SemverVersion, "nuget": uv.NugetVersion, "gem": uv.RubygemsVersion,
          "composer": uv.ComposerVersion, "deb": uv.DebianVersion, "rpm": uv.RpmVersion}

PRERELEASE = re.compile(r"(?i)(alpha|beta|rc|cr|milestone|snapshot|preview|dev|[-.]m\d+|[-.]a\d+|[-.]b\d+)")


@total_ordering
class _Loose:
    def __init__(self, s: str):
        self.s = s
        self.key = tuple(int(x) if x.isdigit() else -1 for x in re.findall(r"\d+|[a-zA-Z]+", s))

    def __eq__(self, o):
        return self.key == o.key

    def __lt__(self, o):
        return self.key < o.key


def V(version: str, ecosystem: str = ""):
    cls = _CLASS.get((ecosystem or "").lower())
    v = version.strip().lstrip("v") if ecosystem in ("npm", "golang", "cargo") else version.strip()
    if cls:
        try:
            return cls(v)
        except Exception:
            pass
    return _Loose(v)


def cmp(a: str, b: str, eco: str = "") -> int:
    x, y = V(a, eco), V(b, eco)
    try:
        return (x > y) - (x < y)
    except TypeError:  # 클래스가 섞이면 느슨한 비교
        x, y = _Loose(a), _Loose(b)
        return (x > y) - (x < y)


def is_prerelease(v: str) -> bool:
    return bool(PRERELEASE.search(v))


def variant(v: str) -> str:
    """숫자 버전 뒤의 변형 접미사: 33.3.1-jre → '-jre', 5.3.17.RELEASE → '.release'. 정식/사전 배포 표시는 제외."""
    m = re.match(r"v?[\d.]+(.*)$", v.strip())
    suf = (m.group(1) if m else "").lower()
    return "" if not suf or PRERELEASE.search(suf) else suf


def major(v: str) -> str:
    m = re.match(r"v?(\d+)", v.strip())
    return m.group(1) if m else ""


_CLAUSE = re.compile(r"\s*(>=|<=|>|<|==|=|!=)?\s*([^\s,<>=!]+)\s*")


def in_range(version: str, expr: str, eco: str = "") -> bool:
    """'>=2.13.0,<2.15.0' 또는 '<2.3.1 || >=2.4.0,<2.12.2' 형태. 모르는 형식이면 False(영향 없음으로 보지 않도록 호출측이 처리)."""
    for alt in expr.split("||"):
        ok = True
        clauses = [c for c in re.split(r",|\s+(?=[<>=!])", alt) if c.strip()]
        if not clauses:
            continue
        for c in clauses:
            m = _CLAUSE.fullmatch(c)
            if not m:
                ok = False
                break
            op, ver = m.group(1) or "==", m.group(2)
            r = cmp(version, ver, eco)
            ok = {">=": r >= 0, "<=": r <= 0, ">": r > 0, "<": r < 0, "==": r == 0, "=": r == 0, "!=": r != 0}[op]
            if not ok:
                break
        if ok:
            return True
    return False


def fix_for_line(installed: str, fixed: list[str], eco: str = "") -> str | None:
    """설치 버전보다 큰 수정 버전 중 가장 작은 것(그 버전대의 수정 버전)."""
    higher = [f for f in fixed if cmp(f, installed, eco) > 0]
    return min(higher, key=lambda f: V(f, eco)) if higher else None


def is_affected(version: str, installed: str, affected_ranges: list[str], fixed: list[str], eco: str = "") -> bool:
    """version 이 이 취약점의 영향을 받는가. 범위 정보가 있으면 범위로, 없으면 수정 버전으로 판단."""
    if affected_ranges:
        return any(in_range(version, r, eco) for r in affected_ranges)
    line_fix = fix_for_line(installed, fixed, eco)
    if line_fix is None:
        return True                       # 수정 버전이 없으면 어떤 버전도 안전하다고 단정할 수 없다
    return cmp(version, line_fix, eco) < 0
