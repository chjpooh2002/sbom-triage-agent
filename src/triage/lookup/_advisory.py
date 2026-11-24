"""출처별 권고문에서 공통 모델로 전달할 값."""
from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Evidence, Vulnerability


class EvidenceList(list[Evidence]):
    def add(self, kind: str, **fields: str) -> str:
        item = Evidence(id=f"lookup-{len(self) + 1:04d}", kind=kind, **fields)
        self.append(item)
        return item.id


@dataclass
class Advisory:
    vulnerability: Vulnerability
    in_range: bool | None
    source: str
    evidence_id: str


def any_match(matches: list[bool | None]) -> bool | None:
    if True in matches:
        return True
    return False if matches and all(match is False for match in matches) else None


def exact_version(version: str) -> bool:
    return bool(re.fullmatch(r"v?\d[0-9A-Za-z.+!_~-]*", version))
