"""Evidence IDs and file-backed verification for a single scan."""
from __future__ import annotations

import re
from collections import Counter
from collections.abc import Iterable
from pathlib import Path
from threading import RLock

from triage.models import Evidence


def scoped_path(root: Path, name: str) -> Path:
    relative = Path(name)
    if not name or relative.anchor or ".." in relative.parts:
        raise ValueError("루트 기준 상대 경로가 필요합니다")
    path = root / relative
    if path.resolve() != path:
        raise ValueError("링크를 통한 파일 접근")
    return path


class EvidenceStore:
    """Share one store across a scan. Merging preserves references from other stages."""

    _standalone_numbers: Counter[str] = Counter()
    _standalone_lock = RLock()

    @classmethod
    def standalone(cls, root: str | Path) -> EvidenceStore:
        """Independent tool calls can later merge their IDs into the scan store."""
        store = cls(root)
        store._numbers = cls._standalone_numbers
        store._lock = cls._standalone_lock
        return store

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self._items: dict[str, Evidence] = {}
        self._numbers: Counter[str] = Counter()
        self._lock = RLock()

    def add(self, stage: str = "evidence", **fields) -> Evidence:
        if not re.fullmatch(r"[\w-]+", stage):
            raise ValueError("잘못된 단계 이름")
        with self._lock:
            number = self._numbers[stage] + 1
            if number > 9999:
                raise ValueError("단계별 증거 ID 소진")
            item = Evidence(id=f"{stage}-{number:04d}", **fields)
            self._items[item.id] = item.model_copy()
            self._numbers[stage] = number
            return item

    def get(self, evidence_id: str) -> Evidence:
        with self._lock:
            return self._items[evidence_id].model_copy()

    def merge(self, items: Iterable[Evidence]) -> None:
        """An identical retry is harmless. A conflict rejects the whole batch."""
        pending: dict[str, Evidence] = {}
        numbers: Counter[str] = Counter()
        with self._lock:
            for item in items:
                match = re.fullmatch(r"([\w-]+)-(\d{4})", item.id)
                if not match:
                    raise ValueError(f"잘못된 증거 ID: {item.id}")
                existing = pending.get(item.id, self._items.get(item.id))
                if existing is not None and existing != item:
                    raise ValueError(f"증거 ID 충돌: {item.id}")
                pending[item.id] = item.model_copy()
                stage, number = match.groups()
                numbers[stage] = max(numbers[stage], int(number))
            self._items.update(pending)
            self._numbers |= numbers

    def verify(self, item: Evidence | str) -> bool:
        """Only an exact canonical excerpt of the cited UTF-8 lines verifies."""
        if isinstance(item, str):
            try:
                item = self.get(item)
            except KeyError:
                return False
        start, end = item.line_start, item.line_end
        if not item.file or start is None or end is None or not 1 <= start <= end:
            return False
        try:
            path = scoped_path(self.root, item.file)
            if not path.is_file():
                return False
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, ValueError, RuntimeError):
            return False
        return end <= len(lines) and item.snippet == "\n".join(lines[start - 1:end])[:600]
