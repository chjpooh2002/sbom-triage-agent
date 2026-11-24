from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from triage.models import Evidence, SourceFileScope
from .store import EvidenceStore, scoped_path

Log = Callable[..., None] | None
Files = Iterable[SourceFileScope]


@dataclass
class Source:
    name: str
    text: str
    lines: list[str]


class Query:
    def __init__(self, root: str | Path, files: Files, store: EvidenceStore | None,
                 stage: str, include_excluded: bool, log: Log):
        self.root = Path(root).resolve()
        self.store = store if store is not None else EvidenceStore.standalone(root)
        if self.root != self.store.root:
            raise ValueError("증거 저장소 루트 불일치")
        self.stage = stage
        self.log = log
        self.evidence: list[Evidence] = []
        # Materialize once since a scope provider can yield rows lazily.
        rows = list(files)
        paths = {Path(f.path).as_posix() for f in rows}
        if not include_excluded:
            paths -= {Path(f.path).as_posix() for f in rows
                      if f.category in {"generated", "vendored_bundle"}}
        self.paths = sorted(paths)
        if log:
            log(stage, "start")

    def sources(self, accept: Callable[[Path], bool]):
        for name in self.paths:
            if not accept(Path(name)):
                continue
            try:
                path = scoped_path(self.root, name)
                if not path.is_file():
                    continue
                text = path.read_text(encoding="utf-8")
            except (OSError, ValueError, RuntimeError):
                continue
            yield Source(name, text, text.splitlines())

    def cite(self, src: Source, start: int, end: int, kind: str = "code") -> str:
        item = self.store.add(self.stage, kind=kind, file=src.name, line_start=start,
                              line_end=end, snippet="\n".join(src.lines[start-1:end])[:600])
        self.evidence.append(item)
        return item.id

    def finish(self, result):
        if self.log:
            self.log(self.stage, "end", evidence_count=len(self.evidence))
        return result, self.evidence
