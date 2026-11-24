"""수집기 공통 자료형과 줄 단위 근거 발급."""
from __future__ import annotations

import json
import os
import re
from bisect import bisect_right
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from triage.ingest.common import component_id, make_purl
from triage.models import Anomaly, Component, Evidence

ANOMALY_EXAMPLE_LIMIT = 3


class CollectResult(NamedTuple):
    components: list[Component]
    evidence: list[Evidence]
    anomalies: list[Anomaly]


@dataclass(eq=False)
class Document:
    file: str
    text: str
    kind: str
    url: str = ""
    lines: list[str] = field(init=False)

    def __post_init__(self):
        self.lines = self.text.splitlines()


class SourceLine(NamedTuple):
    doc: Document
    line: int


class LocatedJSON:
    """검증된 JSON의 키 경로별 값 시작 줄. 같은 이름·값의 중첩 항목도 구분한다."""

    def __init__(self, doc: Document):
        self.data = json.loads(doc.text)
        if not isinstance(self.data, dict):
            raise ValueError("JSON 최상위 객체 필요")
        self.lines = {}
        starts = [m.end() for m in re.finditer("\n", doc.text)]
        lexemes = iter(re.finditer(r'"(?:\\.|[^"\\])*"|[{}\[\],:]|[^\s{}\[\],:"]+', doc.text))

        def visit(token, path):
            self.lines[path] = 1 + bisect_right(starts, token.start())
            symbol = token.group()
            if symbol not in ("{", "["):
                return
            token = next(lexemes)
            index = 0
            while token.group() not in ("}", "]"):
                if symbol == "{":
                    key = json.loads(token.group())
                    next(lexemes)  # colon
                    token = next(lexemes)
                else:
                    key = index
                visit(token, (*path, key))
                index += 1
                token = next(lexemes)
                if token.group() == ",":
                    token = next(lexemes)

        visit(next(lexemes), ())

    def line(self, *path):
        return self.lines[tuple(path)]


def project_files(root):
    ignored = {".git", ".venv", "node_modules", "__pycache__"}
    for folder, dirs, files in os.walk(root):
        base = Path(folder)
        dirs[:] = sorted(d for d in dirs if d not in ignored and safe_file(root, base / d))
        for name in sorted(files):
            path = base / name
            if safe_file(root, path) and path.is_file():
                yield path


def safe_file(root, path):
    try:
        return path.resolve().is_relative_to(root) and not path.is_symlink()
    except (ValueError, RuntimeError, OSError):
        return False


class Collection:
    def __init__(self, root: Path, log: Callable[..., None] | None, *, offline: bool = False):
        self.root = root
        self.log = log
        self.offline = offline
        self.result = CollectResult([], [], [])
        self.locations = {}
        self.components = {}

    def event(self, event, **data):
        if self.log is not None:
            self.log("collect", event, **data)

    def read(self, path, kind):
        if not safe_file(self.root, path):
            raise ValueError("프로젝트 밖 경로")
        return Document(path.relative_to(self.root).as_posix(), path.read_text(encoding="utf-8-sig"), kind)

    def evidence(self, doc, line=1, *, note="", command=""):
        key = (doc.file, doc.url, doc.kind, line, note, command)
        if key not in self.locations:
            batch, index = divmod(len(self.result.evidence), 9999)
            stage = "collect" if batch == 0 else f"collect{batch + 1}"
            eid = f"{stage}-{index + 1:04d}"
            snippet = doc.lines[line - 1][:600] if line and line <= len(doc.lines) else ""
            evidence = Evidence(id=eid, kind=doc.kind, file=doc.file, line_start=line,
                                line_end=line, snippet=snippet, url=doc.url, note=note, command=command)
            self.locations[key] = eid
            self.result.evidence.append(evidence)
        return self.locations[key]

    def reference_ids(self, refs):
        # 대형 BOM에서 실제 선택한 항목의 근거만 결과에 포함한다.
        return list(dict.fromkeys(self.evidence(*r) if isinstance(r, SourceLine) else r for r in refs))

    def anomaly(self, kind, message, *ids):
        self.result.anomalies.append(Anomaly(kind=kind, message=message, evidence_ids=self.reference_ids(ids)))

    def summarize_anomalies(self):
        by_kind = defaultdict(list)
        for anomaly in self.result.anomalies:
            by_kind[anomaly.kind].append(anomaly)

        summary = []
        for kind, rows in by_kind.items():
            if len(rows) == 1:
                summary.append(rows[0])
                continue
            examples = list(dict.fromkeys(row.message for row in rows))[:ANOMALY_EXAMPLE_LIMIT]
            refs = list(dict.fromkeys(ref for row in rows for ref in row.evidence_ids))
            summary.append(Anomaly(kind=kind, message=f"총 {len(rows)}건 · 대표 사례 " + " / ".join(examples),
                                   evidence_ids=refs))
        self.result.anomalies[:] = summary

    def add(self, *, name, ecosystem, version="", group="", location="", evidence_ids, sources, **fields):
        evidence_ids = self.reference_ids(evidence_ids)
        full_name = f"{group}:{name}" if group and ecosystem == "maven" else name
        purl = fields.pop("purl", make_purl(ecosystem, full_name, version))
        if not version:
            purl = purl.removesuffix("@")
        cid = component_id(purl, ecosystem, full_name, version)
        if location:
            cid += "#" + location
        if cid in self.components:
            c = self.components[cid]
            c.evidence_ids = list(dict.fromkeys([*c.evidence_ids, *evidence_ids]))
            c.sources = list(dict.fromkeys([*c.sources, *sources]))
            return c
        c = Component(id=cid, purl=purl, name=name, group=group, ecosystem=ecosystem, version=version,
                      evidence_ids=list(dict.fromkeys(evidence_ids)), sources=list(dict.fromkeys(sources)), **fields)
        self.components[cid] = c
        self.result.components.append(c)
        self.event("component", component_id=cid, evidence_ids=c.evidence_ids)
        return c
