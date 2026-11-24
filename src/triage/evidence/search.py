from __future__ import annotations

import ast
import re
from pathlib import Path

from .lexer import Tokens
from .source import Files, Log, Query, Source
from .store import EvidenceStore


def search_symbol(root, files: Files, symbol: str, *, store: EvidenceStore | None = None,
                  include_excluded: bool = False, log: Log = None):
    """Return up to eight literal, identifier-bounded hits with three lines of context."""
    q = Query(root, files, store, "search", include_excluded, log)
    hits = []
    if symbol.strip():
        pattern = re.compile(r"(?<!\w)" + re.escape(symbol) + r"(?!\w)")
        for src in q.sources(lambda _: True):
            for line, text in enumerate(src.lines, 1):
                if pattern.search(text):
                    eid = q.cite(src, max(1, line - 3), min(len(src.lines), line + 3))
                    hits.append(dict(file=src.name, line=line, evidence_ids=[eid]))
                    if len(hits) == 8:
                        return q.finish(hits)
    return q.finish(hits)


def read_lines(root, files: Files, path: str, start: int = 1, end: int | None = None, *,
               store: EvidenceStore | None = None, include_excluded: bool = False, log: Log = None):
    """Read an inclusive 1-based range within the supplied scope."""
    q = Query(root, files, store, "read", include_excluded, log)
    if start < 1 or (end is not None and end < start):
        raise ValueError("잘못된 줄 범위")
    for src in q.sources(lambda p: p == Path(path)):
        last = min(len(src.lines), start + 59, end if end is not None else start + 59)
        if last >= start:
            eid = q.cite(src, start, last)
            return q.finish(dict(file=src.name, line_start=start, line_end=last,
                                 lines=src.lines[start-1:last], evidence_ids=[eid]))
    return q.finish(dict(file=path, lines=[], evidence_ids=[]))


JS = {".js", ".jsx", ".ts", ".tsx", ".cjs", ".mjs"}


def imports(src: Source):
    suffix = Path(src.name).suffix
    if suffix == ".py":
        try:
            tree = ast.parse(src.text)
        except (SyntaxError, ValueError, RecursionError):
            return
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    yield alias.name.split(".")[0], node.lineno, node.end_lineno
            elif isinstance(node, ast.ImportFrom) and not node.level and node.module:
                yield node.module.split(".")[0], node.lineno, node.end_lineno
        return
    t = Tokens(src.text)
    for i, word in enumerate(t.words):
        if suffix == ".java" and word == "import":
            j = i + 1 + (t.at(i+1) == "static")
            parts = []
            while t.at(j) and (t.at(j).isidentifier() or t.at(j) in {".", "*"}):
                parts.append(t.at(j))
                j += 1
            if parts and t.at(j) == ";":
                # Java source exposes the imported namespace, not Maven coordinates.
                tail = 2 if t.at(i+1) == "static" else 1
                package = ".".join("".join(parts).split(".")[:-tail])
                if package:
                    yield package, t.lines[i], t.lines[j]
        elif suffix in JS and word in {"import", "require"} and t.at(i-1) != ".":
            j = i + 1
            if t.at(j) == "(":
                j += 1
                if t.at(j+1) != ")":
                    continue
            elif word == "require":
                continue
            elif not t.quoted(j):
                while t.at(j) and t.at(j) not in {"from", ";", "import", "(", "="}:
                    j += 1
                if t.at(j) != "from":
                    continue
                j += 1
            if t.quoted(j):
                spec = t.at(j)[1:-1]
                if spec and not spec.startswith((".", "/", "#")):
                    parts = spec.split("/")
                    yield "/".join(parts[:2 if spec.startswith("@") else 1]), t.lines[i], t.lines[j]


def build_import_graph(root, files: Files, *, store: EvidenceStore | None = None,
                       include_excluded: bool = False, log: Log = None):
    """Map each package/Java namespace to usage paths and their evidence IDs."""
    q = Query(root, files, store, "imports", include_excluded, log)
    graph: dict[str, dict[str, list[str]]] = {}
    for src in q.sources(lambda p: p.suffix in JS | {".java", ".py"}):
        for name, start, end in imports(src):
            graph.setdefault(name, {}).setdefault(src.name, []).append(q.cite(src, start, end))
    return q.finish(graph)
