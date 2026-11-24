"""주석 줄 판별과 인용문 위치 찾기. 증거 표시(workspace)와 검증기(verify)가 함께 쓴다.

주석·문서는 단서일 뿐 근거가 아니므로, 인용이 주석 부분에만 걸리는지 결정적으로 가려낸다.
"""
from __future__ import annotations

import re
from pathlib import PurePosixPath

_HASH = {".py", ".yml", ".yaml", ".sh", ".bash", ".properties", ".conf", ".toml", ".cfg", ".ini", ".rb",
         ".pl", ".r", ".env", ".dockerignore", ".gitignore", ".example"}
_SLASH = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".java", ".kt", ".kts", ".go", ".c", ".h", ".cpp",
          ".cc", ".cs", ".scala", ".groovy", ".gradle", ".swift", ".rs", ".php", ".dart"}
_MARKUP = {".xml", ".html", ".htm", ".xhtml", ".vue", ".svg", ".pom"}
_DOC = {".md", ".rst", ".adoc", ".txt"}
_PREFIX = re.compile(r"^\s*\d+\s*>?\s*\|\s?")


def style(path: str) -> str:
    p = PurePosixPath(path)
    name, suffix = p.name.lower(), p.suffix.lower()
    if name.startswith("dockerfile") or name.endswith(".dockerfile") or name.startswith(".env"):
        return "hash"
    if suffix == ".txt" and name.startswith(("requirements", "constraints")):
        return "hash"
    if suffix in _DOC:
        return "doc"
    if suffix in _HASH:
        return "hash"
    if suffix in _SLASH:
        return "slash"
    if suffix in _MARKUP:
        return "markup"
    return "code"


def _inline(line: str, marker: str) -> int | None:
    """따옴표 밖에서 marker 가 처음 나오는 열."""
    quote = ""
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = ""
        elif ch in "\"'`":
            quote = ch
        elif line.startswith(marker, i):
            return i
        i += 1
    return None


def comment_starts(path: str, lines: list[str]) -> list[int | None]:
    """줄마다 주석이 시작하는 열. 0 이면 줄 전체가 주석(또는 문서), None 이면 주석 없음."""
    kind = style(path)
    out: list[int | None] = []
    block_end = ""
    suffix = PurePosixPath(path).suffix.lower()
    for line in lines:
        s = line.strip()
        if block_end:
            out.append(0)
            if block_end in s:
                block_end = ""
            continue
        if kind == "doc":
            out.append(0 if s else None)
            continue
        if not s:
            out.append(None)
            continue
        if kind == "slash":
            if s.startswith(("//", "/*", "*")):
                out.append(0)
                if s.startswith("/*") and "*/" not in s[2:]:
                    block_end = "*/"
                continue
            out.append(_inline(line, "//"))
        elif kind == "hash":
            if s.startswith("#") or (suffix == ".properties" and s.startswith("!")):
                out.append(0)
                continue
            if suffix == ".py" and s[:3] in ('"""', "'''"):
                out.append(0)
                if s.count(s[:3]) == 1:
                    block_end = s[:3]
                continue
            out.append(_inline(line, "#"))
        elif kind == "markup":
            if s.startswith("<!--"):
                out.append(0)
                if "-->" not in s[4:]:
                    block_end = "-->"
                continue
            out.append(None)
        else:
            out.append(None)
    return out


def comment_text(path: str, lines: list[str]) -> list[str]:
    """줄마다 주석 부분 문자열(없으면 빈 문자열)."""
    starts = comment_starts(path, lines)
    return ["" if s is None else line[s:] for line, s in zip(lines, starts)]


def _norm(text: str) -> str:
    return re.sub(r"\s+", " ", text).strip()


def quote_lines(quote: str) -> list[str]:
    """모델이 붙인 줄 번호·구분자를 떼고, 빈 줄을 버린다."""
    return [n for n in (_norm(_PREFIX.sub("", line)) for line in quote.splitlines()) if n]


def locate(quote: str, snippet: str) -> list[list[tuple[int, int]]] | None:
    """인용 줄마다 원문에서 찾은 (줄 위치, 열) 목록. 하나라도 못 찾으면 None."""
    lines = snippet.split("\n")
    wanted = quote_lines(quote)
    if not wanted:
        return None
    found = []
    for q in wanted:
        hits = []
        for i, line in enumerate(lines):
            n = _norm(line)
            col = n.find(q)
            if col >= 0:
                hits.append((i, col))
        if not hits:
            return None
        found.append(hits)
    return found


def quote_in_comment(path: str, quote: str, snippet: str) -> bool | None:
    """인용이 원문의 주석 부분에만 걸리면 True. 인용을 못 찾으면 None."""
    found = locate(quote, snippet)
    if found is None:
        return None
    lines = snippet.split("\n")
    starts = comment_starts(path, lines)
    for hits in found:
        for i, col in hits:
            start = starts[i]
            if start is None:
                return False
            # 정규화된 줄에서 코드 부분 길이보다 앞에서 시작하면 코드에 걸친 인용
            if start != 0 and col < len(_norm(lines[i][:start])):
                return False
    return True
