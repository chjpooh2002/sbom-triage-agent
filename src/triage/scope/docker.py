"""Docker 빌드 명령과 빌드 컨텍스트의 경로 해석."""
from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import PurePosixPath
from typing import Iterator


@dataclass(frozen=True)
class Line:
    start: int
    end: int
    snippet: str


@dataclass(frozen=True)
class Instruction:
    op: str
    args: str
    line: Line


def instructions(text: str) -> Iterator[Instruction]:
    raw = text.splitlines()
    escape = "\\"
    for value in raw:
        if not value.strip().startswith("#"):
            break
        match = re.fullmatch(r"\s*#\s*escape\s*=\s*([`\\])\s*", value, re.I)
        if match:
            escape = match[1]
    start = 0
    parts: list[str] = []
    heredocs: list[str] = []
    for number, value in enumerate(raw, 1):
        if heredocs:
            if value.lstrip("\t") == heredocs[0]:
                heredocs.pop(0)
            continue
        trimmed = value.strip()
        if not trimmed or trimmed.startswith("#"):
            continue
        if not parts:
            start = number
        if trimmed.endswith(escape):
            parts.append(value.rstrip()[:-1])
            continue
        parts.append(value)
        command = "".join(parts).strip().split(None, 1)
        parts.clear()
        args = command[1] if len(command) == 2 else ""
        heredocs = re.findall(r"(?:^|\s)<<-?['\"]?([\w.-]+)", args)
        yield Instruction(command[0].upper(), args, Line(start, number, "\n".join(raw[start - 1:number])[:600]))


def words(args: str) -> list[str]:
    if args.startswith("["):
        value = json.loads(args)
        if isinstance(value, list) and all(isinstance(item, str) for item in value):
            return value
        raise ValueError("문자열 배열 필요")
    return shlex.split(args)


def container_path(value: str, cwd: str = "/") -> str:
    return posixpath.normpath("/" + posixpath.join(cwd, value).lstrip("/"))


def within(path: str, parent: str) -> bool:
    return path == parent or path.startswith(parent.rstrip("/") + "/")


def _glob(pattern: str, double_star: bool) -> re.Pattern[str]:
    """Docker 패턴에서 단일 별표와 물음표는 경로 구분자를 넘지 않는다."""
    chunks = re.split(r"(\*\*/|\*\*|\*|\?|\[[^\]]+\])", pattern)
    regex = []
    for chunk in chunks:
        if chunk in {"**/", "**"} and double_star:
            regex.append("(?:.*/)?" if chunk.endswith("/") else ".*")
        elif chunk in {"**/", "**", "*"}:
            regex.append("[^/]*" + ("/" if chunk.endswith("/") else ""))
        elif chunk == "?":
            regex.append("[^/]")
        elif chunk.startswith("[") and chunk.endswith("]"):
            regex.append("(?!/)" + fnmatch.translate(chunk))
        else:
            regex.append(re.escape(chunk))
    # fnmatch는 패턴 끝을 고정하므로 문자 클래스 해석에만 쓴다.
    return re.compile("".join(regex).replace(r")\Z", ")"))


def matches(paths: dict[str, object], source: str) -> Iterator[tuple[str, str]]:
    """(원본 기준점, 파일 경로). 기준점이 디렉터리면 내용만 복사한다."""
    pattern = _glob(source, double_star=False)
    for path in paths:
        for candidate in (path, *(str(parent) for parent in PurePosixPath(path).parents)):
            if pattern.fullmatch(candidate):
                yield candidate, path
                break


@dataclass(frozen=True)
class IgnoreRule:
    pattern: re.Pattern[str]
    include: bool
    line: Line


def ignore_rules(text: str) -> list[IgnoreRule]:
    rules = []
    for index, raw in enumerate(text.splitlines(), 1):
        value = raw.strip()
        if not value or raw.startswith("#"):
            continue
        include = value.startswith("!")
        pattern = posixpath.normpath(value.removeprefix("!").strip()).strip("/")
        if pattern and pattern != ".":
            rules.append(IgnoreRule(_glob(pattern, double_star=True), include, Line(index, index, raw[:600])))
    return rules


def ignored(path: str, rules: list[IgnoreRule]) -> Line | None:
    candidates = [path, *(str(parent) for parent in PurePosixPath(path).parents)]
    result = None
    for rule in rules:
        if any(rule.pattern.fullmatch(candidate) for candidate in candidates):
            result = None if rule.include else rule.line
    return result
