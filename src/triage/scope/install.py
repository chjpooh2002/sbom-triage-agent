"""지원하는 RUN 명령의 인자와 패키지 명세를 정적으로 읽는다."""
from __future__ import annotations

import posixpath
import re
import shlex
from collections.abc import Callable

from .docker import container_path, words


def commands(args: str) -> list[list[str]]:
    if args.startswith("["):
        result = words(args)
        if not result or posixpath.basename(result[0]) in {"sh", "bash", "cmd", "powershell"}:
            raise ValueError("실행 셸은 해석할 수 없음")
        return [result]
    if any(char in args for char in "$`<>;|\n"):
        raise ValueError("셸 확장 또는 분기")
    lexer = shlex.shlex(args, posix=True, punctuation_chars="&")
    lexer.whitespace_split = True
    lexer.commenters = ""
    result: list[list[str]] = [[]]
    for arg in lexer:
        if arg == "&&" and result[-1]:
            result.append([])
        elif arg in {"&", "&&"}:
            raise ValueError("백그라운드 명령")
        else:
            result[-1].append(arg)
    if not result[-1]:
        raise ValueError("빈 명령")
    return result


def options(args: list[str], short: str, long: str) -> list[str]:
    values = []
    for index, arg in enumerate(args):
        if arg in {short, long}:
            if index + 1 < len(args) and not args[index + 1].startswith("-"):
                values.append(args[index + 1])
        elif arg.startswith(long + "="):
            values.append(arg.split("=", 1)[1])
        elif arg.startswith(short) and short != long:
            values.append(arg[len(short):].removeprefix("="))
    return values


def omit_dev(args: list[str]) -> bool:
    omit = options(args, "--omit", "--omit")
    include = options(args, "--include", "--include")
    production = next((arg for arg in reversed(args) if arg in {
        "--production", "--prod", "--only=production", "--only=prod", "--production=true",
        "--production=false", "--no-production", "--no-prod",
    }), "")
    return "dev" not in include and ("dev" in omit or production in {
        "--production", "--prod", "--only=production", "--only=prod", "--production=true",
    })


def normalized_name(value: str) -> str:
    return re.sub(r"[-_.]+", "-", value).lower()


def requirements(start: str, read: Callable, line_evidence: Callable) -> dict[str, list[tuple[str, str]]]:
    result: dict[str, list[tuple[str, str]]] = {}
    visited: set[str] = set()

    def visit(path: str, prior: tuple[str, ...] = ()) -> None:
        if path in visited:
            return
        visited.add(path)
        source = read(path)
        if source is None:
            return
        origin, content, evidence = source
        start_line = 0
        parts: list[str] = []
        for number, raw in enumerate(content.splitlines(), 1):
            if not parts:
                start_line = number
            if raw.endswith("\\"):
                parts.append(raw[:-1])
                continue
            parts.append(raw)
            value = re.split(r"(?:^|\s)#", "".join(parts), maxsplit=1)[0].strip()
            parts.clear()
            if not value:
                continue
            if value.startswith(("-r", "--requirement")):
                includes = options(value.split(), "-r", "--requirement")
                if includes and not any(char in includes[0] for char in (":", "$")):
                    ref = line_evidence(origin, content, start_line, number)
                    visit(container_path(includes[0], posixpath.dirname(path)), (*prior, *evidence, ref))
                continue
            match = re.fullmatch(r"([\w.-]+)(?:\[[\w, .-]+\])?\s*==\s*([\w.!+-]+)(?:\s+--hash=\S+)*", value, re.ASCII)
            if match:
                ref = line_evidence(origin, content, start_line, number)
                name, version = match.groups()
                result.setdefault(normalized_name(name), []).extend(
                    (version, item) for item in dict.fromkeys((*prior, *evidence, ref))
                )

    visit(start)
    return result
