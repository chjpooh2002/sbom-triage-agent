"""Resolve literal configuration with source marks. Never consult the host environment."""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import Path

import yaml

from .source import Files, Log, Query, Source
from .store import EvidenceStore


@dataclass
class Setting:
    src: Source
    value: str
    first: int
    last: int
    context: str = ""


def yaml_value(src, node, key):
    if not isinstance(node, yaml.MappingNode):
        return None
    found = None
    for name, child in node.value:
        if not isinstance(name, yaml.ScalarNode):
            continue
        if name.value == key:
            if isinstance(child, yaml.ScalarNode):
                value = child.value
            elif isinstance(child, yaml.SequenceNode) and all(
                    isinstance(n, yaml.ScalarNode) for n in child.value):
                value = ",".join(n.value for n in child.value)
            else:
                continue
            first = name.start_mark.line + 1
            last = child.end_mark.line + int(child.end_mark.column > 0)
            found = Setting(src, value, first, max(first, last))
        elif name.value and key.startswith(name.value + "."):
            nested = yaml_value(src, child, key[len(name.value)+1:])
            if nested:
                found = nested
    return found


ACTIVE = "spring.profiles.active"
ON_PROFILE = "spring.config.activate.on-profile"
SPRING = re.compile(r"application(?:-(.+))?\.(properties|ya?ml)$")


def documents(src, keys):
    """Yield just the requested keys from each logical document."""
    path = Path(src.name)
    if path.suffix == ".properties" or path.name == ".env.example":
        props = {}
        env = path.name == ".env.example"
        lines = iter(enumerate(src.lines, 1))
        for first, line in lines:
            if line.strip() in {"#---", "!---"} and not env:
                yield props
                props = {}
            if not line.strip() or line.lstrip().startswith(("#", "!")):
                continue
            last = first
            while not env and (len(line) - len(line.rstrip("\\"))) % 2:
                last, tail = next(lines, (last, ""))
                line = line[:-1] + tail.lstrip()
            if env:
                m = re.match(r"\s*(?:export\s+)?([\w.\-]+)\s*=\s*(.*)", line)
            else:
                m = re.match(r"\s*([^\s=:]+)(?:\s*[=:]\s*|\s+)(.*)", line)
            if m and m[1] in keys:
                value = m[2].strip()
                if env:
                    quoted = re.fullmatch(r"""("[^"]*"|'[^']*')(?:\s*#.*)?""", value)
                    value = quoted[1][1:-1] if quoted else re.split(r"\s+#", value)[0]
                props[m[1]] = Setting(src, value, first, last)
        yield props
    else:
        if path.suffix == ".json":
            json.loads(src.text)
        for node in yaml.compose_all(src.text, Loader=yaml.BaseLoader):
            yield {k: setting for k in keys if (setting := yaml_value(src, node, k))}


_NGINX_TOKEN = re.compile(r'''\#[^\n]*|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[{};]|[^\s{};#"']+''')


def nginx_settings(src, key):
    stack = []
    servers = []
    settings = defaultdict(list)
    statement = []
    line = 1
    previous = 0
    for match in _NGINX_TOKEN.finditer(src.text):
        line += src.text.count("\n", previous, match.start())
        previous = match.start()
        token = match[0]
        if token.startswith("#"):
            continue
        if token == "{":
            stack.append(" ".join(statement) + f" @{first}" if statement else "{}")
            if statement == ["server"]:
                servers.append(tuple(stack))
        elif token == "}":
            if stack:
                stack.pop()
        elif token == ";":
            if statement:
                directive, *args = statement
                value = None
                if directive == key and args:
                    if key != "http2" or args in (["on"], ["off"]):
                        value = " ".join(args)
                elif key == "http2" and directive == "listen" and "http2" in args:
                    value = "on"
                if value is not None:
                    settings[tuple(stack)].append(Setting(src, value, first, line, " / ".join(stack)))
        else:
            if not statement:
                first = line
            statement.append(token)
            continue
        statement = []
    if key == "http2" and servers:
        for server in servers:
            for depth in range(len(server), -1, -1):
                inherited = settings.get(server[:depth])
                if inherited:
                    for item in inherited:
                        yield replace(item, context=" / ".join(server))
                    break
    else:
        for items in settings.values():
            yield from items


def profile_list(value):
    if value is None:
        return None
    values = value.split(",") if isinstance(value, str) else value
    names = [s.strip() for s in values if s.strip()]
    return names if all(re.fullmatch(r"[\w.\-]+", s) for s in names) else None


def resolve_config(root, files: Files, key: str, *, active_profiles=None,
                   store: EvidenceStore | None = None, include_excluded: bool = False,
                   log: Log = None):
    """Return status, textual value, candidate locations, reasons and evidence.

    None means the active profiles must be inferred. [] explicitly selects base files.
    Spring precedence is evaluated separately in each directory.
    """
    q = Query(root, files, store, "config", include_excluded, log)
    spring = defaultdict(list)
    selected = []
    uncertain = []
    reasons = []
    profile_state = {}
    profile_ids = []
    directive = key.removeprefix("nginx.")
    for src in q.sources(lambda p: p.suffix in {".yml", ".yaml", ".json", ".properties", ".conf"}
                         or p.name in {".env.example", "nginx.conf"}):
        path = Path(src.name)
        if path.suffix == ".conf":
            if directive in {"http2", "proxy_pass", "listen", "resolver"}:
                selected.extend(nginx_settings(src, directive))
            continue
        match = SPRING.fullmatch(path.name)
        try:
            for doc in documents(src, {key, ACTIVE, ON_PROFILE}):
                if match:
                    spring[path.parent.as_posix()].append(
                        (match[1], path.suffix == ".properties", doc))
                elif key in doc:
                    selected.append(doc[key])
        except (ValueError, yaml.YAMLError, RecursionError):
            if match:
                # A malformed inactive profile must not override valid base settings.
                spring[path.parent.as_posix()].append(
                    (match[1], path.suffix == ".properties", None))
            else:
                reasons.append(f"설정 구문 분석 실패: {src.name}")

    for directory, entries in spring.items():
        declarations = [(priority, doc[ACTIVE]) for profile, priority, doc in entries
                        if not profile and doc and ON_PROFILE not in doc and ACTIVE in doc]
        declarations.sort(key=lambda pair: pair[0])
        profiles = profile_list(active_profiles)
        if active_profiles is None and declarations:
            declaration = declarations[-1][1]
            profiles = profile_list(declaration.value)
            profile_ids.append(q.cite(declaration.src, declaration.first, declaration.last, "config"))
        profile_state[directory] = profiles
        candidates = []
        for profile, priority, doc in entries:
            if profile and profiles is not None and profile not in profiles:
                continue
            if doc is None:
                reasons.append(f"Spring 설정 구문 분석 실패: {directory}")
                continue
            if key not in doc:
                continue
            item = doc[key]
            condition = doc.get(ON_PROFILE)
            if condition:
                profile_ids.append(q.cite(condition.src, condition.first, condition.last, "config"))
            names = profile_list(condition.value) if condition else []
            if ((profile or condition) and profiles is None) or names is None:
                uncertain.append(item)
                reasons.append(f"활성 프로파일 또는 활성 조건 불명: {directory}")
                continue
            if condition and not set(names).intersection(profiles or []):
                continue
            rank = profiles.index(profile) + 1 if profile else 0
            candidates.append((rank, priority, item))
        if candidates:
            candidates.sort(key=lambda row: row[:2])
            selected.append(candidates[-1][2])

    matches = []
    for item in selected + uncertain:
        eid = q.cite(item.src, item.first, item.last, "config")
        matches.append(dict(value=item.value, file=item.src.name, context=item.context,
                            evidence_ids=[eid]))
    values = {s.value for s in selected}
    if len(values) > 1:
        reasons.append("설정 위치에 따라 값이 다름")
    if any("${" in value for value in values):
        reasons.append("설정에 미해석 변수가 있음")
    if not matches and not reasons:
        reasons.append("범위에서 설정을 찾지 못함")
    known = len(values) == 1 and not reasons
    return q.finish(dict(status="resolved" if known else "unknown",
                         value=next(iter(values)) if known else None,
                         active_profiles=profile_state, matches=matches,
                         reasons=list(dict.fromkeys(reasons)),
                         evidence_ids=profile_ids + [m["evidence_ids"][0] for m in matches]))
