"""File-local call arguments. A positive trace carries both source and call evidence."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .search import JS
from .source import Files, Log, Query
from .store import EvidenceStore
from .lexer import Tokens


@dataclass(frozen=True)
class Origin:
    request: bool
    lines: tuple[int, ...]


Trace = Origin | None


def assigned(origin: Trace, line: int) -> Trace:
    return Origin(origin.request, (*origin.lines, line)) if origin is not None else None


def combine(traces) -> Trace:
    traces = list(traces)
    request = [t for t in traces if t is not None and t.request]
    if request:
        return Origin(True, tuple(line for t in request for line in t.lines))
    if any(t is None for t in traces):
        return None
    return Origin(False, tuple(line for t in traces for line in t.lines))


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return f"{dotted(node.value)}.{node.attr}"
    return ""


def local_nodes(node):
    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.ClassDef)):
        return
    yield node
    for child in ast.iter_child_nodes(node):
        yield from local_nodes(child)


def python_calls(src, symbol):
    try:
        tree = ast.parse(src.text)
    except (SyntaxError, ValueError, RecursionError):
        return
    request_names = set()
    route_objects = {"app", "bp", "blueprint"}
    constructors = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.ImportFrom) and n.module == "flask":
            request_names.update(a.asname or a.name for a in n.names if a.name == "request")
            constructors.update(a.asname or a.name for a in n.names if a.name in {"Flask", "Blueprint"})
        if isinstance(n, ast.Import):
            request_names.update(f"{a.asname or a.name}.request" for a in n.names if a.name == "flask")
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and isinstance(n.value, ast.Call):
            if dotted(n.value.func) in constructors | {"flask.Flask", "flask.Blueprint"}:
                route_objects.update(a.id for a in n.targets if isinstance(a, ast.Name))
    for fn in ast.walk(tree):
        if not isinstance(fn, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        route = next((d for d in fn.decorator_list if isinstance(d, ast.Call)
                      and isinstance(d.func, ast.Attribute)
                      and d.func.attr in {"route", "get", "post", "put", "patch", "delete"}
                      and (d.func.attr == "route" or dotted(d.func.value) in route_objects)
                      and d.args and isinstance(d.args[0], ast.Constant)
                      and isinstance(d.args[0].value, str)), None)
        values: dict[str, Trace] = {}
        for arg in (*fn.args.posonlyargs, *fn.args.args, *fn.args.kwonlyargs):
            values[arg.arg] = None
        if route:
            for name in re.findall(r"<(?:[^:>]+:)?(\w+)>", route.args[0].value):
                values[name] = Origin(True, (route.lineno,))

        def trace(n):
            if isinstance(n, ast.Constant):
                return Origin(False, (n.lineno,))
            if isinstance(n, ast.Name):
                return values.get(n.id)
            if isinstance(n, ast.Subscript):
                return trace(n.value)
            if isinstance(n, ast.BinOp):
                return combine((trace(n.left), trace(n.right)))
            if isinstance(n, ast.Call):
                if isinstance(n.func, ast.Attribute) and n.func.attr == "get" and not any(
                        k.arg == "default" for k in n.keywords) and len(n.args) == 1:
                    return trace(n.func.value)
                if dotted(n.func).split(".")[-1] not in {"get_json", "get_data"}:
                    return None
                n = n.func
            if isinstance(n, ast.Attribute):
                parts = dotted(n.value)
                if (route and parts in request_names
                        and parts.split(".")[0] not in values and n.attr in {
                            "args", "form", "values", "json", "data", "files", "headers",
                            "cookies", "get_json", "get_data", "view_args"}):
                    return Origin(True, (n.lineno,))
            return None

        def visit(statements):
            for stmt in statements:
                if isinstance(stmt, ast.If):
                    yield from visit([ast.Expr(value=stmt.test)])
                    original = values.copy()
                    yield from visit(stmt.body)
                    positive = values.copy()
                    values.clear()
                    values.update(original)
                    yield from visit(stmt.orelse)
                    for name in set(positive) | set(values):
                        if positive.get(name) != values.get(name):
                            values[name] = None
                    continue
                nodes = list(local_nodes(stmt))
                simple = isinstance(stmt, (ast.Expr, ast.Return, ast.Assign, ast.AnnAssign))
                for call in (n for n in nodes if isinstance(n, ast.Call)):
                    name = dotted(call.func)
                    if name != symbol and ("." in symbol or name.split(".")[-1] != symbol):
                        continue
                    args = [*call.args, *(kw.value for kw in call.keywords)]
                    flow = combine(trace(a) for a in args) if simple else None
                    yield (fn.name, "flask" if route else None, flow,
                           route.lineno if route else fn.lineno, call.lineno, call.end_lineno)
                if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value:
                    observed = trace(stmt.value)
                    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
                    for target in targets:
                        if isinstance(target, ast.Name):
                            values[target.id] = assigned(observed, stmt.lineno)
                        else:
                            for n in ast.walk(target):
                                if isinstance(n, ast.Name):
                                    values[n.id] = None
                else:
                    for n in nodes:
                        if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                            values[n.id] = None
        yield from visit(fn.body)


@dataclass
class Handler:
    name: str
    framework: str
    route: int
    body: int
    end: int
    params: dict[str, Trace]
    request: str = ""
    request_line: int | None = None


def js_function(t, start, limit=None):
    """Read an inline or named callback, including a concise arrow expression."""
    i = start + (t.at(start) == "async")
    name = ""
    if t.at(i) == "function":
        i += 1
        if t.at(i).isidentifier():
            name = t.at(i)
            i += 1
    if t.at(i) == "(" and i in t.pairs:
        req = t.at(i+1)
        i = t.pairs[i] + 1
    elif t.at(i).isidentifier() and t.at(i+1) == "=>":
        req = t.at(i)
        i += 1
    else:
        return None
    if t.at(i) == "=>":
        i += 1
        if t.at(i) != "{" and limit is not None and i < limit:
            return name, req, i-1, limit
    if t.at(i) == "{" and i in t.pairs:
        return name, req, i, t.pairs[i]
    return None


def js_handlers(t):
    named = {}
    routers = {"app", "router"}
    for i, word in enumerate(t.words):
        if word == "=" and (t.words[i+1:i+3] in (["express", "("], ["Router", "("])
                            or t.words[i+1:i+5] == ["express", ".", "Router", "("]):
            routers.add(t.at(i-1))
        if word == "function" or word == "=":
            fn = js_function(t, i + (word == "="))
            if fn:
                named[fn[0] or t.at(i-1)] = fn
    for i, word in enumerate(t.words):
        if (word not in routers or t.at(i+1) != "."
                or t.at(i+2) not in {"get", "post", "put", "patch", "delete", "all", "use"}
                or t.at(i+3) != "(" or i+3 not in t.pairs):
            continue
        end = t.pairs[i+3]
        j = i+4
        while j < end:
            fn = js_function(t, j, end)
            if not fn and t.at(j+1) in {",", ")"}:
                fn = named.get(t.at(j))
            if fn:
                name, req, body, last = fn
                yield Handler(name or (t.at(j) if t.at(j) in named else "<inline>"),
                              "express", i, body, last, {}, req)
            # Advance by argument, skipping nested parameter lists and bodies.
            while j < end and t.at(j) != ",":
                j = t.pairs[j]+1 if j in t.pairs and t.pairs[j] > j else j+1
            j += 1


def spring_handlers(t):
    for i, word in enumerate(t.words):
        if word != "@" or not t.at(i+1).endswith("Mapping"):
            continue
        j = i+2
        if t.at(j) == "(":
            j = t.pairs.get(j, j)+1
        while t.at(j) and t.at(j) not in {"{", ";", "class", "interface", "("}:
            j += 1
        if t.at(j) != "(" or j not in t.pairs:
            continue
        close = t.pairs[j]
        body = close+1
        while t.at(body) and t.at(body) not in {"{", ";", "@", "}"}:
            body += 1
        if t.at(body) != "{" or body not in t.pairs:
            continue
        params = {}
        request = ""
        request_line = None
        p = j+1
        while p < close:
            if t.at(p) in {"HttpServletRequest", "ServletRequest"}:
                request = t.at(p+1)
                request_line = t.lines[p]
            if t.at(p) == "@" and t.at(p+1) in {
                "RequestBody", "RequestParam", "PathVariable", "RequestHeader",
                "CookieValue", "RequestPart", "ModelAttribute"}:
                last = p+2
                while last < close and t.at(last) != ",":
                    last = t.pairs[last]+1 if t.at(last) == "(" and last in t.pairs else last+1
                params[t.at(last-1)] = Origin(True, (t.lines[p],))
                p = last
            p += 1
        yield Handler(t.at(j-1), "spring", i, body, t.pairs[body], params, request, request_line)


def token_flow(t, start, end, values, handler):
    words = t.words[start:end]
    if not words:
        return Origin(False, ())
    # Recognize only a simple value or property/index chain. Function returns
    # and conditional expressions have no proven value provenance.
    if len(words) == 1:
        if t.quoted(start) or words[0].isdigit() or words[0] in {"null", "true", "false"}:
            return Origin(False, (t.lines[start],))
        return values.get(words[0])
    if words[0] == handler.request and words[0] not in values and len(words) >= 3:
        if (handler.framework == "spring" and handler.request_line and words[1] == "."
                and words[2] in {"getParameter", "getHeader", "getQueryString", "getInputStream",
                                 "getReader", "getCookies"} and t.at(start+3) == "("
                and t.pairs.get(start+3) == end-1):
            return Origin(True, (handler.request_line, t.lines[start]))
        if words[1] in {".", "?."} and words[2] in {
                "body", "query", "params", "headers", "cookies", "files"}:
            if all(w in {".", "?.", "[", "]"} or re.fullmatch(r"[\w$]+", w)
                   or w.startswith(('"', "'")) for w in words[3:]):
                return Origin(True, (t.lines[start],))
    if all(w.isidentifier() or w == "." for w in words):
        return values.get(words[0])
    return None


def token_calls(src, symbol, java):
    t = Tokens(src.text)
    handlers = spring_handlers(t) if java else js_handlers(t)
    leaf = symbol.split(".")[-1]
    observed = set()

    def is_call(i):
        if t.at(i) != leaf or t.at(i+1) != "(" or i+1 not in t.pairs:
            return False
        after = t.at(t.pairs[i+1]+1)
        if t.at(i-1) in {"function", "new", "@"} or after in {"{", "throws"}:
            return False
        if "." not in symbol:
            return True
        first = i
        while first >= 2 and t.at(first-1) == "." and t.at(first-2).isidentifier():
            first -= 2
        return "".join(t.words[first:i+1]) == symbol

    for h in handlers:
        values = h.params.copy()
        blocks = []
        i = h.body+1
        while i < h.end:
            word = t.at(i)
            if word == "{" and i in t.pairs:
                previous = t.at(i-1)
                # A callback/local function may shadow request parameters.
                if previous == "=>" or (previous == ")" and
                        t.at(t.pairs.get(i-1, 0)-1) not in {"if", "for", "while", "switch", "catch",
                                                          "synchronized", "try"}):
                    i = t.pairs[i]+1
                    continue
                blocks.append(t.pairs[i])
            if blocks and i == blocks[-1]:
                blocks.pop()
            if word in {"=", "+=", "-="} and t.at(i-1).isidentifier():
                j = i+1
                while j < h.end and t.at(j) != ";" and t.lines[j] == t.lines[i]:
                    j += 1
                flow = token_flow(t, i+1, j, values, h) if word == "=" and not blocks else None
                if t.at(i-2) == ")" and t.at(t.pairs.get(i-2, 0)-1) in {"if", "for", "while"}:
                    flow = None
                values[t.at(i-1)] = assigned(flow, t.lines[i])
            if is_call(i):
                observed.add(i)
                end = t.pairs[i+1]
                start = j = i+2
                args = []
                while j <= end:
                    if t.at(j) == "," or j == end:
                        args.append(token_flow(t, start, j, values, h))
                        start = j+1
                    j = t.pairs[j]+1 if j in t.pairs and j < t.pairs[j] else j+1
                yield h.name, h.framework, combine(args), t.lines[h.route], t.lines[i], t.lines[end]
            i += 1
    for i, word in enumerate(t.words):
        if word == leaf and i not in observed and is_call(i):
            yield None, None, None, t.lines[i], t.lines[i], t.lines[t.pairs[i+1]]


def find_callers(root, files: Files, symbol: str, *, store: EvidenceStore | None = None,
                 include_excluded: bool = False, log: Log = None):
    """Report observed same-file call sites and yes/no/unknown argument provenance."""
    q = Query(root, files, store, "callers", include_excluded, log)
    hits = []
    for src in q.sources(lambda p: p.suffix in JS | {".py", ".java"}):
        ext = Path(src.name).suffix
        calls = python_calls(src, symbol) if ext == ".py" else token_calls(src, symbol, ext == ".java")
        for name, framework, flow, route, start, end in calls:
            lines = flow.lines if flow is not None else ()
            ranges = [(route, route), *((n, n) for n in lines), (start, end)]
            refs = [q.cite(src, a, b) for a, b in dict.fromkeys(ranges)]
            hits.append(dict(file=src.name, line=start, handler=name, framework=framework,
                             request_input="unknown" if flow is None else "yes" if flow.request else "no",
                             evidence_ids=refs))
    return q.finish(hits)
