"""File-local argument provenance and direct incoming edges from other request handlers."""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from pathlib import Path

from .search import JS
from .source import Files, Log, Query
from .store import EvidenceStore
from .lexer import Tokens
from .links import CallIndex, Unit


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


@dataclass
class Call:
    handler: str | None
    framework: str | None
    flow: Trace
    route: int
    start: int
    end: int
    callee: str
    position: int
    arity: int


def matches(callee, symbol):
    return callee == symbol or ("." not in symbol and callee.split(".")[-1] == symbol)


def python_calls(tree, symbol, bindings):
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
                    if not matches(name, symbol) and not (route and name in bindings):
                        continue
                    args = [*call.args, *(kw.value for kw in call.keywords)]
                    flow = combine(trace(a) for a in args) if simple else None
                    yield Call(fn.name, "flask" if route else None, flow,
                               route.lineno if route else fn.lineno, call.lineno, call.end_lineno,
                               name, fn.lineno, len(args))
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


def token_calls(unit, symbol, bindings):
    t = unit.lex
    handlers = spring_handlers(t) if unit.ext == ".java" else js_handlers(t)
    leaf = symbol.split(".")[-1]
    names = {leaf} | {name.rsplit(".", 1)[-1] for name in bindings}
    observed = set()

    def callee(i):
        if t.at(i) not in names or t.at(i+1) != "(" or i+1 not in t.pairs:
            return ""
        after = t.at(t.pairs[i+1]+1)
        if t.at(i-1) in {"function", "new", "@"} or after in {"{", "throws"}:
            return ""
        first = i
        while first >= 2 and t.at(first-1) == "." and t.at(first-2).isidentifier():
            first -= 2
        # A suffix of a computed receiver is not a resolvable import/field.
        if t.at(first-1) in {".", "?."}:
            return "." + t.at(i)
        return "".join(t.words[first:i+1])

    for h in handlers:
        values = h.params.copy()
        blocks = []
        i = h.body+1
        while i < h.end:
            if i in unit.nested:
                i = unit.nested[i]
                continue
            word = t.at(i)
            if word == "{" and i in t.pairs:
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
            name = callee(i)
            if name and (matches(name, symbol) or name in bindings):
                observed.add(i)
                end = t.pairs[i+1]
                start = j = i+2
                args = []
                while j <= end:
                    if t.at(j) == "," or j == end:
                        args.append(token_flow(t, start, j, values, h))
                        start = j+1
                    j = t.pairs[j]+1 if j in t.pairs and j < t.pairs[j] else j+1
                yield Call(h.name, h.framework, combine(args), t.lines[h.route], t.lines[i],
                           t.lines[end], name, i, len(args) if end > i+2 else 0)
            i += 1
    for i, word in enumerate(t.words):
        if word == leaf and i not in observed and (name := callee(i)) and matches(name, symbol):
            yield Call(None, None, None, t.lines[i], t.lines[i], t.lines[t.pairs[i+1]], name, i, 0)


def find_callers(root, files: Files, symbol: str, *, store: EvidenceStore | None = None,
                 include_excluded: bool = False, log: Log = None):
    """Each hit retains local argument provenance. caller_paths lists direct external
    handler calls to its enclosing function/method, with evidence from both files.
    """
    q = Query(root, files, store, "callers", include_excluded, log)
    hits = []
    units = [Unit(src) for src in q.sources(lambda p: p.suffix in JS | {".py", ".java"})]
    index = CallIndex(units)
    targets = []
    incoming = {}
    for unit in units:
        bindings = index.bindings(unit)
        calls = (python_calls(unit.tree, symbol, bindings) if unit.tree is not None
                 else token_calls(unit, symbol, bindings))
        for call in calls:
            if matches(call.callee, symbol):
                targets.append((unit, call))
            if call.framework and call.callee in bindings:
                edge = index.resolve(unit, bindings[call.callee], call)
                if edge:
                    incoming.setdefault(edge.method, []).append((unit, call, edge))

    cited = {}

    def cite(src, first, last):
        key = (src.name, first, last)
        if key not in cited:
            cited[key] = q.cite(src, first, last)
        return cited[key]

    def describe(unit, call):
        lines = call.flow.lines if call.flow is not None else ()
        refs = [cite(unit.src, n, n) for n in (call.route, *lines)]
        refs.append(cite(unit.src, call.start, call.end))
        return dict(file=unit.src.name, line=call.start, handler=call.handler, framework=call.framework,
                    request_input="unknown" if call.flow is None else "yes" if call.flow.request else "no",
                    evidence_ids=list(dict.fromkeys(refs)))

    for unit, call in targets:
        hit = describe(unit, call)
        paths = []
        method = unit.enclosing(call.position)
        local_ids = hit["evidence_ids"].copy()
        for caller, site, edge in incoming.get(method, ()):
            handler = describe(caller, site)
            handler["callee"] = site.callee
            refs = [*handler["evidence_ids"], *(cite(caller.src, a, b) for a, b in edge.lines),
                    cite(unit.src, edge.export_line, edge.export_line),
                    cite(unit.src, method.line, method.line), *local_ids]
            ids = list(dict.fromkeys(refs))
            paths.append(dict(handler=handler, method=dict(file=method.file, name=method.name,
                                                          line=method.line), evidence_ids=ids))
            hit["evidence_ids"].extend(ids)
        hit["caller_paths"] = paths
        hit["evidence_ids"] = list(dict.fromkeys(hit["evidence_ids"]))
        hits.append(hit)
    return q.finish(hits)
