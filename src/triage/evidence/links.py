"""Static bindings for one external edge. Only scoped source files are indexed."""
from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass
from pathlib import PurePosixPath
import posixpath

from .lexer import Tokens
from .search import JS


@dataclass(frozen=True)
class Method:
    file: str
    name: str
    line: int
    first: int
    last: int
    arity: int | None = None


@dataclass(frozen=True)
class Binding:
    method: Method
    lines: tuple[tuple[int, int], ...]
    export_line: int
    local: str
    first: int = 0
    last: int | None = None
    declaration: int | None = None


def spans(t, first, last):
    """Indices at one nesting depth, omitting the contents of balanced groups."""
    i = first
    while i < last:
        yield i
        i = t.pairs[i]+1 if t.pairs.get(i, i) > i else i+1


def expression_end(t, start):
    return next((i for i in spans(t, start, len(t.words)) if t.at(i) in {",", ")", ";", "}"}),
                len(t.words))


def string_spec(t, i):
    return t.at(i)[1:-1] if t.quoted(i) else ""


def python_name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute) and (base := python_name(node.value)):
        return f"{base}.{node.attr}"
    return ""


def java_arity(t, opening, close):
    if opening+1 == close:
        return 0
    count = 1
    generic_depth = 0
    for i in spans(t, opening+1, close):
        word = t.at(i)
        if word == "<":
            generic_depth += 1
        elif word == ">":
            generic_depth -= 1
        elif word == "," and generic_depth == 0:
            count += 1
    return count


class Unit:
    def __init__(self, src):
        self.src = src
        self.path = PurePosixPath(src.name)
        self.ext = self.path.suffix
        self.tree = None
        self.lex = None
        self.methods = []
        self.exports = defaultdict(list)
        self.shadows = {}
        self.classes = []
        self.package = ""
        self.type_imports = {}
        self.java_variables = defaultdict(list)
        self.nested = {}
        if self.ext == ".py":
            try:
                self.tree = ast.parse(src.text)
            except (ValueError, SyntaxError, RecursionError):
                self.tree = ast.Module(body=[], type_ignores=[])
            self._python()
        else:
            self.lex = Tokens(src.text)
            if self.ext == ".java":
                self._java()
            else:
                self._javascript()
            self._nested_functions()

    def declare(self, name, line, first, last, arity=None):
        method = Method(self.src.name, name, line, first, last, arity)
        self.methods.append(method)
        return method

    def enclosing(self, position):
        if self.ext == ".py":
            # python_calls supplies the owning function's definition line.
            return next((m for m in self.methods if m.first == position), None)
        method = next((m for m in self.methods if m.first < position < m.last), None)
        if method and any(method.first < a <= position < b for a, b in self.nested.items()):
            return None
        return method

    def _nested_functions(self):
        t = self.lex
        for i, word in enumerate(t.words):
            if word == "=>" or (word == ">" and t.at(i-1) == "-"):
                if t.at(i+1) == "{":
                    self.nested[i+1] = t.pairs.get(i+1, i+1)+1
                else:
                    self.nested[i] = expression_end(t, i+1)
            elif word == "{" and t.at(i-1) == ")":
                before = t.at(t.pairs.get(i-1, 0)-1)
                if before not in {"for", "if", "switch", "try", "while", "catch", "synchronized"}:
                    self.nested[i] = t.pairs.get(i, i)+1

    def _python(self):
        function = (ast.FunctionDef, ast.AsyncFunctionDef)
        for node in self.tree.body:
            members = node.body if isinstance(node, ast.ClassDef) else [node]
            for fn in members:
                if isinstance(fn, function):
                    name = f"{node.name}.{fn.name}" if isinstance(node, ast.ClassDef) else fn.name
                    method = self.declare(name, fn.lineno, fn.lineno, fn.end_lineno)
                    self.exports[name].append((method, fn.lineno))
        for fn in ast.walk(self.tree):
            if isinstance(fn, function):
                names = set()
                for n in ast.walk(fn):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                        names.add(n.id)
                    elif isinstance(n, ast.arg):
                        names.add(n.arg)
                    elif isinstance(n, ast.alias):
                        names.add(n.asname or n.name.split(".")[0])
                    elif isinstance(n, (*function, ast.ClassDef)) and n is not fn:
                        names.add(n.name)
                self.shadows[fn.lineno] = names

    def _javascript(self):
        t = self.lex
        definitions = defaultdict(list)
        exports = []
        top = list(spans(t, 0, len(t.words)))
        for i in top:
            if t.at(i) == "function" and t.at(i+1).isidentifier() and t.at(i+2) == "(":
                name = t.at(i+1)
                body = t.pairs.get(i+2, i)+1
            elif t.at(i) in {"const", "let"} and t.at(i+2) == "=":
                name = t.at(i+1)
                p = i+3 + (t.at(i+3) == "async")
                arrow = t.pairs.get(p, p)+1
                if t.at(arrow) != "=>":
                    continue
                body = arrow+1
                if not t.at(body):
                    continue
                if t.at(body) != "{":
                    # A concise helper ends at a top-level terminator or line break.
                    end = next((j for j in spans(t, body, len(t.words))
                                if t.at(j) == ";" or t.lines[j] > t.lines[body]), len(t.words))
                    definitions[name].append(self.declare(name, t.lines[i], arrow, end))
                    continue
            else:
                continue
            if t.at(body) == "{" and body in t.pairs:
                definitions[name].append(self.declare(name, t.lines[i], body, t.pairs[body]))

        for i in top:
            word = t.at(i)
            if word == "export":
                j = i+1
                default = t.at(j) == "default"
                j += int(default)
                j += int(t.at(j) == "async")
                if t.at(j) in {"function", "const", "let"}:
                    local = t.at(j+1)
                    exports.append(("default" if default else local, local, i))
                elif t.at(j) == "{" and j in t.pairs:
                    if t.at(t.pairs[j]+1) != "from":
                        for local, public, entry in name_pairs(t, j, "as"):
                            exports.append((public, local, entry))
                elif default:
                    exports.append(("default", t.at(j), i))
            elif word == "exports":
                if t.at(i+1) == "." and t.at(i+3) == "=":
                    exports.append((t.at(i+2), t.at(i+4), i))
                elif t.at(i+1) == "=" and t.words[max(0,i-2):i] == ["module", "."]:
                    if t.at(i+2) == "{":
                        for public, local, entry in name_pairs(t, i+2, ":"):
                            exports.append((public, local, entry))
                        for p in spans(t, i+3, t.pairs.get(i+2, i+3)):
                            if t.at(p) != "(" or p not in t.pairs or t.at(p-2) not in {"{", ",", "async"}:
                                continue
                            block = t.pairs[p]+1
                            if t.at(block) == "{" and block in t.pairs:
                                name = t.at(p-1)
                                method = self.declare(name, t.lines[p-1], block, t.pairs[block])
                                self.exports[name].append((method, t.lines[i]))
                    else:
                        exports.append(("default", t.at(i+2), i))
        for public, local, i in exports:
            self.exports[public].extend((m, t.lines[i]) for m in definitions[local])

    def _java(self):
        t = self.lex
        top = list(spans(t, 0, len(t.words)))
        for i in top:
            if t.at(i) in {"package", "import"}:
                j = i+1
                while t.at(j) and t.at(j) != ";":
                    j += 1
                name = "".join(t.words[i+1:j])
                if t.at(i) == "package":
                    self.package = name
                else:
                    self.type_imports[name.rsplit(".", 1)[-1]] = (name, t.lines[i])
            if t.at(i) != "class":
                continue
            body = next((j for j in spans(t, i+2, len(t.words)) if t.at(j) == "{"), None)
            if body is None or body not in t.pairs:
                continue
            owner = ".".join(filter(None, (self.package, t.at(i+1))))
            self.classes.append((owner, body, t.pairs[body]))
            for p in spans(t, body+1, t.pairs[body]):
                if t.at(p) != "(" or p not in t.pairs or not t.at(p-1).isidentifier():
                    continue
                close = t.pairs[p]
                block = close+1
                if t.at(block) == "throws":
                    while t.at(block) and t.at(block) not in {";", "{"}:
                        block += 1
                if t.at(block) != "{" or block not in t.pairs:
                    continue
                arity = java_arity(t, p, close)
                method = self.declare(t.at(p-1), t.lines[p-1], block, t.pairs[block], arity)
                self.exports[(owner, method.name)].append((method, t.lines[i]))
            # Names declared in a nearer block/parameter list shadow a class field,
            # including declarations whose type belongs to an unindexed library.
            groups = []
            for k in range(body+1, t.pairs[body]):
                while groups and groups[-1][1] <= k:
                    groups.pop()
                if t.at(k) == "{" and k in t.pairs:
                    groups.append((k, t.pairs[k]))
                if (not t.at(k).isidentifier() or t.at(k) in {"return", "throw", "new", "case"}
                        or not t.at(k+1).isidentifier() or t.at(k+2) not in {";", "=", ",", ")"}):
                    continue
                first, last = groups[-1] if groups else (body, t.pairs[body])
                for m in self.methods:
                    if i < k < m.first and t.pairs.get(m.first-1, m.first) < k:
                        first, last = m.first, m.last
                        break
                self.java_variables[t.at(k+1)].append((k, first, last, first == body))


def name_pairs(t, opening, separator):
    """Simple JS shorthand or aliased names within a flat destructuring/export list."""
    i = opening+1
    end = t.pairs.get(opening, i)
    while i < end:
        entry = i
        left = right = t.at(i)
        i += 1
        if t.at(i) == separator:
            right = t.at(i+1)
            i += 2
        if not left.isidentifier() or not right.isidentifier() or t.at(i) not in {",", "}"}:
            return
        yield left, right, entry
        i += 1


class CallIndex:
    def __init__(self, units):
        self.files = {unit.path.as_posix(): unit for unit in units}
        self.java_types = defaultdict(list)
        for unit in units:
            for owner, _, _ in unit.classes:
                self.java_types[owner].append(unit)

    def _module(self, candidates):
        found = {self.files[name] for name in candidates if name in self.files}
        return found.pop() if len(found) == 1 else None

    def _py_module(self, unit, module, level):
        parent = unit.path.parent
        if level:
            if level-1 > len(parent.parts):
                return None
            for _ in range(level-1):
                parent = parent.parent
            bases = {parent}
        else:
            bases = {PurePosixPath("."), PurePosixPath("src"), parent}
        stem = module.replace(".", "/")
        return self._module(str(path) for base in bases for path in
                            (base / f"{stem}.py", base / stem / "__init__.py"))

    def _js_module(self, unit, spec):
        if not spec.startswith(("./", "../")):
            return None
        base = posixpath.normpath(str(unit.path.parent / spec))
        if base in self.files and self.files[base].ext in JS:
            return self.files[base]
        return self._module(path for ext in JS for path in (base+ext, base+"/index"+ext))

    def bindings(self, unit):
        bindings = defaultdict(list)

        def bind(name, target, public, local, lines, first=0, last=None, declaration=None):
            if target is None or target is unit:
                return
            for method, export_line in target.exports.get(public, ()):
                bindings[name].append(Binding(method, tuple(lines), export_line, local,
                                              first, last, declaration))

        if unit.ext == ".py":
            self._python(unit, bind)
        elif unit.ext == ".java":
            self._java(unit, bind)
        else:
            self._javascript(unit, bind)
        return bindings

    def _python(self, unit, bind):
        # Only unconditional module imports have a known binding for every handler.
        imports = defaultdict(list)
        for stmt in unit.tree.body:
            if isinstance(stmt, ast.ImportFrom):
                for alias in stmt.names:
                    local = alias.asname or alias.name
                    submodule = ".".join(filter(None, (stmt.module, alias.name)))
                    imports[local].append((stmt, self._py_module(unit, submodule, stmt.level), ""))
                    if stmt.module:
                        imports[local].append((stmt, self._py_module(unit, stmt.module, stmt.level),
                                               alias.name))
            elif isinstance(stmt, ast.Import):
                for alias in stmt.names:
                    imports[alias.asname or alias.name].append(
                        (stmt, self._py_module(unit, alias.name, 0), ""))
        assigned = defaultdict(list)
        instances = defaultdict(list)
        for stmt in unit.tree.body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
                assigned[stmt.name].append(stmt)
            elif not isinstance(stmt, (ast.ImportFrom, ast.Import)):
                for n in ast.walk(stmt):
                    if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                        assigned[n.id].append(stmt)
                if (isinstance(stmt, ast.Assign) and len(stmt.targets) == 1 and
                        isinstance(stmt.targets[0], ast.Name) and isinstance(stmt.value, ast.Call)):
                    instances[python_name(stmt.value.func)].append((stmt.targets[0].id, stmt))
        for local, entries in imports.items():
            if local.split(".")[0] in assigned or len({stmt for stmt, _, _ in entries}) != 1:
                continue
            for stmt, target, member in entries:
                if target is None:
                    continue
                for name in target.exports:
                    if member and name != member and not name.startswith(member+"."):
                        continue
                    suffix = name[len(member):] if member else "."+name
                    imported = local+suffix
                    lines = [(stmt.lineno, stmt.end_lineno)]
                    bind(imported, target, name, local.split(".")[0], lines)
                    if "." in name:
                        constructor, _, method = imported.rpartition(".")
                        for variable, assignment in instances[constructor]:
                            if assigned[variable] == [assignment] and variable not in imports:
                                bind(f"{variable}.{method}", target, name, variable,
                                     [*lines, (assignment.lineno, assignment.end_lineno)])

    def _javascript(self, unit, bind):
        t = unit.lex
        for i in spans(t, 0, len(t.words)):
            word = t.at(i)
            pairs = []
            namespace = ""
            if word == "import":
                start = i+1
                if t.at(start) == "{":
                    pairs = [(a, b) for a, b, _ in name_pairs(t, start, "as")]
                    end = t.pairs.get(start, start)+2
                elif t.at(start) == "*" and t.at(start+1) == "as":
                    namespace = t.at(start+2)
                    end = start+4
                else:
                    pairs = [("default", t.at(start))]
                    end = start+2
                if t.at(end-1) != "from":
                    continue
            elif word in {"const", "let", "var"}:
                start = i+1
                assignment = t.pairs.get(start, start)+1
                if t.words[assignment:assignment+3] != ["=", "require", "("]:
                    continue
                if t.at(start) == "{":
                    pairs = [(a, b) for a, b, _ in name_pairs(t, start, ":")]
                else:
                    namespace = t.at(start)
                    pairs = [("default", namespace)]
                end = assignment+3
                if t.at(end+1) != ")":
                    continue
                after = end+2
                if namespace and t.at(after) == "." and t.at(after+1).isidentifier():
                    pairs = [(t.at(after+1), namespace)]
                    namespace = ""
                    after += 2
                if t.at(after) and t.at(after) != ";" and t.lines[after] == t.lines[end]:
                    continue
            else:
                continue
            target = self._js_module(unit, string_spec(t, end))
            if target is None:
                continue
            lines = [(t.lines[i], t.lines[end])]
            for public, local in pairs:
                bind(local, target, public, local, lines, declaration=start)
            if namespace:
                for public in target.exports:
                    bind(f"{namespace}.{public}", target, public, namespace, lines, declaration=start)

    def _java(self, unit, bind):
        t = unit.lex
        for _, body, end in unit.classes:
            for i in range(body+1, end):
                simple = t.at(i)
                qualified, imported = unit.type_imports.get(
                    simple, (".".join(filter(None, (unit.package, simple))), None))
                units = self.java_types.get(qualified, ())
                if len(units) != 1:
                    continue
                target = units[0]
                local = t.at(i+1)
                static = local == "."
                if not static and (not local.isidentifier() or t.at(i+2) not in {";", "=", ",", ")"}):
                    continue
                receiver = simple if static else local
                if static:
                    first, last = i, i+3
                else:
                    decl = next((d for d in unit.java_variables[local] if d[0] == i), None)
                    if not decl:
                        continue
                    _, first, last, _ = decl
                lines = [(t.lines[i], t.lines[i])]
                if imported is not None:
                    lines.append((imported, imported))
                for (cls, name) in target.exports:
                    if cls == qualified:
                        bind(f"{receiver}.{name}", target, (cls, name), receiver, lines, first, last,
                             None if static else i)
                        if not static and first == body:
                            bind(f"this.{receiver}.{name}", target, (cls, name), receiver,
                                 lines, first, last, i)

    def resolve(self, unit, candidates, call):
        matched = []
        for edge in candidates:
            if call.position < edge.first or (edge.last is not None and call.position >= edge.last):
                continue
            if edge.method.arity is not None and call.arity != edge.method.arity:
                continue
            if edge.local in unit.shadows.get(call.position, ()):
                continue
            if unit.ext in JS and js_shadowed(unit.lex, edge, call.position):
                continue
            if unit.ext == ".java":
                visible = [d for d in unit.java_variables[edge.local]
                           if d[1] < call.position < d[2] and (d[3] or d[0] < call.position)
                           and (not call.callee.startswith("this.") or d[3])]
                nearest = max(visible, key=lambda d: d[1], default=None)
                if (nearest[0] if nearest else None) != edge.declaration:
                    continue
            matched.append(edge)
        # Same arity overloads, duplicate exports and competing bindings are ambiguous.
        unique = {edge.method for edge in matched}
        return matched[0] if len(unique) == 1 else None


def js_shadowed(t, edge, position):
    for i, word in enumerate(t.words):
        if word != edge.local or i == edge.declaration:
            continue
        if t.at(i-1) in {"const", "let", "var", "function", "class"} or t.at(i+1) == "=":
            return True
        if t.at(i+1) == "=>":
            if t.at(i+2) == "{":
                if i+2 < position < t.pairs.get(i+2, i+2):
                    return True
            elif i+2 <= position < expression_end(t, i+2):
                return True
        if t.at(i-1) in {"(", ","} and t.at(i+1) in {",", ")"}:
            # Limit parameter shadowing to an enclosing function, not arguments of calls.
            for p in range(i-1, -1, -1):
                if t.at(p) == "(" and t.pairs.get(p, 0) > i:
                    close = t.pairs[p]
                    body = close+1 + (t.at(close+1) == "=>")
                    if t.at(body) == "{" and body < position < t.pairs.get(body, body):
                        return True
                    if (t.at(close+1) == "=>" and t.at(body) != "{"
                            and body <= position < expression_end(t, body)):
                        return True
                    break
    return False
