"""판정 한 건의 증거 작업 공간.

후보마다 전용 EvidenceStore 를 써서 근거 ID가 그 후보의 처리만으로 정해지게 한다(동시 처리해도
같은 입력이면 같은 프롬프트 → 모델 캐시 적중). 끝나면 agent 가 실행 전체 저장소로 옮겨 ID를 다시 매긴다.
"""
from __future__ import annotations

import re
from pathlib import Path

from triage.evidence import EvidenceStore, find_callers, read_lines, resolve_config, search_symbol
from triage.models import Anomaly, Checklist, Evidence, Finding, SourceFileScope

from .checklist import import_names
from .comments import comment_starts, comment_text
from .settings import Settings

_CALLABLE = re.compile(r"^[A-Za-z_$][\w$]*(\.[A-Za-z_$][\w$]*)*$")
_RANGE_NOTE = {True: "범위 안", False: "범위 밖", None: "계산 불가"}


class Workspace:
    def __init__(self, root: Path, files: list[SourceFileScope], base: list[Evidence], settings: Settings,
                 log=None, subject: str = ""):
        self.root = Path(root).resolve()
        self.files = files
        self.scope = {Path(f.path).as_posix(): f for f in files}
        self.store = EvidenceStore(self.root)
        self.store.merge(base)
        self.new: list[Evidence] = []
        self.settings = settings
        self.log = log
        self.subject = subject
        self.memo: dict[tuple, str] = {}
        self.shown: dict[tuple, str] = {}
        self.anomalies: dict[tuple, Anomaly] = {}
        self.tool_count = 0
        self.checklist: Checklist | None = None

    # ── 근거 표시 ──
    def note(self, **fields) -> str:
        item = self.store.add("judge", **fields)
        self.new.append(item)
        return item.id

    def exists(self, eid: str) -> bool:
        try:
            self.store.get(eid)
        except KeyError:
            return False
        return True

    def deployed(self, path: str) -> str:
        s = self.scope.get(path)
        return s.deployed if s else "unknown"

    def render(self, eid: str, focus: int | None = None) -> str:
        try:
            e = self.store.get(eid)
        except KeyError:
            return f"[{eid}] (근거 없음)"
        if not e.file or e.line_start is None:
            where = e.url or e.file
            return f"[{eid}] ({e.kind}) {e.note or e.command}" + (f" — {where}" if where else "")
        s = self.scope.get(e.file)
        head = (f"[{eid}] {e.file}:{e.line_start}-{e.line_end} "
                f"(배포: {s.deployed if s else 'unknown'}, 분류: {s.category if s else '-'})")
        same = self.shown.get((e.file, e.line_start, e.line_end))
        if same and same != eid:
            return f"{head} — [{same}]와 같은 줄"
        self.shown[(e.file, e.line_start, e.line_end)] = eid
        lines = e.snippet.split("\n")
        starts = comment_starts(e.file, lines)
        texts = comment_text(e.file, lines)
        whole = [str(e.line_start + i) for i, st in enumerate(starts) if st == 0]
        flagged = []
        for i, text in enumerate(texts):
            if text and any(p.search(text) for p in self.settings.instruction_patterns):
                n = e.line_start + i
                flagged.append(str(n))
                self.anomalies.setdefault((e.file, n), Anomaly(
                    kind="instruction_like_comment",
                    message=f"{e.file}:{n} 판정 지시처럼 보이는 주석을 근거에서 제외: {text.strip()[:160]}",
                    evidence_ids=[eid]))
        notes = []
        if whole:
            notes.append(f"주석·문서 줄: {', '.join(whole)}")
        if flagged:
            notes.append(f"주의: 판정 지시처럼 보이는 주석 줄 {', '.join(flagged)} — 근거 아님")
        body = [f"  {e.line_start + i:>5}{'>' if e.line_start + i == focus else ' '}| {text}"
                for i, text in enumerate(lines)]
        return "\n".join([head + (f" [{'; '.join(notes)}]" if notes else ""), *body])

    def _tool(self, tool: str, args: dict, by: str, ids: list[str], hits: int) -> None:
        if self.log:
            self.log("judge", "tool", subject=self.subject, tool=tool, args=args, by=by, hits=hits,
                     evidence_ids=ids[:40])

    def _scanned(self) -> int:
        return sum(1 for f in self.files if f.category not in {"generated", "vendored_bundle"})

    # ── 도구 4종 ──
    def search(self, symbol: str, by: str = "prefetch") -> str:
        key = ("search_symbol", symbol)
        if key in self.memo:
            return f"search_symbol '{symbol}': 위에 표시함"
        hits, ev = search_symbol(self.root, self.files, symbol, store=self.store)
        self.new.extend(ev)
        if hits:
            blocks = [self.render(h["evidence_ids"][0], focus=h["line"]) for h in hits]
            more = " (상한 8건까지만 표시)" if len(hits) >= 8 else ""
            text = f"search_symbol '{symbol}': {len(hits)}건{more}\n" + "\n".join(blocks)
            ids = [i for h in hits for i in h["evidence_ids"]]
        else:
            eid = self.note(kind="tool", command=f"search_symbol {symbol!r}",
                            note=f"검색 0건: 파일 {self._scanned()}개(생성·번들 파일 제외)에서 '{symbol}'을 찾지 못함")
            text, ids = f"search_symbol '{symbol}': 0건 [{eid}]", [eid]
        self._tool("search_symbol", {"symbol": symbol}, by, ids, len(hits))
        self.memo[key] = text
        return text

    def callers(self, symbol: str, by: str = "prefetch") -> str:
        key = ("find_callers", symbol)
        if key in self.memo:
            return f"find_callers '{symbol}': 위에 표시함"
        hits, ev = find_callers(self.root, self.files, symbol, store=self.store)
        self.new.extend(ev)
        ids = []
        if hits:
            parts = [f"find_callers '{symbol}': {len(hits)}건"]
            for h in hits:
                parts.append(f"- 호출 {h['file']}:{h['line']} (배포: {self.deployed(h['file'])}) "
                             f"처리기={h.get('handler') or '-'}({h.get('framework') or '-'}) "
                             f"요청 입력 전달={h.get('request_input')}")
                for path in h.get("caller_paths", []):
                    hd = path["handler"]
                    parts.append(f"  · 외부 처리기 경유: {hd['file']}:{hd['line']} {hd.get('handler') or '-'} "
                                 f"→ {path['method']['name']} (요청 입력 전달={hd.get('request_input')})")
                parts += [self.render(i) for i in h["evidence_ids"][:6]]
                ids += h["evidence_ids"]
            text = "\n".join(parts)
        else:
            eid = self.note(kind="tool", command=f"find_callers {symbol!r}",
                            note=f"호출 0건: 파일 {self._scanned()}개(생성·번들 파일 제외)에서 '{symbol}' 호출을 찾지 못함")
            text, ids = f"find_callers '{symbol}': 0건 [{eid}]", [eid]
        self._tool("find_callers", {"symbol": symbol}, by, ids, len(hits))
        self.memo[key] = text
        return text

    def read(self, path: str, start: int, end: int, by: str = "model") -> str:
        path = Path(path).as_posix()
        if path not in self.scope:
            return f"read_lines '{path}': 점검 범위에 없는 파일"
        start = max(1, int(start or 1))
        end = int(end) if end and int(end) >= start else None
        try:
            result, ev = read_lines(self.root, self.files, path, start, end, store=self.store)
        except ValueError as e:
            return f"read_lines '{path}': {e}"
        self.new.extend(ev)
        ids = result.get("evidence_ids", [])
        self._tool("read_lines", {"path": path, "start": start, "end": end}, by, ids, len(result.get("lines", [])))
        if not ids:
            return f"read_lines '{path}' {start}-{end or ''}: 읽을 줄 없음"
        return f"read_lines '{path}':\n" + self.render(ids[0])

    def config(self, key: str, by: str = "prefetch") -> str:
        memo = ("resolve_config", key)
        if memo in self.memo:
            return f"resolve_config '{key}': 위에 표시함"
        result, ev = resolve_config(self.root, self.files, key, store=self.store)
        self.new.extend(ev)
        ids = list(result.get("evidence_ids", []))
        head = (f"resolve_config '{key}': 상태={result['status']} 값={result.get('value')!r}"
                + (f" 사유={'; '.join(result['reasons'])}" if result.get("reasons") else ""))
        parts = [head]
        for m in result.get("matches", []):
            parts.append(f"- 값={m['value']!r} 위치={m['file']}" + (f" ({m['context']})" if m.get("context") else ""))
            parts += [self.render(i) for i in m["evidence_ids"]]
        if not result.get("matches"):
            eid = self.note(kind="tool", command=f"resolve_config {key!r}",
                            note=f"설정 0건: '{key}' 설정을 점검 범위 설정 파일에서 찾지 못함")
            parts[0] += f" [{eid}]"
            ids.append(eid)
        self._tool("resolve_config", {"key": key}, by, ids, len(result.get("matches", [])))
        text = "\n".join(parts)
        self.memo[memo] = text
        return text

    def run_tool(self, request: dict) -> str:
        """모델이 요청한 도구 하나를 실행한다."""
        tool = request.get("tool", "")
        self.tool_count += 1
        try:
            if tool == "search_symbol" and request.get("symbol", "").strip():
                return self.search(request["symbol"].strip(), by="model")
            if tool == "find_callers" and request.get("symbol", "").strip():
                return self.callers(request["symbol"].strip(), by="model")
            if tool == "read_lines" and request.get("path", "").strip():
                return self.read(request["path"].strip(), request.get("start", 1), request.get("end", 0))
            if tool == "resolve_config" and request.get("key", "").strip():
                return self.config(request["key"].strip(), by="model")
        except (OSError, ValueError, KeyError, RecursionError) as e:
            return f"{tool}: 도구 오류 {type(e).__name__}"
        return f"{tool}: 인자가 비어 있거나 알 수 없는 도구"

    # ── 결정적 증거 수집 ──
    def imports(self, graph: dict, names: list[str]) -> tuple[str, list[str]]:
        """패키지를 import 하는 파일 목록과, 배포 파일에서 실제로 import 된 모듈 이름."""
        lines, used = [], []
        for module in sorted(graph):
            if not any(module == n or module.startswith(n + ".") for n in names):
                continue
            for path, eids in sorted(graph[module].items()):
                lines.append(f"- {module} ← {path} (배포: {self.deployed(path)}) [{', '.join(eids[:3])}]")
                if self.deployed(path) != "no":
                    used.append(module)
        if not lines:
            eid = self.note(kind="tool", command=f"import graph {names!r}",
                            note="가져오기 0건: 이 이름들을 직접 import 하는 파일이 없음(간접 의존성일 수 있음)")
            return f"직접 import 하는 파일 없음 [{eid}] — 간접 의존성이면 상위 라이브러리를 통해 쓰일 수 있음", []
        return "\n".join(lines[:30]) + ("\n  (이하 생략)" if len(lines) > 30 else ""), list(dict.fromkeys(used))

    def gather(self, finding: Finding, checklist: Checklist, graph: dict) -> str:
        names = list(import_names(finding.component))
        for item in checklist.items:
            for sym in item.symbols:
                head = sym.split(".")[0]
                if _CALLABLE.match(sym) and "." in sym and head not in names:
                    names.append(head)
        listing, modules = self.imports(graph, names)
        sections = ["### 패키지 사용 위치(가져오기 분석, 이름 후보: " + ", ".join(names) + ")", listing]
        # 배포 파일이 import 하는 모듈 이름으로 실제 호출 줄을 보여 준다. 권고문이 말한 함수 이름과 달라도
        # 기본 인자·별칭·래퍼를 거쳐 취약 기능에 닿는 호출을 놓치지 않기 위해서다.
        calls = [self.search(m) for m in modules[:self.settings.max_symbols_per_item] if _CALLABLE.match(m)]
        if calls:
            sections += ["### 패키지 호출 줄(import 이름 검색)", "\n".join(calls)]
        budget = self.settings.max_prompt_evidence_chars
        used = sum(len(s) for s in sections)
        for item in checklist.items:
            parts = []
            for sym in item.symbols[:self.settings.max_symbols_per_item]:
                parts.append(self.search(sym))
                if item.kind in {"api_use", "input_source"} and _CALLABLE.match(sym):
                    parts.append(self.callers(sym))
            for key in item.config_keys[:self.settings.max_config_keys_per_item]:
                parts.append(self.config(key))
            block = f"### 항목 {item.key}\n" + ("\n".join(parts) if parts else "(검색어 없음 — 필요하면 도구로 조회)")
            if used + len(block) > budget:
                sections.append(f"### 항목 {item.key}\n(증거가 많아 생략 — 필요하면 도구로 조회)")
                continue
            used += len(block)
            sections.append(block)
        return "\n\n".join(sections)

    def facts(self, finding: Finding) -> str:
        """조회·수집·배포 단계가 이미 정한 사실(모델이 바꾸지 않는다)."""
        c, v = finding.component, finding.vulnerability
        lookup_ids = list(finding.hints.get("evidence_ids", []))
        fixed = ", ".join(v.fixed_versions) or "(없음)"
        lines = [
            f"- 취약점: {v.id}" + (f" (별칭: {', '.join(v.aliases)})" if v.aliases else ""),
            f"- 구성요소: {c.display} (생태계: {c.ecosystem or '-'}, 종류: {c.kind}, 직접 의존성: "
            f"{ {True: '예', False: '아니오', None: '모름'}[c.direct] }, 버전 출처: {c.version_source or '-'})",
            f"- 버전 범위 판정(조회 데이터로 코드가 계산): {_RANGE_NOTE[finding.version_in_range]}",
            f"- 영향 범위: {'; '.join(v.affected_ranges[-5:]) or '(없음)'}",
            f"- 조회된 수정 버전: {fixed}  ← fix_version 은 이 목록 안에서만",
            f"- 배포 여부: {c.deployed} — {c.deployed_reason or '사유 없음'}",
            f"- 심각도: {v.severity or '-'} {v.cvss_score if v.cvss_score is not None else ''}",
            "",
            "#### 권고문·조회 근거",
            *[self.render(i) for i in lookup_ids[:8]],
            "",
            "#### 구성요소 근거(버전·배포)",
            *[self.render(i) for i in c.evidence_ids[:8]],
        ]
        return "\n".join(lines)

    def scope_summary(self) -> str:
        groups: dict[str, list[str]] = {}
        for f in self.files:
            groups.setdefault(f.deployed, []).append(f"{f.path}({f.category})")
        out = []
        for state in ("no", "unknown"):
            paths = groups.get(state, [])
            if paths:
                out.append(f"- 배포 {state}: " + ", ".join(paths[:40]) + (" …" if len(paths) > 40 else ""))
        out.append(f"- 배포 yes: 파일 {len(groups.get('yes', []))}개")
        return "\n".join(out)

    def deployed_code_evidence(self) -> int:
        """배포되는 앱 파일의 코드 근거 수(승급의 '증거 충분' 기준)."""
        count = 0
        for e in self.new:
            s = self.scope.get(e.file)
            if e.kind == "code" and s and s.deployed == "yes" and s.category == "app":
                lines = e.snippet.split("\n")
                if any(st != 0 for st, line in zip(comment_starts(e.file, lines), lines) if line.strip()):
                    count += 1
        return count
