"""모델 판정의 결정적 검증. 위반이 있으면 위반 내용을 넣어 1회 재요청, 또 실패하면 판단 유보로 강등한다.

규칙(이름은 로그·verifier_notes·재요청 문구에 그대로 쓴다)
- evidence_not_found      인용한 근거 ID가 실행 근거 저장소에 없음
- evidence_mismatch       파일 근거의 원문이 실제 파일과 다름(EvidenceStore.verify 실패)
- quote_mismatch          인용문이 그 근거 원문에 없음(파일 줄 근거는 인용 필수)
- item_without_evidence   met/not_met 항목에 근거가 하나도 없음
- unknown_item            점검표에 없는 항목 키
- comment_only_evidence   met/not_met 항목의 인용이 전부 주석·문서 줄
- version_conflict        버전 범위 판정과 모순(범위 밖인데 영향 있음/없음 외, 계산 불가인데 영향 있음)
- deployment_conflict     배포 여부와 모순(미배포 구성요소·배포 안 되는 파일만 근거로 영향 있음)
- fix_version_not_in_lookup  수정 버전이 조회 데이터의 수정 버전 목록에 없음
- missing_info_empty      판단 유보인데 필요한 정보(missing_info)가 비어 있음
- state_items_conflict    판정과 항목 결과가 맞지 않음(영향 있음인데 필수 항목 미충족 등)
- justification_missing   영향 없음인데 CycloneDX 사유가 없음
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from triage.evidence import EvidenceStore
from triage.models import Checklist, Finding, SourceFileScope

from .comments import locate, quote_in_comment

CODE_CATEGORIES = {"app", "test", "script", "legacy", "generated", "vendored_bundle"}


@dataclass(frozen=True)
class Violation:
    rule: str
    message: str

    def __str__(self) -> str:
        return f"[{self.rule}] {self.message}"


def _line_backed(e) -> bool:
    return bool(e.file) and e.line_start is not None


def check(output: dict, *, finding: Finding, checklist: Checklist, store: EvidenceStore,
          scope: dict[str, SourceFileScope]) -> list[Violation]:
    out: list[Violation] = []
    state = output.get("state", "")
    items = output.get("items", [])
    keys = {i.key: i for i in checklist.items}
    status = {}

    # ── 근거 실재·원문 일치·인용 ──
    item_comment_only: dict[str, bool] = {}
    item_code_files: dict[str, list[str]] = {}
    for item in items:
        key = item.get("key", "")
        if key not in keys:
            out.append(Violation("unknown_item", f"점검표에 없는 항목 '{key}'"))
            continue
        status[key] = item.get("status", "unknown")
        citations = item.get("citations", [])
        if status[key] in ("met", "not_met") and not citations:
            out.append(Violation("item_without_evidence", f"'{key}'를 {status[key]}로 판정했지만 근거 ID가 없음"))
        comment_flags = []
        for c in citations:
            eid = c.get("evidence_id", "")
            try:
                e = store.get(eid)
            except KeyError:
                out.append(Violation("evidence_not_found", f"'{key}'의 근거 '{eid}'는 존재하지 않는 ID"))
                comment_flags.append(False)
                continue
            if not _line_backed(e):
                comment_flags.append(False)       # 조회·도구 기록은 주석이 아니다
                continue
            if not store.verify(eid):
                out.append(Violation("evidence_mismatch", f"'{key}'의 근거 '{eid}' 원문이 실제 파일({e.file})과 다름"))
            quote = c.get("quote", "")
            if not quote.strip() or locate(quote, e.snippet) is None:
                out.append(Violation("quote_mismatch",
                                     f"'{key}'의 근거 '{eid}' 인용문이 원문({e.file}:{e.line_start}-{e.line_end})에 없음"))
                comment_flags.append(False)
                continue
            comment_flags.append(bool(quote_in_comment(e.file, quote, e.snippet)))
            s = scope.get(Path(e.file).as_posix())
            if s and s.category in CODE_CATEGORIES:
                item_code_files.setdefault(key, []).append(e.file)
        if status[key] in ("met", "not_met") and comment_flags and all(comment_flags):
            item_comment_only[key] = True
            out.append(Violation("comment_only_evidence",
                                 f"'{key}'의 근거가 전부 주석·문서 줄임. 주석은 단서일 뿐이니 실제 코드 줄이나 검색 기록을 인용할 것"))

    # ── 버전 범위 ──
    in_range = finding.version_in_range
    if in_range is False and state != "not_affected":
        out.append(Violation("version_conflict", "조회 데이터상 설치 버전이 영향 범위 밖인데 영향 없음이 아님"))
    if in_range is None and state == "affected":
        out.append(Violation("version_conflict", "설치 버전의 영향 범위 여부를 계산할 수 없는데 영향 있음으로 판정함"))

    # ── 배포 여부 ──
    c = finding.component
    if c.deployed == "no" and state == "affected":
        out.append(Violation("deployment_conflict", f"구성요소가 배포되지 않는데({c.deployed_reason}) 영향 있음으로 판정함"))
    if state == "affected":
        for key, files in item_code_files.items():
            if status.get(key) != "met" or keys[key].kind not in {"api_use", "input_source"}:
                continue
            states = {scope[Path(f).as_posix()].deployed for f in files if Path(f).as_posix() in scope}
            if states and states <= {"no"}:
                out.append(Violation("deployment_conflict",
                                     f"'{key}'의 코드 근거가 전부 배포되지 않는 파일({', '.join(sorted(set(files)))})"))

    # ── 수정 버전 ──
    fix = (output.get("fix_version") or "").strip()
    known = {v.strip().lstrip("v") for v in finding.vulnerability.fixed_versions}
    if fix and fix.lstrip("v") not in known:
        listed = ", ".join(finding.vulnerability.fixed_versions) or "없음"
        out.append(Violation("fix_version_not_in_lookup", f"수정 버전 '{fix}'가 조회 데이터 목록({listed})에 없음"))

    # ── 판단 유보 사유 ──
    if state == "undetermined" and not any((m.get("what") or "").strip() for m in output.get("missing_info", [])):
        out.append(Violation("missing_info_empty", "판단 유보인데 필요한 정보와 확인 위치(missing_info)가 비어 있음"))

    # ── 판정과 항목 결과의 일관성 ──
    required = [k for k, i in keys.items() if i.required]
    if state == "affected":
        unmet = [k for k in required if status.get(k) != "met"]
        if unmet:
            out.append(Violation("state_items_conflict",
                                 f"영향 있음인데 필수 항목이 충족으로 확인되지 않음: {', '.join(unmet)} (모르면 undetermined)"))
    if state == "not_affected":
        if not any(status.get(k) == "not_met" for k in required):
            out.append(Violation("state_items_conflict", "영향 없음인데 증거로 미충족(not_met) 확인된 필수 항목이 없음"))
        if not (output.get("justification") or "").strip():
            out.append(Violation("justification_missing", "영향 없음인데 justification 이 비어 있음"))
    return out


def retry_message(violations: list[Violation]) -> str:
    lines = "\n".join(f"- {v}" for v in violations)
    return ("## 검증 실패\n" + lines + "\n\n위 문제를 고쳐 같은 형식으로 다시 제출하라. 도구는 더 쓸 수 없다(action=final). "
            "근거 ID는 위 자료에 나온 것만, 인용은 원문 그대로 쓴다. 증거로 확인할 수 없으면 "
            "state=undetermined 로 두고 missing_info 에 필요한 정보와 확인 위치를 적어라.")
