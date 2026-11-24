"""웹과 인쇄 보고서가 공유하는 개발자용 표시 값. 판정이나 우선순위를 바꾸지 않는다."""
from __future__ import annotations

import os
import re
import shlex
from collections import Counter, defaultdict
from pathlib import Path, PureWindowsPath
from typing import TYPE_CHECKING

from .output._common import file_location, finding_state
from .output._redact import Redactor

if TYPE_CHECKING:
    from .actions import Action
    from .models import Evidence, Finding

SEVERITY = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음"}


def action_summary(actions: list[Action], findings: list[Finding]) -> tuple[str, dict[str, int]]:
    counts = Counter(map(finding_state, findings))
    metrics = {"오늘 할 일": len(actions), "영향 있음": counts["affected"],
               "확인 필요": counts["undetermined"], "영향 없음": counts["not_affected"]}
    if counts["affected"]:
        conclusion = f"먼저 고칠 것은 {actions[0].component}입니다."
    elif actions:
        conclusion = f"먼저 확인할 것은 {actions[0].component}의 영향 조건입니다."
    elif findings:
        conclusion = "모든 후보가 영향 없음으로 판정되어 먼저 확인할 것이 없습니다."
    else:
        conclusion = "취약점 후보가 없어 먼저 확인할 것은 이번 점검의 수집·조회 범위입니다."
    return conclusion, metrics


def action_board(actions: list[Action], findings: dict[str, Finding], evidence: dict[str, Evidence]) -> list[dict]:
    rows = []
    for index, action in enumerate(actions, 1):
        levels = {findings[key].vulnerability.severity.lower() for key in action.findings}
        severity = next((name for level, name in SEVERITY.items() if level in levels), "미상")
        sources = [evidence[r] for r in action.evidence_ids if r in evidence and evidence[r].file]
        source = next((e for e in sources if e.line_start is not None), next(iter(sources), None))
        affected = action.counts["affected"]
        if affected:
            todo = "변경안 적용 + 확인 요청" if action.work_request else "변경안 적용"
        else:
            todo = "확인 요청 보내기" if action.work_request else "영향 조건 확인"
        rows.append({
            "순서": index, "구분": "바로 고칠 것" if affected else "확인 필요",
            "구성요소": action.component, "목표": action.target or "확인 후 결정",
            "영향 있음": affected, "확인 필요": action.counts["undetermined"], "최고 심각도": severity,
            "근거 위치": file_location(source) if source else "위치 미기록",
            "연락할 부서": action.team or ("개발자 직접" if affected else "담당 팀 미정"), "다음 행동": todo,
        })
    return rows


def risk_summary(finding: Finding) -> str:
    """영향 있음 판정에서 변경 지시와 분리한 위험 설명을 가져온다."""
    verdict = finding.verdict
    if not verdict or verdict.state != "affected":
        return finding.status_note or "영향 여부를 확인할 정보가 더 필요합니다."
    for text in filter(None, [verdict.plain_ko, verdict.rationale_ko, finding.status_note]):
        # 위험 설명과 지시가 한 문장이면 원문에서 결과에 해당하는 절만 남긴다.
        clause = re.search(r"(.*?)(?:있으므로|있으니|있어서|있어[, ])", text)
        if clause and "수 " in clause[1]:
            return clause[1].rstrip() + " 있습니다."
        sentences = re.split(r"(?<=[.!?])\s+", text)
        factual = [part for part in sentences if not re.search(
            r"(?:하세요|십시오|합니다만|해야 합니다|바랍니다|권장합니다|권고합니다|해 주세요)[.!?]?$", part)]
        if factual:
            return " ".join(factual[:2])
    return "이 버전에서 권고문의 영향 조건이 충족된 것으로 판정했습니다."


def team_requests(actions: list[Action]) -> dict[str, list[tuple[int, Action]]]:
    teams = defaultdict(list)
    for index, action in enumerate(actions, 1):
        if action.work_request:
            teams[action.team or "담당 팀 미정"].append((index, action))
    return dict(teams)


def team_draft(label: str, team: str, items: list[tuple[int, Action]]) -> str:
    lines = [f"제목: [{label} 취약점 점검] 영향 확인 요청 {len(items)}건", "",
             f"{team} 담당자님, 안녕하세요.",
             "운영 환경에서 아래 조건에 해당하는지 확인 후 회신 부탁드립니다.", ""]
    for index, action in items:
        request = action.work_request
        lines.extend([f"할 일 {index} · {action.component} | {request.title}", request.body])
        lines.extend(f"• {branch}" for branch in request.branches)
        lines.append("")
    lines.append("회신 내용을 근거로 판정과 조치 계획을 갱신하겠습니다. 감사합니다.")
    return Redactor().text("\n".join(lines))


def shell_arg(value: str) -> str:
    if os.name != "nt":
        return shlex.quote(value)
    if re.fullmatch(r"[\w./-]+", value):
        return value
    return "'" + re.sub("[‘’‚‛']", lambda m: m[0] * 2, value) + "'"


def scan_command(label: str, source: str, offline: bool = False) -> str:
    source = source or "<점검할 소스 경로>"
    path = Path(source)
    if path.is_absolute():
        cwd = Path.cwd()
        source = (Path(os.path.relpath(path, cwd)).as_posix()
                  if path.is_relative_to(cwd.parent) else "<점검할 소스 경로>")
    elif PureWindowsPath(source).is_absolute():
        source = "<점검할 소스 경로>"
    args = ["uv", "run", "triage", "scan"]
    if offline:
        args.append("--offline")
    args.extend(["--", label, source, "out/recheck"])
    return " ".join(map(shell_arg, args))


def saved_scan_args(command: str) -> dict:
    # 명령을 실행하거나 보고서에 그대로 삽입하지 않고 알려진 인자만 복원한다.
    if os.name == "nt":
        pattern = r"'(?:[^']|'')*'|[\w./-]+"
        args = re.findall(pattern, command)
        if " ".join(args) != command:
            return {}
        args = [arg[1:-1].replace("''", "'") if arg.startswith("'") else arg for arg in args]
    else:
        try:
            args = shlex.split(command)
        except ValueError:
            return {}
    if args[:4] == ["uv", "run", "triage", "scan"]:
        args = args[4:]
        offline = args[:1] == ["--offline"]
        args = args[1:] if offline else args
        if args[:1] != ["--"]:
            return {}
        args = args[1:]
    elif args[:2] == ["triage", "scan"]:
        offline, args = False, args[2:]
    else:
        return {}
    if len(args) != 3 or args[2] not in ("./out", "out/recheck"):
        return {}
    return {"label": args[0], "scan_source": args[1], "scan_offline": offline}


def recheck_command(command: str, label: str) -> str:
    args = saved_scan_args(command)
    return scan_command(args.get("label") or label, args.get("scan_source", ""), args.get("scan_offline", False))


def check_summary(check: dict) -> str:
    if check.get("status") != "ok":
        return check.get("reason") or "재점검 결과 미기록"
    counts = {}
    for key in ("resolved", "remaining", "new"):
        value = check.get(key)
        counts[key] = len(value) if isinstance(value, list) else value
    if not all(type(value) is int for value in counts.values()):
        return "재점검 후보 수 미기록"
    before = check.get("before_candidates")
    after = check.get("after_candidates")
    before = before if before is not None else counts["resolved"] + counts["remaining"]
    after = after if after is not None else counts["remaining"] + counts["new"]
    return (f"후보 {before}건 → {after}건 "
            f"(해소 {counts['resolved']} · 남음 {counts['remaining']} · 새로 생김 {counts['new']})")
