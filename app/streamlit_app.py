"""시연 화면. 실행: uv run streamlit run app/streamlit_app.py"""
from __future__ import annotations

import os
import re
import shlex
import sys
import tempfile
from collections import Counter, defaultdict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import date, datetime, timedelta
from importlib import import_module
from pathlib import Path, PureWindowsPath
from queue import Empty, Queue
from stat import S_IFDIR, S_IFMT, S_IFREG
from zipfile import BadZipFile, ZipFile

import streamlit as st
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from triage.actions import build_actions  # noqa: E402
from triage.models import TriageBundle  # noqa: E402
from triage.output._common import file_location, finding_state  # noqa: E402
from triage.pipeline import run  # noqa: E402
from triage.output._redact import Redactor  # noqa: E402
from triage.report import excel  # noqa: E402
from triage.report.view import action_groups, finding_row, reasons_text, summary  # noqa: E402

SAMPLES = {
    "시연 앱 (스프링 부트 + log4j 2.14.1 전이)": ROOT / "samples" / "demo-app" / "scan",
    "형식별 입력 샘플 (fixtures)": ROOT / "samples" / "fixtures",
}

ZIP_UPLOAD_MIB = 100
ZIP_UPLOAD_LIMIT = ZIP_UPLOAD_MIB * 1024**2
ZIP_EXPANDED_LIMIT = 500 * 1024**2
ZIP_ENTRY_LIMIT = 10_000
COPY_CHUNK_SIZE = 1024**2

STAGES = {
    "collect": ("수집", "구성요소", "components"),
    "scope": ("범위", "배포 확인 대상 파일", "files"),
    "lookup": ("조회", "취약점 후보", "candidates"),
    "judge": ("판정·검증", "판정", "verdicts"),
    "enrich": ("위험 정보 보강", "후보", "candidates"),
    "priority": ("우선순위 산정", "후보", "prioritized"),
    "remediate": ("조치·검증 계획", "조치안", "remediations"),
    "cyclonedx": ("구성요소 목록 생성", "생성 파일", None),
    "pdf": ("PDF 보고서 생성", "생성 파일", None),
}
STATE_LABELS = {"affected": "영향 있음", "not_affected": "영향 없음", "undetermined": "판단 유보"}
DOWNLOADS = {
    "report": ("PDF 보고서", "application/pdf"),
    "sbom": ("구성요소 목록 (SBOM JSON)", "application/json"),
    "patch": ("변경안 (.patch)", "text/x-diff"),
    "log": ("실행 기록 (JSONL)", "application/jsonl"),
}
WEB_RESULTS = ROOT / "out" / "web"
STYLE = """
<style>
.block-container {max-width: 1320px; padding-top: 1.2rem;}
header[data-testid="stHeader"] {height: 0; min-height: 0; background: transparent;}
h1 {font-size: 1.75rem !important; padding-top: 0.4rem !important;}
[data-testid="stMetric"] {background: #f7f8fa; border: 1px solid #e3e6eb; border-radius: 14px; padding: 14px 20px;}
[data-testid="stMetricLabel"] p {font-size: 0.95rem; font-weight: 600; color: #4a4f57;}
[data-testid="stMetricValue"] {font-size: 2.6rem; font-weight: 750;}
.st-key-hero {border-left: 7px solid #d93025; background: #fff4f2; border-radius: 12px; padding: 18px 24px;}
.st-key-hero h3 {margin: 0 0 4px 0; padding: 0;}
.st-key-dev_panel, .st-key-team_panel {background: #fbfbfc; border: 1px solid #e3e6eb; border-radius: 14px; padding: 18px 22px;}
.st-key-dev_panel {border-top: 5px solid #d93025;}
.st-key-team_panel {border-top: 5px solid #1a56c4;}
.tri-badges {margin: 2px 0 10px;}
.tri-badge {display: inline-block; padding: 3px 11px; border-radius: 999px; font-size: 0.82rem; font-weight: 650; margin: 0 6px 4px 0;}
.b-red {background: #fde7e4; color: #a8221a;} .b-amber {background: #fff2cc; color: #7a5200;}
.b-blue {background: #e6efff; color: #1747a6;} .b-gray {background: #eef0f3; color: #464b53;}
.b-green {background: #e3f5e8; color: #1a6b31;}
.tri-section {font-size: 0.8rem; font-weight: 700; letter-spacing: .04em; color: #7a808a; margin: 6px 0 2px;}
[data-testid="stExpander"] details {border-radius: 12px;}
[data-testid="stExpander"] summary p {font-size: 1.02rem; font-weight: 650;}
</style>
"""
SEVERITY_LABELS = {"critical": "치명", "high": "높음", "medium": "중간", "low": "낮음"}
SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def badges(*items) -> str:
    """(문구, 색) 묶음을 배지 HTML로. 문구는 HTML로 이스케이프한다."""
    import html

    spans = "".join(f'<span class="tri-badge b-{color}">{html.escape(text)}</span>' for text, color in items if text)
    return '<div class="tri-badges">' + spans + "</div>"
STAMP_FORMAT = "%Y%m%d-%H%M%S"


class SavedResultMeta(BaseModel):
    downloads: dict[str, str]
    failures: dict[str, str]
    command: str


def valid_filename(name: str) -> bool:
    return bool(name and not name.endswith((" ", ".")) and not PureWindowsPath(name).is_reserved()
                and not any(ord(char) < 32 or char in '<>:"/\\|?*' for char in name))


def checked_child(parent: Path, name: str) -> Path:
    child = parent / name
    if not valid_filename(name) or child.resolve() != child.absolute():
        raise ValueError("저장 결과 경로가 허용되지 않습니다.")
    return child


def save_result(service, bundle, downloads, failures, command):
    service_dir = checked_child(WEB_RESULTS, service)
    service_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=service_dir) as temporary:
        pending = Path(temporary) / "result"
        pending.mkdir()
        (pending / "bundle.json").write_text(bundle.model_dump_json(), encoding="utf-8")
        names = {}
        for kind, (name, data) in downloads.items():
            if name.casefold() in {"meta.json", "bundle.json"}:
                raise ValueError("저장 파일 이름이 겹칩니다.")
            with checked_child(pending, name).open("xb") as output:
                output.write(data)
            names[kind] = name
        meta = SavedResultMeta(downloads=names, failures=failures, command=command)
        (pending / "meta.json").write_text(meta.model_dump_json(), encoding="utf-8")
        stamp = datetime.now()
        while True:
            destination = service_dir / stamp.strftime(STAMP_FORMAT)
            try:
                pending.rename(destination)
                return destination
            except OSError:
                if not destination.is_dir():
                    raise
                stamp += timedelta(seconds=1)


def saved_results() -> list[Path]:
    if not WEB_RESULTS.exists():
        return []
    if WEB_RESULTS.resolve() != WEB_RESULTS.absolute():
        raise ValueError("저장 폴더 경로가 허용되지 않습니다.")
    runs = []
    for service in WEB_RESULTS.iterdir():
        if service.resolve() != service.absolute() or not service.is_dir():
            continue
        for run_dir in service.iterdir():
            if (re.fullmatch(r"[0-9]{8}-[0-9]{6}", run_dir.name)
                    and run_dir.resolve() == run_dir.absolute() and run_dir.is_dir()):
                runs.append(run_dir)
    return sorted(runs, key=lambda path: (path.name, path.parent.name), reverse=True)


def load_result(directory: Path):
    if (directory.absolute().parent.parent != WEB_RESULTS.absolute()
            or directory.resolve() != directory.absolute()):
        raise ValueError("저장 결과 경로가 허용되지 않습니다.")
    meta = SavedResultMeta.model_validate_json(checked_child(directory, "meta.json").read_bytes())
    bundle = TriageBundle.model_validate_json(checked_child(directory, "bundle.json").read_bytes())
    downloads = {kind: (name, checked_child(directory, name).read_bytes())
                 for kind, name in meta.downloads.items() if kind in DOWNLOADS}
    return bundle, downloads, meta.failures, meta.command

# 콜론도 이스케이프해 Streamlit이 본문의 URL을 자동 링크로 읽지 않게 한다.
_MD_ESCAPES = str.maketrans({c: "\\" + c for c in r"\`*_{}[]()#+-.!|><$~:"})


def md_escape(text: str) -> str:
    """외부 문자열이 Markdown 문법으로 해석되지 않도록 한 번만 치환한다."""
    return text.translate(_MD_ESCAPES)


def extract_zip(upload, root: Path) -> Path:
    if upload.size > ZIP_UPLOAD_LIMIT:
        raise ValueError("ZIP 파일은 100 MiB까지 올릴 수 있습니다.")
    remaining = ZIP_EXPANDED_LIMIT
    root = root.resolve()
    upload.seek(0)
    with ZipFile(upload) as archive:
        members = archive.infolist()
        if not members:
            raise ValueError("ZIP 파일에 점검할 내용이 없습니다.")
        if len(members) > ZIP_ENTRY_LIMIT or sum(item.file_size for item in members) > remaining:
            raise ValueError("압축을 풀면 500 MiB 또는 10,000개 항목을 초과합니다.")
        for member in members:
            parts = member.orig_filename.replace("\\", "/").removesuffix("/").split("/")
            kind = S_IFMT(member.external_attr >> 16)
            if kind not in (0, S_IFREG, S_IFDIR) or member.flag_bits & 1:
                raise ValueError("링크, 특수 파일 또는 암호화된 파일이 들어 있는 ZIP입니다.")
            if any(
                not part or part in {".", ".."} or part.endswith((" ", "."))
                or PureWindowsPath(part).is_reserved()
                or any(ord(char) < 32 or char in '<>:"|?*' for char in part)
                for part in parts
            ):
                raise ValueError("ZIP에 허용되지 않는 파일 경로가 있습니다.")
            path = root.joinpath(*parts).resolve()
            if not path.is_relative_to(root):
                raise ValueError("ZIP에 임시 폴더를 벗어나는 경로가 있습니다.")
            if member.is_dir():
                path.mkdir(parents=True, exist_ok=True)
                continue
            path.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(member) as source, path.open("xb") as output:
                while chunk := source.read(COPY_CHUNK_SIZE):
                    remaining -= len(chunk)
                    if remaining < 0:
                        raise ValueError("압축을 푼 파일이 500 MiB를 초과합니다.")
                    output.write(chunk)
    entries = list(root.iterdir())
    return entries[0] if len(entries) == 1 and entries[0].is_dir() else root


def load_scan():
    try:
        finals = import_module("triage.finals")
    except ModuleNotFoundError as exc:
        if exc.name != "triage.finals":
            raise
        return None
    if hasattr(finals, "run_scan") and hasattr(finals, "default_judge"):
        return finals
    return None


def stage_label(stage: str) -> str:
    if stage in STAGES:
        return STAGES[stage][0]
    return {"download": "내려받기 준비"}.get(stage, "점검 실행")


def show_scan_error(stage: str, error: Exception) -> None:
    st.error(f"{stage_label(stage)} 단계 실패 · 오류 종류 {type(error).__name__}")


def show_progress(slots, stages) -> None:
    for number, (stage, (label, unit, _)) in enumerate(STAGES.items(), 1):
        status, count = stages.get(stage, ("대기", None))
        suffix = f" · {unit} {count}건" if count is not None else ""
        if stage == "judge" and isinstance(count, str):
            suffix = f" · 판정 · {count}건"
        slots[stage].text(f"{number}. {label} — {status}{suffix}")


def update_stage(stages, record) -> None:
    stage = record.get("stage")
    event = record.get("event")
    if stage == "judge" and event == "progress":
        data = record.get("data", {})
        done, total = data.get("done"), data.get("total")
        previous, _ = stages.get(stage, ("", None))
        if type(done) is int and type(total) is int and 0 <= done <= total and previous not in ("완료", "실패"):
            stages[stage] = ("진행 중", f"{done}/{total}")
        return
    if stage not in STAGES or event not in ("start", "end", "error"):
        return
    status = {"start": "진행 중", "end": "완료", "error": "실패"}[event]
    data = record.get("data", {})
    if data.get("status") in ("error", "failed") or (
        event == "end" and stages.get(stage, ("", None))[0] == "실패"
    ):
        status = "실패"
    count = data.get(STAGES[stage][2])
    if stage == "judge" and isinstance(count, Mapping):
        count = sum(value for value in count.values() if type(value) is int and value >= 0)
    stages[stage] = (status, count if type(count) is int and count >= 0 else None)


def show_evidence(ids, evidence) -> None:
    from triage.output._common import public_url

    for evidence_id in dict.fromkeys(ids):
        item = evidence.get(evidence_id)
        if item is None:
            st.caption(f"{md_escape(evidence_id)} · 근거를 찾을 수 없습니다.")
            continue
        location = item.file
        if location and item.line_start is not None:
            location += f":{item.line_start}"
            if item.line_end and item.line_end > item.line_start:
                location += f"–{item.line_end}"
        st.caption(f"{md_escape(item.id)} · {md_escape(location or item.note or '파일 위치 없음')}")
        if item.snippet:
            st.code(item.snippet, language=None)
        if url := public_url(item.url):
            st.link_button("근거 원문", url)


def finding_label(finding) -> str:
    return f"{finding.component.display} · {finding.vulnerability.id}"


def show_detail(finding, evidence, remediation, checklist) -> None:
    from triage.output._common import public_url

    verdict = finding.verdict
    explanation = reason_text(finding)
    st.markdown(md_escape(explanation))
    if verdict and verdict.rationale_ko and verdict.rationale_ko != explanation:
        st.markdown(md_escape(verdict.rationale_ko))
    if finding.component.evidence_ids:
        st.markdown("**설치 버전·배포 근거**")
        show_evidence(finding.component.evidence_ids, evidence)

    st.markdown("**문제가 생기는 조건**")
    questions = {item["key"]: item["question"] for item in checklist.get("items", [])}
    answers = {item.item_key: item for item in verdict.item_results} if verdict else {}
    if not questions and not answers:
        st.caption("기록된 조건이 없습니다.")
    for key in dict.fromkeys([*questions, *answers]):
        answer = answers.get(key)
        status = {"met": "충족", "not_met": "미충족"}.get(
            answer.status if answer else "", "확인 필요",
        )
        st.markdown(f"{md_escape(questions.get(key, key))} — {status}")
        if answer:
            if answer.reason:
                st.caption(md_escape(answer.reason))
            show_evidence(answer.evidence_ids, evidence)

    references = dict.fromkeys(filter(None, map(public_url, finding.vulnerability.references)))
    for index, url in enumerate(references, 1):
        st.link_button(f"공개 권고문 {index}", url)

    if verdict and verdict.missing_info:
        st.markdown("**추가 확인**")
        for item in verdict.missing_info:
            st.markdown(f"{md_escape(item.what)} · 확인할 곳 {md_escape(item.where)}")
    if remediation:
        st.markdown("**조치 방법**")
        if remediation.target_version:
            st.markdown(f"올릴 버전 {md_escape(remediation.target_version)}")
        for line in filter(None, [remediation.summary_ko, *remediation.steps, remediation.workaround]):
            st.markdown(md_escape(line))
        st.markdown("**검증 방법과 결과**")
        st.markdown("목표 버전 확인 완료" if remediation.verified else "목표 버전 확인 필요")
        for note in remediation.verify_notes:
            st.markdown(md_escape(note))
    elif not verdict or verdict.state != "not_affected":
        st.caption("기록된 조치·검증 방법이 없습니다.")
    if verdict and verdict.work_request:
        request = verdict.work_request
        st.markdown("**업무 요청 초안**")
        st.caption("초안 오른쪽 위 복사 버튼으로 내용을 복사할 수 있습니다.")
        st.code("\n".join([f"받는 팀 {request.to_team}", request.title, "", request.body,
                           *request.branches]), language=None)


def reason_text(finding):
    verdict = finding.verdict
    return ((verdict.plain_ko or verdict.rationale_ko) if verdict else "") or finding.status_note or "판정 설명이 없습니다."


def scan_command(label: str, source: str, offline: bool = False) -> str:
    """고친 뒤 다시 점검하는 명령. PDF 보고서의 '다시 실행' 명령과 같은 형식이다."""
    def quote(value):
        if os.name == "nt":
            return value if re.fullmatch(r"[\w./-]+", value) else "'" + value.replace("'", "''") + "'"
        return shlex.quote(value)

    options = ["--offline"] if offline else []
    return " ".join(["uv run triage scan", *options, "--", *map(quote, (label, source or "./source", "out/recheck"))])


LEGACY_COMMAND = re.compile(r"^triage scan (?P<args>.+) (?:'\./out'|\./out)$")


def recheck_command(command: str) -> str:
    # 예전 저장본은 'triage scan 라벨 경로 ./out' 형식이라 결과 폴더를 덮어쓴다.
    if match := LEGACY_COMMAND.match(command):
        return f"uv run triage scan -- {match['args']} out/recheck"
    return command


def team_requests(actions):
    teams = defaultdict(list)
    for index, action in enumerate(actions, 1):
        if action.work_request:
            teams[action.team or "담당 팀 미정"].append((index, action))
    return teams


def team_draft(label: str, team: str, items) -> str:
    """받는 팀에 바로 보낼 수 있는 메일 초안."""
    lines = [f"제목: [{label} 취약점 점검] 영향 확인 요청 {len(items)}건", "",
             f"{team} 담당자님, 안녕하세요.",
             f"{label} 서비스의 오픈소스 취약점을 점검했는데, 아래 항목은 소스 코드만으로는 영향 여부를 확정할 수 없어 "
             "운영 정보 확인을 부탁드립니다. 답변에 따라 바로 업그레이드하거나 조치 불필요로 기록하겠습니다.", ""]
    for number, (index, action) in enumerate(items, 1):
        request = action.work_request
        lines += [f"{number}. {request.title} (할 일 {index} · {action.component})", request.body]
        lines += [f"   - {branch}" for branch in request.branches]
        lines.append("")
    lines.append("확인 후 회신 부탁드립니다. 감사합니다.")
    return "\n".join(lines)


def work_requests_text(label: str, actions) -> str:
    """확인 필요 항목의 업무 요청서를 받는 팀별로 묶은 문서."""
    teams = defaultdict(list)
    for index, action in enumerate(actions, 1):
        if action.work_request:
            teams[action.team or "담당 팀 미정"].append((index, action))
    lines = [f"# {label} 확인 요청서", "",
             "취약점 점검에서 코드만으로 영향 여부를 확정하지 못한 항목입니다. 답을 받아 판정을 확정합니다.", ""]
    for team, items in teams.items():
        lines += [f"## {team} ({len(items)}건)", ""]
        for index, action in items:
            request = action.work_request
            lines += [f"### 할 일 {index}. {request.title}", "", request.body, ""]
            lines += [f"- {branch}" for branch in request.branches]
            lines.append("")
    return "\n".join(lines)


def action_board(actions, findings, evidence):
    """조치를 고르기 위해 먼저 보는 값을 한 줄씩 모은 표."""
    rows = []
    for index, action in enumerate(actions, 1):
        members = [findings[key] for key in action.findings if key in findings]
        levels = [f.vulnerability.severity.lower() for f in members]
        top = next((level for level in SEVERITY_ORDER if level in levels), "")
        where = next((file_location(evidence[r]) for r in action.evidence_ids
                      if r in evidence and evidence[r].file), "")
        affected, pending = action.counts["affected"], action.counts["undetermined"]
        if affected and action.work_request:
            todo = "변경안 적용 + 확인 요청"
        elif affected:
            todo = "변경안 적용"
        elif action.work_request:
            todo = "확인 요청 보내기"
        else:
            todo = "영향 조건 확인"
        rows.append({
            "순서": index,
            "구분": "바로 고칠 것" if affected else "확인 필요",
            "구성요소": action.component,
            "목표": action.target or "확인 후 결정",
            "영향 있음": affected,
            "확인 필요": pending,
            "최고 심각도": SEVERITY_LABELS.get(top, "미상"),
            "근거 위치": where,
            "연락할 부서": action.team or ("개발자 직접" if affected else "-"),
            "다음 행동": todo,
        })
    return rows


def show_next_steps(label, actions, downloads, fix_check, command) -> None:
    """분석 결과 바로 다음에 무엇을 할지, 단계마다 필요한 파일·명령과 함께 보여 준다."""
    st.subheader("지금 할 일")
    teams = team_requests(actions)
    if teams:
        left, right = st.columns([1, 1], gap="large")
    else:
        left, right = st.container(), None
    number = 0

    def step(box, text):
        nonlocal number
        number += 1
        box.markdown(f"**{number}. {text}**")

    dev = left.container(key="dev_panel")
    dev.markdown('<div class="tri-section">개발자가 할 일</div>', unsafe_allow_html=True)
    if "patch" in downloads:
        name, data = downloads["patch"]
        plain = name.replace("`", "")
        step(dev, "변경안 적용")
        dev.markdown(f"변경안을 받아 소스 폴더에서 `git apply {plain}`로 적용하고 이미지를 다시 빌드합니다.")
        dev.download_button(f"{DOWNLOADS['patch'][0]} 내려받기", data, name, DOWNLOADS["patch"][1],
                            key="finals_top_patch", type="primary")
    elif actions:
        step(dev, "코드 수정")
        dev.markdown("아래 '바로 고칠 것' 카드의 '어떻게 고치나'대로 선언을 고치고 이미지를 다시 빌드합니다.")
    if actions:
        step(dev, "다시 점검")
        if fix_check.get("status") == "ok":
            before = fix_check.get("before_candidates") or len(fix_check["resolved"]) + len(fix_check["remaining"])
            after = fix_check.get("after_candidates") or len(fix_check["remaining"]) + len(fix_check["new"])
            dev.markdown(f"고친 소스로 아래 명령을 실행합니다. 변경안 기준 예상 결과: 후보 {before}건 → {after}건 "
                         f"(해소 {len(fix_check['resolved'])} · 남음 {len(fix_check['remaining'])} · "
                         f"새로 생김 {len(fix_check['new'])})")
        else:
            dev.markdown("고친 소스로 아래 명령을 실행해 해소 여부를 확인합니다.")
        dev.code(command, language=None, wrap_lines=True)
    if "report" in downloads:
        name, data = downloads["report"]
        step(dev, "결과 공유")
        dev.markdown("판정 근거가 모두 담긴 보고서를 보안 담당자·팀장에게 공유합니다.")
        dev.download_button(f"{DOWNLOADS['report'][0]} 내려받기", data, name, DOWNLOADS["report"][1],
                            key="finals_top_report", type="secondary" if "patch" in downloads else "primary")
    if right is None:
        return
    panel = right.container(key="team_panel")
    pending = sum(len(items) for items in teams.values())
    panel.markdown('<div class="tri-section">연락할 부서 · 메일 초안 준비됨</div>', unsafe_allow_html=True)
    panel.markdown(f"**확인 요청 보내기** · 코드만으로 영향을 확정하지 못한 항목의 요청서 {pending}건을 "
                   f"{len(teams)}개 부서에 보내고, 답이 오면 카드의 분기대로 처리합니다.")
    panel.markdown(badges(*((f"{team} {len(items)}건", "blue") for team, items in teams.items())),
                   unsafe_allow_html=True)
    for tab, (team, items) in zip(panel.tabs([f"{team} ({len(group)})" for team, group in teams.items()]), teams.items()):
        tab.caption("오른쪽 위 복사 버튼으로 메일에 그대로 붙여 넣을 수 있습니다.")
        tab.code(team_draft(label, team, items), language=None, height=320, wrap_lines=True)
    panel.download_button("팀별 확인 요청서 (.md) 내려받기", work_requests_text(label, actions).encode("utf-8"),
                          f"requests-{label}.md", "text/markdown", key="finals_requests")


def show_search(query, findings, membership):
    hits = []
    for f in findings:
        names = [f.component.display, *f.vulnerability.all_ids]
        if any(query.casefold() in name.casefold() for name in names):
            hits.append(f)
    st.subheader(f"검색 결과 {len(hits)}건")
    matched = set()
    for f in hits:
        st.markdown(f"{md_escape(finding_label(f))} · {STATE_LABELS[finding_state(f)]}")
        st.markdown(md_escape((f.verdict.rationale_ko if f.verdict else "") or reason_text(f)))
        if index := membership.get(f.key):
            matched.add(index)
            st.markdown(f"[할 일 {index}로 이동](#action-{index})")
        else:
            st.caption("영향 없음 · 별도 할 일 없음")
    return matched


def show_card(action, index, expanded, findings, evidence, plans, checklists, command, fix_plan, fix_check):
    top = findings[action.top_finding]
    st.markdown(f'<div id="action-{index}" style="scroll-margin-top:4rem"></div>', unsafe_allow_html=True)
    members = [findings[key] for key in action.findings]
    kind = {"upgrade": "업그레이드", "base_image": "기본 이미지", "confirm": "확인 필요"}[action.kind]
    if action.kind == "base_image":
        current = ", ".join(dict.fromkeys(f.component.declared_spec or f.component.display for f in members))
    else:
        current = top.component.display if top.component.version else f"{top.component.display} (버전 미상)"
    target = action.target or ("영향 확인 후 결정" if action.kind == "confirm" else "목표 버전 확인 필요")
    title = f"{index}. {kind} · {md_escape(current)} → {md_escape(target)} · 관련 취약점 {len(members)}건"
    with st.expander(title, expanded=expanded):
        st.markdown(badges(
            (f"영향 있음 {action.counts['affected']}건" if action.counts["affected"] else "", "red"),
            (f"확인 필요 {action.counts['undetermined']}건" if action.counts["undetermined"] else "", "amber"),
            (f"연락할 부서 {action.team}" if action.team else ("직접 수정" if action.counts["affected"] else ""), "blue"),
        ), unsafe_allow_html=True)
        left, right = st.columns(2, gap="large")
        with left:
            st.markdown("**무슨 일이 생기나**")
            # 대표 후보가 확인 필요이면 설명이 확인 지시문이 되므로, 영향 있음 판정의 설명을 먼저 쓴다.
            lead = next((f for f in members if finding_state(f) == "affected"), top)
            st.markdown(md_escape(reason_text(lead)))
            st.markdown("**어디서**")
            if action.evidence_ids:
                show_evidence(action.evidence_ids, evidence)
            else:
                st.caption("대표 후보에 연결된 근거가 없습니다.")

        with right:
            st.markdown("**무엇을 확인하나**" if action.kind == "confirm" else "**어떻게 고치나**")
            if action.kind == "confirm":
                for item in action.missing_info:
                    st.markdown(f"{md_escape(item.what)} · 확인할 곳 {md_escape(item.where)}")
                if not action.missing_info:
                    st.caption("추가 확인 항목이 기록되지 않았습니다.")
            finding_keys = set(action.findings)
            matching = [item for item in fix_plan if not finding_keys.isdisjoint(item["findings"])]
            if matching:
                if action.kind == "confirm":
                    st.markdown("**어떻게 고치나**")
                for item in matching:
                    if item["kind"] == "change":
                        st.caption(f"{md_escape(item['file'])}:{item['line']}")
                        st.code(f"-{item['before']}\n+{item['after']}", language="diff")
                    elif item["kind"] == "manual":
                        st.markdown(f"수동 확인 · {md_escape(item['reason'])}")
            elif action.kind != "confirm":
                if action.target:
                    st.markdown(f"교체 목표 {md_escape(action.target)}")
                relevant = [plans[f.key] for f in members if f.key in plans and plans[f.key].target_version == action.target]
                if relevant:
                    steps = dict.fromkeys(step for plan in relevant for step in plan.steps)
                    if steps:
                        st.markdown("\n".join(f"{i}. {md_escape(step)}" for i, step in enumerate(steps, 1)))
                    if not all(plan.verified for plan in relevant):
                        st.caption("목표 버전 확인 필요")
                else:
                    fixes = dict.fromkeys(v for f in members for v in f.vulnerability.fixed_versions)
                    st.caption("목표 버전 확인 필요 · 조회된 수정 버전 " + (", ".join(map(md_escape, fixes)) or "없음"))
            st.markdown("**고친 뒤 확인**")
            if fix_check.get("status") == "ok":
                resolved = len(set(action.findings) & set(fix_check["resolved"]))
                st.markdown(f"변경안 적용 시 이 항목 {len(action.findings)}건 중 해소 **{resolved}건** · "
                            f"남음 **{len(action.findings) - resolved}건**")
            elif reason := fix_check.get("reason"):
                st.caption(md_escape(reason))
            st.code(command, language=None)
        st.markdown("**누구에게**")
        if request := action.work_request:
            st.markdown(f"받는 팀 **{md_escape(action.team)}** · {md_escape(request.title)}")
            st.caption("질문과 답별 처리 방법은 위 '연락할 부서'의 메일 초안에 들어 있습니다.")
        elif action.counts["undetermined"] == 0:
            st.caption("모두 영향 있음으로 확정되어 확인 요청 없이 바로 고치면 됩니다.")
        else:
            st.caption("대표 판정에 지정된 팀과 업무 요청서가 없습니다.")
        details = st.expander(f"포함된 취약점 {len(action.findings)}건", key=f"details_{index}", on_change="rerun")
        if details.open:
            with details:
                for key in action.findings:
                    finding = findings[key]
                    st.markdown(f"{md_escape(finding_label(finding))} · {STATE_LABELS[finding_state(finding)]}")
                    checklist = checklists.get(key, {})
                    if not isinstance(checklist, Mapping):
                        checklist = checklist.model_dump()
                    show_detail(finding, evidence, plans.get(key), checklist)


def show_results(bundle, downloads, failures, command=None) -> None:
    actions = build_actions(bundle)
    counts = Counter(map(finding_state, bundle.findings))
    for anomaly in bundle.anomalies:
        if anomaly.kind == "judge_degraded":
            st.error(md_escape(Redactor().text(anomaly.message)))
    metrics = [("오늘 할 일", len(actions)), ("영향 있음", counts["affected"]),
               ("확인 필요", counts["undetermined"]), ("영향 없음", counts["not_affected"])]
    # 한 화면에 결론과 숫자가 같이 보이도록 윗줄을 결론(왼쪽)과 지표 2×2(오른쪽)로 나눈다.
    top_left, top_right = st.columns([3, 2], gap="large", vertical_alignment="center")
    tiles = [*top_right.columns(2), *top_right.columns(2)]
    for column, (label, value) in zip(tiles, metrics):
        column.metric(label, value)

    if counts["affected"]:
        conclusion = f"먼저 고칠 것은 {md_escape(actions[0].component)}입니다."
    elif actions:
        conclusion = f"먼저 확인할 것은 {md_escape(actions[0].component)}의 영향 조건입니다."
    elif bundle.findings:
        conclusion = "모든 후보가 영향 없음으로 판정되어 먼저 확인할 것이 없습니다."
    else:
        conclusion = "취약점 후보가 없어 먼저 확인할 것은 이번 점검의 수집·조회 범위입니다."
    evidence = {e.id: e for e in bundle.evidence}
    findings = {f.key: f for f in bundle.findings}
    fix_check = bundle.meta.get("fix_check", {})
    hero = top_left.container(key="hero")
    hero.markdown(f"### {conclusion}")
    if actions:
        first = actions[0]
        where = next((file_location(evidence[r]) for r in first.evidence_ids if r in evidence and evidence[r].file), "")
        solved = len(set(first.findings) & set(fix_check.get("resolved", [])))
        hero.markdown(badges(
            (f"{first.component} → {first.target}" if first.target else "", "gray"),
            (f"영향 있음 {first.counts['affected']}건" if first.counts["affected"] else "", "red"),
            (f"확인 필요 {first.counts['undetermined']}건" if first.counts["undetermined"] else "", "amber"),
            (f"근거 {where}" if where else "", "gray"),
            (f"변경안 적용 시 {solved}건 해소" if solved else "", "green"),
            (f"연락할 부서 {first.team}" if first.team else "", "blue"),
        ), unsafe_allow_html=True)
    label = bundle.meta.get("label") or "서비스"
    command = recheck_command(command or scan_command(label, ""))
    if actions:
        st.subheader("조치 보드")
        st.caption("조치를 고를 때 보는 값: 영향 있음 여부 → 근거 위치 → 목표 버전 → 연락할 부서. 위에서부터 우선순위입니다.")
        import pandas as pd

        tone = {"바로 고칠 것": "background-color:#fde7e4;color:#a8221a;font-weight:650",
                "확인 필요": "background-color:#fff2cc;color:#7a5200;font-weight:650"}
        board = pd.DataFrame(action_board(actions, findings, evidence))
        st.dataframe(
            board.style.map(lambda value: tone.get(value, ""), subset=["구분"]),
            hide_index=True, use_container_width=True, height=min(38 + 35 * len(board), 420),
            column_config={
                "순서": st.column_config.NumberColumn(width=48),
                "구분": st.column_config.TextColumn(width=100),
                "구성요소": st.column_config.TextColumn(width=150),
                "목표": st.column_config.TextColumn(width=110),
                "영향 있음": st.column_config.ProgressColumn(
                    min_value=0, max_value=max(a.counts["affected"] for a in actions) or 1, format="%d건", width=110),
                "확인 필요": st.column_config.NumberColumn(format="%d건", width=72),
                "최고 심각도": st.column_config.TextColumn(width=80),
                "근거 위치": st.column_config.TextColumn(width=170),
                "연락할 부서": st.column_config.TextColumn(width=120),
                "다음 행동": st.column_config.TextColumn(width=160),
            },
        )
    show_next_steps(label, actions, downloads, fix_check, command)
    query = st.text_input("특정 취약점·패키지 찾기", placeholder="CVE, GHSA 또는 패키지 이름").strip()
    if failures:
        st.warning("일부 단계 실패")
        for stage, reason in failures.items():
            st.markdown(f"{stage_label(stage)} · {md_escape(reason)}")
    for limitation in bundle.meta.get("limitations", []):
        st.warning(md_escape(limitation))
    membership = {key: index for index, action in enumerate(actions, 1) for key in action.findings}
    matched = show_search(query, bundle.findings, membership) if query else set()
    plans = {r.finding_key: r for r in bundle.remediations}
    checklists = bundle.meta.get("checklists", {})
    fix_plan = bundle.meta.get("fix_plan", [])
    numbered = list(enumerate(actions, 1))
    fix_now = [(i, a) for i, a in numbered if a.counts["affected"]]
    confirm = [(i, a) for i, a in numbered if not a.counts["affected"]]
    for title, group in ((f"바로 고칠 것 {len(fix_now)}개", fix_now), (f"확인이 필요한 것 {len(confirm)}개", confirm)):
        if not group:
            continue
        st.subheader(title)
        for index, action in group:
            show_card(action, index, index == 1 or index in matched, findings, evidence, plans, checklists, command,
                      fix_plan, fix_check)

    other_anomalies = [item for item in bundle.anomalies if item.kind != "judge_degraded"]
    if other_anomalies:
        st.subheader("주의 신호")
        for item in other_anomalies:
            if item.kind in {"instruction_like_comment", "stage_failure"}:
                label = ("판정을 유도하는 주석을 발견했습니다 — 근거로 쓰지 않았습니다"
                         if item.kind == "instruction_like_comment" else md_escape(item.message))
                locations = [md_escape(file_location(evidence[r])) for r in item.evidence_ids if r in evidence]
                st.warning(" · ".join(filter(None, [label, *dict.fromkeys(locations)])))
            else:
                st.markdown(md_escape(item.message))
    unaffected = defaultdict(list)
    for f in bundle.findings:
        if finding_state(f) == "not_affected":
            unaffected[f.component.id].append(f)
    with st.expander(f"영향 없음 {counts['not_affected']}건"):
        for members in unaffected.values():
            first = members[0]
            st.markdown(f"{md_escape(first.component.display)} · {len(members)}건 · "
                        f"대표 사유 {md_escape(reason_text(first))}")

    st.subheader("기록용 파일")
    for kind, (label, mime) in DOWNLOADS.items():
        if kind in ("patch", "report") and kind in downloads:
            continue  # 위 '지금 할 일'에서 내려받는다.
        if kind in downloads:
            name, data = downloads[kind]
            st.download_button(label, data, name, mime, key=f"finals_download_{kind}")
        elif kind != "patch":
            st.caption(f"{label} 파일이 생성되지 않았습니다.")
    st.caption("PDF 보고서와 변경안은 위 '지금 할 일'에서 내려받습니다.")


def finals_screen() -> None:
    st.title("소스 코드 보안 점검")
    st.caption("소스에서 사용 중인 구성요소를 찾고, 서비스에 영향이 있는지 확인합니다.")
    try:
        history = saved_results()
    except (OSError, ValueError, RuntimeError):
        st.warning("저장된 점검 결과를 읽을 수 없습니다.")
        history = []
    selected = st.selectbox("저장된 결과 열기", [None, *history], key="finals_history",
                            format_func=lambda p: f"{p.parent.name} · {p.name}" if p else "새 점검")
    if selected is not None:
        try:
            restored = load_result(selected)
        except (OSError, ValueError, RuntimeError):
            st.warning("저장된 점검 결과를 읽을 수 없습니다.")
        else:
            show_results(*restored)
        return
    try:
        finals = load_scan()
    except Exception as exc:
        show_scan_error("run", exc)
        return
    if finals is None:
        st.error("점검 실행기를 찾을 수 없습니다")
        return
    with st.form("finals_input"):
        service = st.text_input("서비스 이름")
        upload = st.file_uploader(
            f"소스 코드 ZIP (최대 {ZIP_UPLOAD_MIB} MiB)", type=["zip"],
            max_upload_size=ZIP_UPLOAD_MIB,
        )
        server_path = st.text_input("또는 서버의 소스 폴더 경로")
        offline = st.checkbox("오프라인 실행 (저장된 조회 결과만 사용)", value=False)
        submitted = st.form_submit_button("점검 시작", type="primary")

    stages = st.session_state.get("finals_stages", {})
    if submitted:
        st.session_state.pop("finals_result", None)
        stages = {}
        st.session_state["finals_stages"] = stages
    if submitted:
        box = st.container()
        box.subheader("진행 상황")
    elif stages:
        box = st.expander("점검 단계 기록", expanded=False)
    else:
        box = st.empty().container()
    slots = {stage: box.empty() for stage in STAGES}
    if submitted or stages:
        show_progress(slots, stages)

    active_stage = "run"

    def drain(events):
        nonlocal active_stage
        changed = False
        while True:
            try:
                record = events.get_nowait()
            except Empty:
                break
            stage, event = record.get("stage"), record.get("event")
            if stage in STAGES and event in ("start", "error", "end", "progress"):
                if event in ("start", "error"):
                    active_stage = stage
                update_stage(stages, record)
                changed = True
        if changed:
            show_progress(slots, stages)

    if submitted:
        service = service.strip()
        has_upload = upload is not None
        if not service or has_upload == bool(server_path.strip()):
            st.error("서비스 이름과 소스 ZIP 또는 서버 폴더 경로 중 하나를 입력해 주세요.")
            return
        if not valid_filename(service):
            st.error("서비스 이름에 파일 경로 구분자나 특수 문자를 사용할 수 없습니다.")
            return
        with tempfile.TemporaryDirectory(prefix="triage-finals-") as directory:
            temporary = Path(directory)
            try:
                if upload is not None:
                    root = extract_zip(upload, temporary / "source")
                else:
                    root = Path(server_path.strip()).expanduser().resolve(strict=True)
                    if not root.is_dir():
                        raise ValueError("서버 경로에 소스 폴더를 지정해 주세요.")
            except ValueError as exc:
                st.error(str(exc))
                return
            except (OSError, BadZipFile, RuntimeError, NotImplementedError):
                st.error("소스를 열 수 없습니다. ZIP 내용 또는 서버 폴더 경로와 권한을 확인해 주세요.")
                return

            out = temporary / "output"
            out.mkdir()
            with st.spinner("점검 중…"):
                try:
                    active_stage = "judge"
                    judge = finals.default_judge()
                    active_stage = "run"
                    events = Queue()
                    with ThreadPoolExecutor(max_workers=1) as worker:
                        future = worker.submit(finals.run_scan, service, root, out, offline=offline,
                                               judge=judge, on_event=events.put)
                        while not future.done():
                            wait([future], timeout=0.3)
                            drain(events)
                        drain(events)
                        result = future.result()
                except Exception as exc:
                    if active_stage in STAGES:
                        stages[active_stage] = ("실패", None)
                    show_progress(slots, stages)
                    show_scan_error(active_stage, exc)
                    return

            redactor = Redactor((str(root), str(temporary)))
            failures = {stage: redactor.text(reason) for stage, reason in result.failures.items()}
            for stage in failures.keys() & STAGES.keys():
                stages[stage] = ("실패", stages.get(stage, ("", None))[1])
            downloads = {}
            for kind in DOWNLOADS.keys() & result.paths.keys():
                try:
                    path = (out / result.paths[kind]).resolve(strict=True)
                    if not path.is_relative_to(out.resolve()):
                        raise ValueError("산출물 경로가 출력 폴더를 벗어납니다.")
                    downloads[kind] = (path.name, path.read_bytes())
                except (OSError, ValueError, RuntimeError) as exc:
                    show_scan_error("download", exc)
            for stage, kind in (("cyclonedx", "sbom"), ("pdf", "report")):
                if kind in downloads and stage not in failures and stages.get(stage) == ("완료", None):
                    stages[stage] = ("완료", 1)
            show_progress(slots, stages)
            command = scan_command(service, str(root) if not has_upload else "", offline)
            st.session_state["finals_command"] = command
            st.session_state["finals_result"] = (result.bundle, downloads, failures)
            try:
                save_result(service, result.bundle, downloads, failures, command)
            except (OSError, ValueError, RuntimeError):
                st.warning("이번 점검 결과를 저장할 수 없습니다.")
            else:
                st.rerun()

    if result := st.session_state.get("finals_result"):
        show_results(*result, command=st.session_state.get("finals_command"))


def sample_inputs(path: Path) -> list[str]:
    if path.name == "fixtures":
        return [str(path / "assets.csv"), str(path / "sbom.cdx.json"), str(path / "grype.json"),
                f"{path / 'trivy.json'}=SVC-001", f"{path / 'osv.json'}=SVC-001"]
    return [str(path)]


def legacy_screen() -> None:
    with st.expander("분석 입력과 설정", expanded=True):
        st.header("입력")
        mode = st.radio("데이터", ["샘플", "파일 올리기"], horizontal=True)
        inputs: list[str] = []
        if mode == "샘플":
            avail = {k: v for k, v in SAMPLES.items() if v.exists()}
            if avail:
                choice = st.selectbox("샘플", list(avail))
                inputs = sample_inputs(avail[choice])
            else:
                st.warning("샘플 폴더가 없습니다")
        else:
            files = st.file_uploader("SBOM·스캔 결과(JSON)·자산 목록(xlsx/csv)", accept_multiple_files=True)
            asset = st.text_input("스캔 결과를 연결할 자산 ID (선택, 자동 매칭이 안 될 때)")
            if files:
                tmp = Path(tempfile.mkdtemp(prefix="triage-"))
                for f in files:
                    p = tmp / f.name
                    p.write_bytes(f.getvalue())
                    is_table = p.suffix.lower() in (".csv", ".xlsx", ".xls", ".tsv")
                    inputs.append(str(p) if is_table or not asset else f"{p}={asset}")
        st.header("설정")
        provider = st.selectbox("조치안 생성", ["template", "anthropic", "openai"],
                                help="키가 없거나 호출이 실패하면 template 으로 대체됩니다")
        llm_limit = st.slider("모델 호출 최대 묶음 수", 1, 50, 10)
        offline = st.checkbox("오프라인(레지스트리 조회 안 함)", value=False)
        as_of = st.date_input("기한 기준일", value=date.today())
        go = st.button("분석 실행", type="primary", disabled=not inputs)

    st.title("SW 공급망 스캐닝 에이전트")
    st.caption("SBOM·취약점 스캔 결과 → KEV·EPSS·자산 맥락으로 결정적 우선순위 → AI 조치안(목표 버전 규칙 재검증) → 한국어 보고서")

    if go:
        with st.spinner("분석 중…"):
            st.session_state["res"] = run(inputs, None, provider, llm_limit, offline, as_of)

    res = st.session_state.get("res")
    if not res:
        st.info("위에서 데이터를 고르고 '분석 실행'을 누르세요.")
        return

    import pandas as pd

    b, pol = res.bundle, res.policy
    s = summary(b)
    intel, rem = b.meta["intel"], b.meta["remediation"]
    for w in b.meta.get("warnings", []) + intel["warnings"] + rem["warnings"]:
        st.warning(w)

    c = st.columns(6)
    c[0].metric("취약점", s["findings"])
    c[1].metric("P1 긴급", s["tiers"]["P1"])
    c[2].metric("P2 높음", s["tiers"]["P2"])
    c[3].metric("KEV 등재", s["kev"])
    c[4].metric("조치 단위", s["groups"])
    c[5].metric("버전 검증 통과", f"{s['groups_verified']}/{s['groups']}")
    st.caption(f"정책 {pol.name} `{pol.fingerprint}` · KEV {intel['kev']['date'] or intel['kev']['origin']} · "
               f"EPSS {intel['epss']['date'] or intel['epss']['origin']} · 조치안 {rem['provider']}({rem['model']}) "
               f"호출 {rem['llm_calls']} / 캐시 {rem['llm_cache_hits']} / 대체 {rem['fallbacks']} / 제안 기각 {rem['rejected_targets']}")

    tab1, tab2, tab3 = st.tabs(["조치 계획", "취약점 목록", "보고서"])
    groups = action_groups(b)
    with tab1:
        df = pd.DataFrame([{"순서": g.order, "등급": g.tier.value, "기한": g.due_date, "서비스": g.service,
                            "구성요소": g.component, "현재": g.installed, "목표": g.target,
                            "검증": "✔" if g.verified else "✘", "해결 건수": len(g.vuln_ids), "KEV": ", ".join(g.kev_ids)}
                           for g in groups])
        st.dataframe(df, hide_index=True, use_container_width=True)
        for g in groups:
            with st.expander(f"{g.order}. [{g.tier.value}] {g.component} {g.installed} → {g.target or '-'} · {g.service}"):
                rm = g.remediation
                if rm:
                    st.markdown(rm.summary_ko)
                    st.markdown("\n".join(f"{i}. {x}" for i, x in enumerate(rm.steps, 1)))
                    st.markdown(f"**임시 완화책**: {rm.workaround}")
                    (st.success if rm.verified else st.error)("목표 버전 검증: " + "; ".join(rm.verify_notes))
                    st.caption(f"작성: {rm.provider}{' (모델 실패로 대체)' if rm.fallback_used else ''}")
                for r, f in g.findings:
                    st.markdown(f"**{f.vulnerability.id}** · {r.tier.value} · 점수 {r.score:.3f} · {r.layer} 계층")
                    st.code("\n".join(reasons_text(r)), language=None)
    with tab2:
        rows = pd.DataFrame(sorted((finding_row(r, f, b) for g in groups for r, f in g.findings), key=lambda x: x["순위"]))
        tiers = st.multiselect("등급", ["P1", "P2", "P3", "P4"], default=["P1", "P2", "P3", "P4"])
        st.dataframe(rows[rows["등급"].isin(tiers)], hide_index=True, use_container_width=True)
    with tab3:
        st.download_button("마크다운 내려받기", res.report_md.encode("utf-8"), "report.md", "text/markdown")
        st.download_button("엑셀 내려받기", excel.to_bytes(b, pol), "report.xlsx",
                           "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
        st.markdown(res.report_md)


def main() -> None:
    st.set_page_config(page_title="SW 공급망 스캐닝 에이전트", layout="wide")
    st.markdown(STYLE, unsafe_allow_html=True)
    finals, legacy = st.tabs(["본선 소스 점검", "기존 스캔 결과 분석"])
    with finals:
        finals_screen()
    with legacy:
        legacy_screen()


if __name__ == "__main__":
    main()
