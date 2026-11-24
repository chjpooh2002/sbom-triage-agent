"""시연 화면. 실행: uv run streamlit run app/streamlit_app.py"""
from __future__ import annotations

from html import escape
import re
import sys
import tempfile
from collections import defaultdict
from collections.abc import Mapping
from concurrent.futures import ThreadPoolExecutor, wait
from datetime import date, datetime, timedelta
from importlib import import_module
from pathlib import Path, PureWindowsPath
from queue import Empty, Queue
from stat import S_IFDIR, S_IFMT, S_IFREG
from threading import Lock
from zipfile import BadZipFile, ZipFile

import streamlit as st
from pydantic import BaseModel

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from triage.action_view import (  # noqa: E402
    action_board, action_summary, check_summary, recheck_command, risk_summary, scan_command, shell_arg,
    team_draft, team_requests,
)
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
STYLE = Path(__file__).with_name("finals.css").read_text(encoding="utf-8")


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


def history_label(path):
    if path is None:
        return "새 점검"
    try:
        stamp = datetime.strptime(path.name, STAMP_FORMAT).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        stamp = path.name
    return f"{path.parent.name} · {stamp}"


def load_result(directory: Path):
    if (directory.absolute().parent.parent != WEB_RESULTS.absolute()
            or directory.resolve() != directory.absolute()):
        raise ValueError("저장 결과 경로가 허용되지 않습니다.")
    meta = SavedResultMeta.model_validate_json(checked_child(directory, "meta.json").read_bytes())
    bundle = TriageBundle.model_validate_json(checked_child(directory, "bundle.json").read_bytes())
    downloads = {}
    for kind, name in meta.downloads.items():
        if kind not in DOWNLOADS:
            continue
        path = checked_child(directory, name)
        if kind == "report" and not path.exists():
            continue  # 저장된 판정으로 다시 내보낼 수 있다.
        downloads[kind] = (name, path.read_bytes())
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


def work_requests_text(label: str, actions) -> str:
    """확인 필요 항목의 업무 요청서를 받는 팀별로 묶은 문서."""
    teams = team_requests(actions)
    lines = [f"# {label} 확인 요청서", "",
             "취약점 점검에서 코드만으로 영향 여부를 확정하지 못한 항목입니다. 답을 받아 판정을 확정합니다.", ""]
    for team, items in teams.items():
        lines += [f"## {team} ({len(items)}건)", "", team_draft(label, team, items), ""]
    return "\n".join(lines)


RESULT_VIEWS = ("조치하기", "판정 내역", "보고서·파일")


def reset_workspace():
    for key in ("active_action", "board_filter", "queue_desktop", "queue_mobile", "result_view", "finding_query",
                "report_export"):
        st.session_state.pop(key, None)


def change_result():
    reset_workspace()
    if st.session_state.get("finals_history") is None:
        for key in ("finals_result", "finals_stages", "finals_command", "save_notice"):
            st.session_state.pop(key, None)


def start_new_scan():
    st.session_state["finals_history"] = None
    change_result()


def choose_from(widget):
    st.session_state["active_action"] = st.session_state[widget]


def open_search_action(number):
    st.session_state["board_filter"] = "전체"
    st.session_state["active_action"] = number
    st.session_state["result_view"] = RESULT_VIEWS[0]


def show_overview(metrics, rows):
    work = metrics["오늘 할 일"]
    fixes = sum(1 for row in rows if row["영향 있음"])
    verdicts = [("영향 있음", metrics["영향 있음"], "affected"),
                ("확인 필요", metrics["확인 필요"], "pending"),
                ("영향 없음", metrics["영향 없음"], "unaffected")]
    candidates = sum(count for _, count, _ in verdicts)
    labels = "".join(f'<div class="{state}"><dt>{label}</dt><dd>{count:,}</dd></div>'
                     for label, count, state in verdicts)
    segments = "".join(f'<i class="{state}" style="flex-grow:{count}"></i>'
                       for _, count, state in verdicts if count)
    st.html(f"""
        <section class="scan-overview" aria-label="점검 요약">
          <div class="overview-group overview-work">
            <dl class="overview-total"><dt>처리할 일</dt><dd>{work:,}<small>개</small></dd></dl>
            <dl class="overview-breakdown">
              <div><dt>수정할 일</dt><dd>{fixes:,}</dd></div>
              <div><dt>확인할 일</dt><dd>{work - fixes:,}</dd></div>
            </dl>
          </div>
          <div class="overview-group overview-findings">
            <dl class="overview-total"><dt>취약점 후보</dt><dd>{candidates:,}<small>건</small></dd></dl>
            <div class="overview-distribution">
              <div class="verdict-bar" aria-hidden="true">{segments}</div>
              <dl class="overview-breakdown">{labels}</dl>
            </div>
          </div>
        </section>""")


def show_queue(rows):
    """같은 선택을 넓은 화면에서는 목록으로, 좁은 화면에서는 선택 상자로 조작한다."""
    st.html('<h3 class="queue-heading">조치 목록</h3>')
    filters = ["전체", *dict.fromkeys(r["구분"] for r in rows)]
    selected = "전체"
    if len(filters) > 2:
        selected = st.segmented_control("조치 구분", filters, default="전체", key="board_filter",
                                        format_func=lambda s: {"바로 고칠 것": "수정", "확인 필요": "확인"}.get(s, s),
                                        label_visibility="collapsed") or "전체"
    choices = [r["순서"] for r in rows if selected == "전체" or r["구분"] == selected]
    active = st.session_state.get("active_action")
    if active not in choices:
        active = choices[0]
    st.session_state["active_action"] = active
    for widget in ("queue_desktop", "queue_mobile"):
        if st.session_state.get(widget) != active:
            st.session_state[widget] = active

    def item_name(number):
        return f"{number}. {rows[number - 1]['구성요소']}"

    def queue_label(number):
        row = rows[number - 1]
        detail = "수정 대상 · " + row["근거 위치"] if row["영향 있음"] else "확인 필요 · " + row["연락할 부서"]
        return f"**{md_escape(item_name(number))}**  \n{md_escape(detail)}"

    st.radio("조치 선택", choices, index=None, format_func=queue_label, key="queue_desktop", width="stretch",
             label_visibility="collapsed", on_change=choose_from, args=("queue_desktop",))
    st.selectbox("조치 선택", choices, index=None, required=True, format_func=item_name, key="queue_mobile",
                 label_visibility="collapsed", on_change=choose_from, args=("queue_mobile",))
    return active


class ReportExport:
    """한 세션의 선택된 결과에 대해 PDF와 생성 기록을 같은 실행에서 받는다."""

    def __init__(self, directory: Path | None, bundle: TriageBundle, command: str | None, patch_name: str):
        self.directory = directory
        self.bundle = bundle if directory is None else None
        self.command = command or ""
        self.patch_name = patch_name
        self._lock = Lock()
        self._files: tuple[bytes, bytes] | None = None

    def _render(self) -> tuple[bytes, bytes]:
        from triage.output.report_pdf.saved import render_saved_report

        # Streamlit은 다운로드를 별도 스레드에서 처리한다. 실패는 캐시하지 않는다.
        with self._lock:
            if self._files is not None:
                return self._files
            try:
                with tempfile.TemporaryDirectory() as scratch:
                    out = Path(scratch) / "report.pdf"
                    if self.directory is not None:
                        source = checked_child(self.directory, "bundle.json")
                    else:
                        source = out.with_name("bundle.json")
                        source.write_text(self.bundle.model_dump_json(), encoding="utf-8")
                        names = {"patch": self.patch_name} if self.patch_name else {}
                        meta = SavedResultMeta(downloads=names, failures={}, command=self.command)
                        source.with_name("meta.json").write_text(meta.model_dump_json(), encoding="utf-8")
                    record = render_saved_report(source, out)
                    self._files = out.read_bytes(), record.read_bytes()
            except (ValueError, OSError, RuntimeError):
                raise ValueError("PDF를 만들 수 없습니다. 다시 시도하거나 보고서·파일에서 점검 기록을 확인하세요.") from None
            return self._files

    def pdf(self) -> bytes:
        return self._render()[0]

    def log(self) -> bytes:
        return self._render()[1]


def show_pdf_export(slot, directory, bundle, downloads, command):
    original = downloads.get("report")
    if directory is None and original and original[1]:
        name, data = original
        help_text = "이번 점검에서 만든 PDF 보고서를 받습니다."
    else:
        export = st.session_state.get("report_export")
        if export is None or export.directory != directory or (directory is None and export.bundle is not bundle):
            patch, contents = downloads.get("patch", ("", b""))
            export = ReportExport(directory, bundle, command, patch if contents else "")
            st.session_state["report_export"] = export
        label = directory.parent.name if directory is not None else bundle.meta.get("label", "")
        name = f"report-{label}.pdf" if isinstance(label, str) and valid_filename(label) else "report.pdf"
        data = export.pdf
        help_text = "저장된 판정으로 현재 양식의 PDF를 만들어 바로 내려받습니다."
    slot.download_button("PDF 내보내기", data, name, DOWNLOADS["report"][1], key="finals_top_report",
                         type="primary", icon=":material/download:", on_click="ignore", help=help_text)


def show_files(label, actions, downloads, fix_check, command):
    directory = st.session_state.get("finals_history")
    report, assets = st.columns([1, 1], gap="large")
    with report:
        st.subheader("보고서 공유")
        if directory and downloads.get("report", ("", b""))[1]:
            name, data = downloads["report"]
            st.download_button("점검 당시 PDF 내려받기", data, name, DOWNLOADS["report"][1],
                               key="archived_report", on_click="ignore")
        else:
            st.caption("현재 보고서는 화면 상단의 ‘PDF 내보내기’에서 받으세요.")
        if export := st.session_state.get("report_export"):
            st.download_button("보고서 재생성 기록", export.log, "report.jsonl", "application/jsonl",
                               key="export_log", on_click="ignore", help="상단에서 내보내는 PDF와 같은 실행의 기록입니다.")
        teams = team_requests(actions)
        if teams:
            st.markdown("**부서별 확인 요청서**")
            for team, items in teams.items():
                with st.expander(f"{md_escape(team)} · {len(items)}개 조치"):
                    st.code(team_draft(label, team, items), language=None, wrap_lines=True)
            st.download_button("팀별 확인 요청서 (.md) 내려받기", work_requests_text(label, actions).encode("utf-8"),
                               f"requests-{label}.md", "text/markdown", key="finals_requests")
    with assets:
        st.subheader("점검 파일")
        if downloads.get("patch", ("", b""))[1]:
            name, data = downloads["patch"]
            st.markdown("**전체 변경안**")
            st.caption("여러 항목의 수정이 함께 들어 있습니다. 적용할 내용을 확인한 뒤 소스 폴더에서 실행하세요.")
            st.download_button("전체 변경안 (.patch) 받기", data, name, DOWNLOADS["patch"][1], key="finals_top_patch")
            st.code("git apply " + shell_arg(name), language=None, wrap_lines=True)
        if actions:
            st.markdown("**전체 재점검**")
            if fix_check.get("status") == "ok":
                st.caption("전체 변경안 기준 예상 결과 · " + md_escape(check_summary(fix_check)))
            elif fix_check.get("reason"):
                st.caption(md_escape(fix_check["reason"]))
            show_recheck(command)
        for kind in ("sbom", "log"):
            title, mime = DOWNLOADS[kind]
            if kind in downloads:
                name, data = downloads[kind]
                st.download_button(title, data, name, mime, key=f"finals_download_{kind}")
            else:
                st.caption(f"{title} 파일이 생성되지 않았습니다.")


def show_recheck(command):
    if "<점검할 소스 경로>" in command:
        st.caption("명령의 <점검할 소스 경로>에 수정한 프로젝트 폴더를 넣으세요.")
    st.code(command, language=None, wrap_lines=True)


def show_search(query, findings, membership):
    hits = [f for f in findings if any(query.casefold() in name.casefold()
                                       for name in (f.component.display, *f.vulnerability.all_ids))]
    st.subheader(f"검색 결과 {len(hits)}건")
    for f in hits:
        st.markdown(f"{md_escape(finding_label(f))} · {STATE_LABELS[finding_state(f)]}")
        st.markdown(md_escape((f.verdict.rationale_ko if f.verdict else "") or reason_text(f)))
        if number := membership.get(f.key):
            st.button(f"조치 {number} 열기", key=f"hit_{f.key}", on_click=open_search_action, args=(number,))
        else:
            st.caption("영향 없음 · 별도 할 일 없음")


def show_edit(edit):
    old = escape(edit["before"])
    st.html(f'<div class="old-line">현재 줄 <code>{old}</code></div>')
    st.markdown("**바꿀 줄** · 복사해 기존 줄을 교체하세요.")
    st.code(edit["after"], language=None, wrap_lines=True)


def show_action(number, action, row, bundle, findings, evidence, command, label):
    members = [findings[k] for k in action.findings]
    lead = next((f for f in members if finding_state(f) == "affected"), findings[action.top_finding])
    affected = bool(action.counts["affected"])
    keys = set(action.findings)
    matching = [e for e in bundle.meta.get("fix_plan") or [] if not keys.isdisjoint(e.get("findings", []))]
    edits = [e for e in matching if affected and e.get("kind") == "change"
             and (not e.get("target") or e["target"] == action.target)]
    plans = [p for p in bundle.remediations if p.finding_key in keys and p.target_version == action.target]
    verified = bool(action.target and plans and all(p.verified for p in plans))
    request = action.work_request
    team = action.team or "담당 팀"
    if edits:
        edit = edits[0]
        title = f"{edit['file']} {edit['line']}행을 수정하세요"
    elif not affected:
        title = f"{team}에 확인을 요청하세요" if request else "운영 환경에서 사용 조건을 확인하세요"
    elif action.kind == "base_image":
        title = "배포에 쓰는 이미지의 교체 버전을 확인하세요"
    elif verified and not any(e.get("kind") == "manual" for e in matching):
        title = f"{lead.component.name} 버전 선언을 변경하세요"
    elif verified:
        title = f"{lead.component.name}의 변경 방법을 확인하세요"
    else:
        title = f"{lead.component.name}의 수정 버전을 먼저 확인하세요"

    badge = "수정 대상" if affected else "확인 필요"
    st.html(f'<div class="task-context"><span class="tri-badge b-{"red" if affected else "amber"}">{badge}</span>'
            f'<span>조치 {number} · {escape(action.component)}</span></div>')
    st.subheader(md_escape(title), anchor=False)
    if edits:
        with st.container(key="ready_edit"):
            show_edit(edits[0])
        if len(edits) > 1:
            with st.expander(f"함께 바꿀 위치 {len(edits) - 1}곳"):
                for edit in edits[1:]:
                    st.markdown(md_escape(f"{edit['file']} {edit['line']}행"))
                    show_edit(edit)
    elif not affected:
        if action.missing_info:
            first, *others = action.missing_info
            st.markdown(f"**확인할 내용**　{md_escape(first.what)}")
            st.markdown(f"**확인할 곳**　{md_escape(first.where)}")
            if others:
                with st.expander(f"추가 확인 항목 {len(others)}개"):
                    for item in others:
                        st.markdown(f"{md_escape(item.what)} · {md_escape(item.where)}")
        else:
            st.markdown(md_escape(request.title if request else reason_text(lead)))
            st.caption(f"점검 근거 위치 · {md_escape(row['근거 위치'])}")
    else:
        if action.target:
            target = "확인된 목표" if verified else "확인할 버전 후보"
            st.markdown(f"현재 **{md_escape(lead.component.version or '미상')}** → {target} **{md_escape(action.target)}**")
        st.caption(f"점검 근거 위치 · {md_escape(row['근거 위치'])}")
        manual = [e["reason"] for e in matching if e.get("kind") == "manual" and e.get("reason")]
        steps = [s for p in plans for s in p.steps] if verified else []
        for text in dict.fromkeys([*manual, *steps]):
            st.markdown(md_escape(text))
        if not manual and not steps:
            st.markdown("의존성 선언과 잠금 파일에서 설치 버전을 대조한 뒤 공개 권고문의 수정 버전을 확인하세요.")

    if affected:
        st.markdown("**왜 고치나요?**")
        why = risk_summary(lead)
        st.markdown(md_escape(why))
        terms = {"JWT": "로그인 상태 같은 정보를 전달하는 토큰 형식", "HTTPS": "서버의 신원을 확인하고 내용을 암호화하는 웹 통신",
                 "TLS": "통신 상대를 확인하고 데이터를 암호화하는 기술"}
        definitions = [f"{term} · {meaning}" for term, meaning in terms.items() if re.search(rf"\b{term}(?![A-Za-z])", why)]
        if definitions:
            st.caption(" / ".join(definitions))
    elif not request:
        st.caption("확인한 설정이나 배포 기록으로 영향 여부를 다시 판단하세요.")

    if request:
        mail = team_draft(label, team, [(number, action)])
        panel = st.expander(f"{md_escape(team)}에 보낼 확인 요청", expanded=not affected)
        panel.caption("메일 본문을 복사해 담당자에게 보내세요. 회신에 따른 다음 행동도 들어 있습니다.")
        panel.code(mail, language=None, wrap_lines=True, height=185)
    if affected:
        with st.expander("고친 뒤 어떻게 확인하나요?"):
            st.markdown("변경한 기능의 테스트를 실행한 뒤, 수정한 소스를 같은 범위로 다시 점검하세요.")
            show_recheck(command)
            check = bundle.meta.get("fix_check") or {}
            if check.get("status") == "ok" and isinstance(check.get("resolved"), list):
                resolved = len(keys.intersection(check["resolved"]))
                st.caption(f"전체 변경안 기준 이 조치의 예상 결과 · {len(keys)}건 중 해소 {resolved}건")
            elif check.get("reason"):
                st.caption(md_escape(check["reason"]))

    details = st.expander(f"판정 근거와 관련 취약점 {len(members)}건", key=f"details_{number}", on_change="rerun")
    if details.open:
        checklists = bundle.meta.get("checklists") or {}
        remediations = {p.finding_key: p for p in bundle.remediations}
        with details:
            if not affected:
                for edit in matching:
                    if edit.get("kind") == "manual" and edit.get("reason"):
                        st.caption("수정 시 확인할 내용 · " + md_escape(edit["reason"]))
            if action.evidence_ids:
                show_evidence(action.evidence_ids, evidence)
            for f in members:
                st.markdown(f"**{md_escape(finding_label(f))}** · {STATE_LABELS[finding_state(f)]}")
                checklist = checklists.get(f.key, {})
                show_detail(f, evidence, remediations.get(f.key), checklist if isinstance(checklist, Mapping)
                            else checklist.model_dump())


def show_results(bundle, downloads, failures, command=None) -> None:
    actions = build_actions(bundle)
    findings = {f.key: f for f in bundle.findings}
    evidence = {e.id: e for e in bundle.evidence}
    rows = action_board(actions, findings, evidence)
    conclusion, metrics = action_summary(actions, bundle.findings)
    label = bundle.meta.get("label") or "서비스"
    command = recheck_command(command or "", label)
    for item in bundle.anomalies:
        if item.kind == "judge_degraded":
            st.error(md_escape(Redactor().text(item.message)))
    if failures:
        st.warning("일부 단계 실패")
    show_overview(metrics, rows)
    work, review, files = st.tabs(RESULT_VIEWS, key="result_view", on_change="rerun")
    with work:
        if rows:
            with st.container(key="action_workspace"):
                left, right = st.columns([1, 2.12], gap="medium")
                with left.container(key="action_queue"):
                    number = show_queue(rows)
                with right.container(key="action_detail"):
                    show_action(number, actions[number - 1], rows[number - 1], bundle, findings, evidence, command, label)
        else:
            with st.container(key="empty_work"):
                if failures or bundle.meta.get("incomplete_coverage"):
                    st.subheader("점검 범위를 먼저 확인하세요")
                    st.write("일부 범위의 점검이 끝나지 않았습니다. 판정 내역에서 확인이 필요한 단계를 살펴보세요.")
                else:
                    st.subheader("현재 수정할 항목이 없습니다")
                    st.markdown(md_escape(conclusion))
    with review:
        for stage, reason in failures.items():
            st.markdown(f"{stage_label(stage)} · {md_escape(reason)}")
        limits = bundle.meta.get("limitations") or []
        for limitation in ([limits] if isinstance(limits, str) else limits):
            st.warning(md_escape(limitation))
        query = st.text_input("특정 취약점·패키지 찾기", placeholder="취약점 ID 또는 패키지 이름", key="finding_query").strip()
        if query:
            membership = {key: i for i, action in enumerate(actions, 1) for key in action.findings}
            show_search(query, bundle.findings, membership)
        if rows:
            board = st.expander(f"전체 조치 보드 {len(rows)}개", key="full_action_board", on_change="rerun")
            if board.open:
                board.dataframe(rows, hide_index=True, width="stretch")
        for item in bundle.anomalies:
            if item.kind == "instruction_like_comment":
                where = [md_escape(file_location(evidence[r])) for r in item.evidence_ids if r in evidence]
                st.warning(" · ".join(["판정을 유도하는 주석을 발견했습니다 — 근거로 쓰지 않았습니다", *dict.fromkeys(where)]))
            elif item.kind != "judge_degraded":
                st.warning(md_escape(item.message))
        unaffected = defaultdict(list)
        for f in bundle.findings:
            if finding_state(f) == "not_affected":
                unaffected[f.component.id].append(f)
        with st.expander(f"영향 없음 {metrics['영향 없음']}건"):
            for members in unaffected.values():
                first = members[0]
                st.markdown(f"{md_escape(first.component.display)} · {len(members)}건 · "
                            f"대표 사유 {md_escape(reason_text(first))}")
    with files:
        show_files(label, actions, downloads, bundle.meta.get("fix_check") or {}, command)


def finals_screen() -> None:
    try:
        history = saved_results()
    except (OSError, ValueError, RuntimeError):
        st.warning("저장된 점검 결과를 읽을 수 없습니다.")
        history = []
    live = st.session_state.get("finals_result")
    default = 1 if history and not live else 0
    initial = history[0] if default else None
    current = st.session_state.get("finals_history", initial)
    if current is not None and current not in history:
        current = initial
        st.session_state["finals_history"] = current
        reset_workspace()
    reading = current is not None or live is not None
    with st.container(key="workspace_result_header" if reading else "workspace_header"):
        if reading:
            left, right, export_slot, new = st.columns([1.25, 1.65, .8, .55], vertical_alignment="center")
            left.title("취약점 조치")
            new.button("새 점검", key="new_scan", on_click=start_new_scan)
        else:
            left, right = st.columns([3, 2], vertical_alignment="center")
            left.title("소스 코드 보안 점검")
            left.write("배포 코드의 취약점을 확인하고, 고칠 위치와 다음 행동을 찾습니다.")
        def result_name(path):
            if path is None and live:
                return f"이번 점검 · {live[0].meta.get('label') or '현재 결과'}"
            return history_label(path)

        selected = right.selectbox("저장된 결과 열기", [None, *history], index=default, key="finals_history",
                                   format_func=result_name, on_change=change_result)
    if reading:
        if selected is not None:
            try:
                bundle, downloads, failures, command = load_result(selected)
            except (OSError, ValueError, RuntimeError):
                st.warning("저장된 점검 결과를 읽을 수 없습니다.")
                return
        else:
            bundle, downloads, failures = live
            command = st.session_state.get("finals_command")
            if st.session_state.get("save_notice"):
                st.warning("이번 점검 결과를 저장할 수 없습니다.")
        show_pdf_export(export_slot, selected, bundle, downloads, command)
        show_results(bundle, downloads, failures, command=command)
        if selected is None:
            with st.expander("점검 단계 기록"):
                show_progress({stage: st.empty() for stage in STAGES}, st.session_state.get("finals_stages", {}))
        return
    try:
        finals = load_scan()
    except Exception as exc:
        show_scan_error("run", exc)
        return
    if finals is None:
        st.error("점검 실행기를 찾을 수 없습니다")
        return
    entry = st.container(key="source_entry")
    with entry.form("finals_input"):
        st.subheader("새 소스 점검")
        service = st.text_input("서비스 이름", placeholder="결과와 보고서를 식별할 이름")
        archive_col, path_col = st.columns(2, gap="large")
        upload = archive_col.file_uploader(
            f"소스 코드 ZIP (최대 {ZIP_UPLOAD_MIB} MiB)", type=["zip"], key="finals_zip",
            max_upload_size=ZIP_UPLOAD_MIB,
        )
        server_path = path_col.text_input("또는 서버의 소스 폴더 경로", placeholder="점검할 프로젝트 폴더")
        path_col.caption("ZIP과 서버 폴더 중 한 가지를 선택하세요.")
        offline = st.checkbox("오프라인 실행 (저장된 조회 결과만 사용)", value=False)
        submitted = st.form_submit_button("점검 시작", type="primary")

    stages = st.session_state.get("finals_stages", {})
    if submitted:
        reset_workspace()
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
                st.session_state["save_notice"] = True
            st.rerun()


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
    st.html(f"<style>{STYLE}</style>")
    finals, legacy = st.tabs(["본선 소스 점검", "기존 스캔 결과 분석"])
    with finals:
        finals_screen()
    with legacy:
        legacy_screen()


if __name__ == "__main__":
    main()
