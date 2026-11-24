"""시연 화면. 실행: uv run streamlit run app/streamlit_app.py"""
from __future__ import annotations

import sys
import tempfile
from collections.abc import Mapping
from datetime import date
from importlib import import_module
from pathlib import Path, PureWindowsPath
from stat import S_IFDIR, S_IFMT, S_IFREG
from zipfile import BadZipFile, ZipFile

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "app"))

from finals_preview import preview_scan  # noqa: E402
from triage.output._common import public_url  # noqa: E402
from triage.pipeline import run  # noqa: E402
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
    "collect": ("수집", "구성요소"),
    "scope": ("범위", "배포 확인 대상"),
    "lookup": ("조회", "취약점 후보"),
    "judge": ("판정", "판정"),
    "verify": ("검증", "검증"),
    "report": ("보고서", "생성 파일"),
}
GROUPS = {
    "affected": "지금 고칠 것 (영향 있음)",
    "not_affected": "안 고쳐도 되는 것과 이유 (영향 없음)",
    "undetermined": "확인이 필요한 것 (판단 유보)",
}
DOWNLOADS = {
    "pdf": ("PDF 보고서", "application/pdf"),
    "sbom": ("구성요소 목록 (SBOM JSON)", "application/json"),
    "log": ("실행 기록 (JSONL)", "application/jsonl"),
}


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
        return preview_scan, True
    scan = getattr(finals, "run_scan", None)
    return (scan, False) if scan is not None else (preview_scan, True)


def show_progress(slots, stages) -> None:
    for stage, (label, unit) in STAGES.items():
        status, count = stages.get(stage, ("대기", None))
        suffix = f" · {unit} {count}건" if count is not None else ""
        slots[stage].text(f"{label} — {status}{suffix}")


def update_stage(stages, record) -> None:
    stage = record.get("stage")
    event = record.get("event")
    if stage not in STAGES or event not in ("start", "end", "error"):
        return
    status = {"start": "진행 중", "end": "완료", "error": "실패"}[event]
    count = record.get("data", {}).get("count")
    stages[stage] = (status, count if type(count) is int and count >= 0 else None)


def final_groups(bundle):
    priorities = {result.finding_key: result for result in bundle.results}

    def ordering(finding):
        priority = priorities.get(finding.key)
        if priority is None:
            return (float("inf"), float("inf"), 0, finding.key)
        return (priority.tier.rank, priority.rank or float("inf"), -priority.score, finding.key)

    groups = {state: [] for state in GROUPS}
    for finding in sorted(bundle.findings, key=ordering):
        state = finding.verdict.state if finding.verdict else "undetermined"
        groups.get(state, groups["undetermined"]).append(finding)
    return groups


def show_evidence(ids, evidence) -> None:
    for evidence_id in dict.fromkeys(ids):
        item = evidence.get(evidence_id)
        if item is None:
            st.text(f"{evidence_id} · 근거를 찾을 수 없습니다.")
            continue
        location = item.file
        if location and item.line_start is not None:
            location += f":{item.line_start}"
            if item.line_end and item.line_end > item.line_start:
                location += f"–{item.line_end}"
        st.text(f"{item.id} · {location or item.note or '파일 위치 없음'}")
        if item.snippet:
            st.code(item.snippet, language=None)
        if url := public_url(item.url):
            st.link_button("근거 원문", url)


def finding_label(finding) -> str:
    return f"{finding.component.display} · {finding.vulnerability.id}"


def show_detail(finding, evidence, remediation, checklist) -> None:
    verdict = finding.verdict
    explanation = (verdict.plain_ko or verdict.rationale_ko) if verdict else ""
    st.text(explanation or finding.status_note or "판정 설명이 없습니다.")
    if verdict and verdict.rationale_ko and verdict.rationale_ko != explanation:
        st.text(verdict.rationale_ko)
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
        st.text(f"{questions.get(key, key)} — {status}")
        if answer:
            if answer.reason:
                st.text(answer.reason)
            show_evidence(answer.evidence_ids, evidence)

    references = dict.fromkeys(filter(None, map(public_url, finding.vulnerability.references)))
    for index, url in enumerate(references, 1):
        st.link_button(f"공개 권고문 {index}", url)

    if verdict and verdict.missing_info:
        st.markdown("**추가 확인**")
        for item in verdict.missing_info:
            st.text(f"{item.what} · 확인할 곳 {item.where}")
    if remediation:
        st.markdown("**조치 방법**")
        if remediation.target_version:
            st.text(f"올릴 버전 {remediation.target_version}")
        for line in filter(None, [remediation.summary_ko, *remediation.steps, remediation.workaround]):
            st.text(line)
        st.markdown("**검증 방법과 결과**")
        st.text("목표 버전 확인 완료" if remediation.verified else "목표 버전 확인 필요")
        for note in remediation.verify_notes:
            st.text(note)
    elif not verdict or verdict.state != "not_affected":
        st.caption("기록된 조치·검증 방법이 없습니다.")
    if verdict and verdict.work_request:
        request = verdict.work_request
        st.markdown("**업무 요청 초안**")
        st.caption("초안 오른쪽 위 복사 버튼으로 내용을 복사할 수 있습니다.")
        st.code("\n".join([f"받는 팀 {request.to_team}", request.title, "", request.body,
                           *request.branches]), language=None)


def show_results(bundle, downloads) -> None:
    groups = final_groups(bundle)
    st.subheader("먼저 고칠 것 3개")
    if not groups["affected"]:
        st.info("영향이 확인된 항목이 없습니다.")
    for index, finding in enumerate(groups["affected"][:3], 1):
        st.text(f"{index}. {finding_label(finding)}")

    evidence = {item.id: item for item in bundle.evidence}
    remediations = {item.finding_key: item for item in bundle.remediations}
    checklists = bundle.meta.get("checklists", {})
    for state, title in GROUPS.items():
        findings = groups[state]
        st.subheader(f"{title} · {len(findings)}건")
        if not findings:
            st.caption("해당 항목이 없습니다.")
        for finding in findings:
            with st.expander(finding_label(finding)):
                checklist = checklists.get(finding.key, {})
                if not isinstance(checklist, Mapping):
                    checklist = checklist.model_dump()
                show_detail(finding, evidence, remediations.get(finding.key), checklist)

    st.subheader("내려받기")
    for kind, (label, mime) in DOWNLOADS.items():
        if kind in downloads:
            name, data = downloads[kind]
            st.download_button(label, data, name, mime, key=f"finals_download_{kind}")
        else:
            st.caption(f"{label} 파일이 생성되지 않았습니다.")


def finals_screen() -> None:
    st.title("소스 코드 보안 점검")
    st.caption("소스에서 사용 중인 구성요소를 찾고, 서비스에 영향이 있는지 확인합니다.")
    scan, preview = load_scan()
    if preview:
        st.warning("화면 예시 모드입니다. 입력을 실제로 점검하지 않으며 결과와 파일은 예시입니다.")
    with st.form("finals_input"):
        service = st.text_input("서비스 이름")
        upload = st.file_uploader(
            f"소스 코드 ZIP (최대 {ZIP_UPLOAD_MIB} MiB)", type=["zip"],
            max_upload_size=ZIP_UPLOAD_MIB,
        )
        server_path = st.text_input("또는 서버의 소스 폴더 경로")
        submitted = st.form_submit_button("점검 시작", type="primary")

    st.subheader("진행 상황")
    columns = st.columns(3)
    slots = {stage: columns[index % len(columns)].empty() for index, stage in enumerate(STAGES)}
    stages = st.session_state.get("finals_stages", {})
    if submitted:
        st.session_state.pop("finals_result", None)
        stages = {}
        st.session_state["finals_stages"] = stages
    show_progress(slots, stages)

    def on_event(record):
        update_stage(stages, record)
        show_progress(slots, stages)

    if submitted:
        service = service.strip()
        has_upload = upload is not None
        if not service or has_upload == bool(server_path.strip()):
            st.error("서비스 이름과 소스 ZIP 또는 서버 폴더 경로 중 하나를 입력해 주세요.")
            return
        if service in {".", ".."} or any(ord(char) < 32 or char in '<>:"/\\|?*' for char in service):
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
                    # 본선 통합 계약: (TriageBundle, 산출물 경로 매핑, JSONL 이벤트 목록).
                    bundle, artifacts, events = scan(service, root, out, on_event=on_event)
                    for event in events:
                        update_stage(stages, event)
                    downloads = {}
                    for kind in DOWNLOADS.keys() & artifacts.keys():
                        path = (out / artifacts[kind]).resolve(strict=True)
                        if not path.is_relative_to(out.resolve()):
                            raise ValueError("산출물 경로가 출력 폴더를 벗어납니다.")
                        downloads[kind] = (path.name, path.read_bytes())
                    st.session_state["finals_result"] = (bundle, downloads)
                except Exception:
                    for stage, (status, _) in stages.items():
                        if status == "진행 중":
                            stages[stage] = ("실패", None)
                    st.error("점검을 완료하지 못했습니다. 서버에서 점검 실행 설정을 확인해 주세요.")
                show_progress(slots, stages)

    if result := st.session_state.get("finals_result"):
        show_results(*result)


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
    finals, legacy = st.tabs(["본선 소스 점검", "기존 스캔 결과 분석"])
    with finals:
        finals_screen()
    with legacy:
        legacy_screen()


if __name__ == "__main__":
    main()
