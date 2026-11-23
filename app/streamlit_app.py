"""시연 화면. 실행: uv run streamlit run app/streamlit_app.py"""
from __future__ import annotations

import sys
import tempfile
from datetime import date
from pathlib import Path

import pandas as pd
import streamlit as st

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from triage.pipeline import run  # noqa: E402
from triage.report import excel  # noqa: E402
from triage.report.view import action_groups, finding_row, reasons_text, summary  # noqa: E402

st.set_page_config(page_title="SW 공급망 스캐닝 에이전트", layout="wide")

SAMPLES = {
    "시연 앱 (스프링 부트 + log4j 2.14.1 전이)": ROOT / "samples" / "demo-app" / "scan",
    "형식별 입력 샘플 (fixtures)": ROOT / "samples" / "fixtures",
}


def sample_inputs(path: Path) -> list[str]:
    if path.name == "fixtures":
        return [str(path / "assets.csv"), str(path / "sbom.cdx.json"), str(path / "grype.json"),
                f"{path / 'trivy.json'}=SVC-001", f"{path / 'osv.json'}=SVC-001"]
    return [str(path)]


with st.sidebar:
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
    st.info("왼쪽에서 데이터를 고르고 '분석 실행'을 누르세요.")
    st.stop()

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
