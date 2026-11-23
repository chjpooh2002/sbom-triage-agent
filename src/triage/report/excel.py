"""엑셀 보고서: 요약 / 조치계획 / 취약점목록 / 판단근거 시트."""
from __future__ import annotations

from io import BytesIO
from pathlib import Path
from typing import Optional

from openpyxl import Workbook
from openpyxl.styles import Alignment, Font, PatternFill
from openpyxl.utils import get_column_letter

from ..models import TriageBundle
from ..priority.policy import Policy
from .view import action_groups, finding_row, reasons_text, summary

TIER_FILL = {"P1": "F8CBAD", "P2": "FCE4D6", "P3": "FFF2CC", "P4": "E2EFDA"}
HEAD = PatternFill("solid", fgColor="305496")


def _sheet(ws, rows: list[dict], widths: Optional[dict] = None, tier_col: str = "등급"):
    if not rows:
        ws.append(["(해당 없음)"])
        return
    cols = list(rows[0])
    ws.append(cols)
    for c in ws[1]:
        c.font, c.fill, c.alignment = Font(bold=True, color="FFFFFF"), HEAD, Alignment(horizontal="center", vertical="center")
    for r in rows:
        ws.append([r[c] for c in cols])
        if tier_col in r and r[tier_col] in TIER_FILL:
            ws.cell(ws.max_row, cols.index(tier_col) + 1).fill = PatternFill("solid", fgColor=TIER_FILL[r[tier_col]])
    ws.freeze_panes = "A2"
    ws.auto_filter.ref = ws.dimensions
    for i, c in enumerate(cols, 1):
        width = (widths or {}).get(c) or min(60, max(8, max(len(str(r[c] or "")) for r in rows[:200]) + 2, len(c) * 2 + 2))
        ws.column_dimensions[get_column_letter(i)].width = width
    for row in ws.iter_rows(min_row=2):
        for c in row:
            c.alignment = Alignment(wrap_text=True, vertical="top")


def build(b: TriageBundle, pol: Policy) -> Workbook:
    s = summary(b)
    groups = action_groups(b)
    wb = Workbook()
    ws = wb.active
    ws.title = "요약"
    intel = b.meta.get("intel", {})
    lines = [("SW 공급망 취약점 조치 보고서", ""), ("기한 기준일", s["as_of"]), ("판단 정책", f"{pol.name} {pol.fingerprint}"),
             ("KEV 기준", intel.get("kev", {}).get("date") or intel.get("kev", {}).get("origin", "-")),
             ("EPSS 기준", intel.get("epss", {}).get("date") or intel.get("epss", {}).get("origin", "-")),
             ("취약점", s["findings"]), ("구성요소", s["components"]), ("KEV 등재", s["kev"]), ("7일 이내 기한", s["due_within_7"]),
             ("조치 단위(구성요소)", s["groups"]), ("목표 버전 검증 완료", s["groups_verified"])]
    lines += [(f"{t} 건수", n) for t, n in s["tiers"].items()]
    lines += [(f"서비스: {k}", v) for k, v in s["services"].items()]
    for k, v in lines:
        ws.append([k, v])
    ws["A1"].font = Font(bold=True, size=14)
    ws.column_dimensions["A"].width, ws.column_dimensions["B"].width = 24, 40

    _sheet(wb.create_sheet("조치계획"), [{
        "순서": g.order, "등급": g.tier.value, "기한": g.due_date, "서비스": g.service, "구성요소": g.component,
        "현재 버전": g.installed, "목표 버전": g.target, "검증": "통과" if g.verified else "미통과",
        "의존": "직접" if g.direct else "전이" if g.direct is False else "모름", "해결 취약점": ", ".join(g.vuln_ids),
        "KEV": ", ".join(g.kev_ids), "조치 요약": g.remediation.summary_ko if g.remediation else "",
        "조치 단계": "\n".join(f"{i}. {x}" for i, x in enumerate(g.remediation.steps, 1)) if g.remediation else "",
        "임시 완화책": g.remediation.workaround if g.remediation else "",
        "검증 메모": "; ".join(g.remediation.verify_notes) if g.remediation else ""} for g in groups],
        widths={"조치 요약": 60, "조치 단계": 70, "검증 메모": 50, "해결 취약점": 30})
    rows = sorted((finding_row(r, f, b) for g in groups for r, f in g.findings), key=lambda x: x["순위"])
    _sheet(wb.create_sheet("취약점목록"), rows)
    _sheet(wb.create_sheet("판단근거"), [{"순위": r.rank, "등급": r.tier.value, "취약점": f.vulnerability.id,
                                        "구성요소": f.component.display, "근거": "\n".join(reasons_text(r))}
                                       for g in groups for r, f in g.findings], widths={"근거": 100})
    return wb


def to_bytes(b: TriageBundle, pol: Policy) -> bytes:
    buf = BytesIO()
    build(b, pol).save(buf)
    return buf.getvalue()


def write(b: TriageBundle, pol: Policy, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    build(b, pol).save(path)
