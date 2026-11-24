"""근거와 조치 계획을 한국어 PDF로 내보낸다."""
import re
import unicodedata
from collections import Counter, defaultdict
from collections.abc import Callable, Iterable
from datetime import datetime, timedelta, timezone
from pathlib import Path, PurePosixPath, PureWindowsPath
from urllib.parse import urlsplit

from jinja2 import Environment

from triage import action_view
from triage.models import Evidence, Finding, TriageBundle

from .._common import (
    artifact_evidence, file_location, finding_evidence, finding_state, public_url, write_artifact,
)
from .._redact import Redactor
from ._engines import render_with_engine


_DIRECTORY = Path(__file__).parent
_STATES = {"affected": "영향 있음", "undetermined": "판단 유보", "not_affected": "영향 없음"}
_DEPLOYMENT = {"yes": "배포됨", "no": "배포되지 않음", "unknown": "확인되지 않음"}
_CONDITIONS = {"met": "충족", "not_met": "미충족", "unknown": "확인되지 않음", "assumed": "전제"}
_FILE_SCOPE = {"yes": "배포됨", "no": "미배포", "unknown": "배포 미확인"}
_SNAPSHOT_DATE = re.compile(r"^data/cache/lookup/(\d{4}-\d{2}-\d{2})/")
_LOOKUP_NAMES = {
    "api.osv.dev": "OSV", "osv.dev": "OSV",
    "services.nvd.nist.gov": "NVD", "nvd.nist.gov": "NVD",
    "www.cisa.gov": "CISA KEV", "www.first.org": "FIRST EPSS",
}


# A4 인쇄용 표시 한도. 원문과 초과 항목은 부록에 둔다.
LIMIT = dict(board=8, cards=3, plans=8, teams=3, ranges=3, snippet_lines=3,
             summary_chars=100, team_lines=10, team_columns=92, command_columns=160,
             board_component=31, board_location=32, board_team=22, plan_text=85, citation_ids=8,
             badge=24, range=26, id=34, label=48, location=64, condition=80, line=90,
             sentence=120, risk=165, question=185, branches=3)
_FILE_TYPES = {"app": "앱", "legacy": "이전 코드", "test": "테스트", "config": "설정",
               "script": "스크립트", "generated": "생성 파일", "vendored_bundle": "번들", "other": "기타"}


def _folders(bundle: TriageBundle) -> list[dict]:
    folders = defaultdict(list)
    for file in sorted(bundle.files, key=lambda item: item.path):
        path = PurePosixPath(file.path.replace("\\", "/"))
        folders[path.parent.as_posix()].append({"name": path.name, "deployed": file.deployed,
                                                "category": file.category, "evidence_ids": file.evidence_ids})
    return [{"path": path, "files": files, "counts": Counter(f["deployed"] for f in files)}
            for path, files in folders.items()]


def _lookup_sources(bundle: TriageBundle, meta: dict) -> list[dict]:
    sources = {}
    for evidence in bundle.evidence:
        if not evidence.id.startswith("lookup-") or not public_url(evidence.url):
            continue
        host = urlsplit(evidence.url).hostname
        name = _LOOKUP_NAMES.get(host, host)
        source = sources.setdefault(name, {"url": evidence.url, "dates": set()})
        if match := _SNAPSHOT_DATE.match(evidence.file.replace("\\", "/")):
            source["dates"].add(match[1])
    if epss := sources.get("FIRST EPSS"):
        epss["dates"].update(
            item.signals.epss_date for item in bundle.findings if item.signals.epss_date
        )
    records = meta.get("lookup_sources")
    if isinstance(records, (list, tuple)):
        for record in records:
            name = record.get("name") if isinstance(record, dict) else None
            if not isinstance(name, str) or not name:
                continue
            source = sources.setdefault(name, {"url": "", "dates": set()})
            if url := record.get("url"):
                source["url"] = url
            if retrieved_at := record.get("retrieved_at"):
                source["retrieved_at"] = retrieved_at
    return [
        {**source, "name": name, "dates": sorted(source["dates"])}
        for name, source in sorted(sources.items())
    ]


def _link_label(url: str) -> str:
    parts = urlsplit(url)
    if parts.hostname == "github.com" and "/advisories/" in parts.path:
        return "GHSA"
    return _LOOKUP_NAMES.get(parts.hostname, parts.hostname or "")


def _references(urls: Iterable[str]) -> list[str]:
    preferred = {"OSV": 0, "GHSA": 0, "NVD": 1}
    links = dict.fromkeys(filter(None, map(public_url, urls)))
    return sorted(links, key=lambda url: preferred.get(_link_label(url), 2))


def _reason(finding: Finding, state: str) -> str:
    verdict = finding.verdict
    if verdict and (verdict.rationale_ko or verdict.plain_ko):
        return verdict.rationale_ko or verdict.plain_ko
    if finding.status_note:
        return finding.status_note
    if verdict and (reason := next((item.reason for item in verdict.item_results if item.reason), "")):
        return reason
    if state == "not_affected":
        if finding.version_in_range is False:
            return "설치 버전이 권고문의 영향 범위 밖입니다."
        if finding.component.deployed == "no":
            return finding.component.deployed_reason or "배포 범위에 포함되지 않습니다."
    return "판정 사유가 기록되지 않았습니다."


def _compact(text: str, length: int) -> str:
    one_line = " ".join(text.split())
    return one_line if len(one_line) <= length else one_line[:length - 1].rstrip() + "…"


def _text_width(text: str) -> int:
    return sum(2 if unicodedata.east_asian_width(char) in {"W", "F"} else 1 for char in text)


def _local_time(value: str) -> str:
    try:
        instant = datetime.fromisoformat(value)
    except ValueError:
        return value
    if instant.tzinfo is None:
        return instant.strftime("%Y-%m-%d %H:%M")
    return instant.astimezone(timezone(timedelta(hours=9))).strftime("%Y-%m-%d %H:%M (한국 시각)")


def _summary_text(text: str, columns: int, *, tail: bool = False) -> str:
    text = " ".join(text.split())
    if _text_width(text) <= columns:
        return text
    # 파일 위치는 뒤쪽의 파일 이름·줄 번호를 우선 보존한다.
    chars = []
    space = columns - 1
    for char in reversed(text) if tail else text:
        space -= _text_width(char)
        if space < 0:
            break
        chars.append(char)
    return "…" + "".join(reversed(chars)) if tail else "".join(chars).rstrip() + "…"


def _scan_command(meta: dict) -> str:
    return action_view.scan_command(meta.get("label") or "재점검", meta.get("scan_source") or "",
                                    bool(meta.get("scan_offline")))


def _decision(finding, by_id):
    verdict = finding.verdict
    state = finding_state(finding)
    conditions = verdict.item_results if verdict else []
    ids = list(dict.fromkeys([r for item in conditions for r in item.evidence_ids] + finding_evidence(finding)))
    evidence = [by_id[r] for r in ids if r in by_id]
    locations = [e for e in evidence if e.file and e.line_start is not None]
    if verdict and verdict.decided_by == "rule:not_deployed":
        locations.sort(key=lambda e: not e.id.startswith("scope-"))
    elif state == "affected":
        # 같은 판정이 인용한 근거 중 호출·설정을 좁은 줄 범위로 특정한 곳을 우선한다.
        locations.sort(key=lambda e: (not e.snippet, e.kind not in {"code", "config"},
                                      (e.line_end or e.line_start) - e.line_start))
    source = next(iter(locations), None)
    links = _references([*finding.vulnerability.references, *(e.url for e in evidence if e.url)])
    missing = verdict.missing_info if verdict else []
    unknown = next((i.reason for i in conditions if i.status == "unknown" and i.reason), "")
    reason = _reason(finding, state)
    # 사유에 들어간 인용 괄호는 색인과 중복된다. 설치 조건이나 일반 괄호 설명은 유지한다.
    def citation(match):
        references = re.split(r"[,;\s]+", match[1].strip())
        return "" if all(ref in by_id for ref in references) else match[0]

    summary = re.sub(r"\s*[\[(]([^()\[\]]+)[\])]", citation, reason)
    c = finding.component
    return {
        "id": finding.vulnerability.id, "component": c.display, "version": c.version,
        "deployment": _DEPLOYMENT.get(c.deployed, _DEPLOYMENT["unknown"]), "state": state,
        "reason": reason, "summary": summary, "ranges": finding.vulnerability.affected_ranges,
        "in_range": finding.version_in_range,
        "location": file_location(source) if source else "", "source_ref": source.id if source else next(iter(ids), ""),
        "snippet": source.snippet if source else "", "link": next(iter(links), ""),
        "refs": ids, "conditions": [i.model_dump() for i in conditions],
        "condition": unknown or reason,
        "what": " / ".join(dict.fromkeys(m.what for m in missing if m.what)) or "기능의 실제 사용 및 운영 환경의 설정",
        "where": " / ".join(dict.fromkeys(m.where for m in missing if m.where))
                 or (file_location(source) if source else "배포 설정과 호출 코드"),
    }


def _action_plan(action, members, matching_edits, plans, decisions):
    affected = [f for f in members if finding_state(f) == "affected"]
    lead = affected[0] if affected else members[0]
    matching = [plans[f.key] for f in members if f.key in plans and plans[f.key].target_version == action.target]
    steps = list(dict.fromkeys(s for p in matching for s in p.steps))
    edit = next((e for e in matching_edits if e.get("kind") == "change"), None)
    manual = next((e.get("reason") for e in matching_edits if e.get("kind") == "manual"), None)
    verified = bool(matching) and all(p.verified for p in matching)
    target = action.target or "확인 후 결정"
    target_label = ("목표 버전 " + target if verified else "목표 버전 후보 " + target + " (확인 필요)") if action.target else target
    if action.kind == "confirm":
        method = manual or "담당 부서에 영향 조건을 확인합니다."
        verify = "회신을 근거로 영향 여부를 재판정합니다."
    elif action.kind == "base_image":
        method = manual or "배포 이미지의 태그와 다이제스트를 확인하고 교체합니다."
        verify = "빌드한 이미지의 런타임 버전과 서비스 기동을 확인합니다."
    else:
        method = manual or next(iter(steps), "의존성 선언과 잠금 파일을 갱신합니다.")
        verify = "설치 버전을 대조하고 변경 경로의 회귀 테스트를 실행합니다."
    if edit and action.kind != "confirm":
        method = f"{edit['file']}:{edit['line']} 선언 변경"
    return {
        "component": action.component, "affected": bool(affected), "target": target, "target_label": target_label,
        "ids": [f.vulnerability.id for f in affected], "lead": decisions[lead.key],
        "risk": action_view.risk_summary(lead) if affected else "", "edits": matching_edits, "edit": edit,
        "method": method, "verify": verify, "steps": steps,
    }


def _citations(used, by_id):
    # 같은 실제 위치나 권고문은 한 번만 출력하되 원래 근거 ID를 모두 보존한다.
    groups = defaultdict(list)
    for ref in sorted(used):
        item = by_id.get(ref)
        url = public_url(item.url) if item else ""
        location = file_location(item) if item and (item.line_start is not None or not url) else ""
        groups[(location, url)].append(ref)
    entries, numbers = [], {}
    for (loc, url), ids in sorted(groups.items()):
        width = LIMIT["citation_ids"] if loc or url else len(ids)
        for start in range(0, len(ids), width):
            refs = ids[start:start + width]
            number = len(numbers) + 1
            entries.append({"n": number, "location": loc, "url": url, "ids": refs, "unlocated": not (loc or url)})
            numbers.update((ref, i) for i, ref in enumerate(refs, number))
    return entries, numbers


def _mail_views(label, actions):
    mails = []
    for team, items in action_view.team_requests(actions).items():
        draft = action_view.team_draft(label, team, items)
        lines = draft.splitlines()
        height = sum(max(1, (_text_width(line) + LIMIT["team_columns"] - 1) // LIMIT["team_columns"])
                     for line in lines)
        req = items[0][1].work_request
        question = next((line for line in re.split(r"(?:^|\s)\d+[.)]\s+|\n", req.body)
                         if "?" in line), req.body or req.title)
        question = question.split("?", 1)[0] + "?" if "?" in question else question
        mails.append({"team": team, "count": len(items), "draft": draft,
                      "subject": lines[0], "greeting": lines[2], "question": question,
                      "branches": req.branches, "short": height > LIMIT["team_lines"]})
    return mails


def _context(bundle: TriageBundle, meta: dict) -> dict:
    from triage.actions import build_actions

    meta = {**bundle.meta, **meta}
    by_id = {e.id: e for e in bundle.evidence}
    findings = {f.key: f for f in bundle.findings}
    decisions = {f.key: _decision(f, by_id) for f in bundle.findings}
    rank = {p.finding_key: (p.tier.rank, p.rank or float("inf")) for p in bundle.results}
    groups = {state: [] for state in _STATES}
    for key in sorted(findings, key=lambda k: (rank.get(k, (99, float("inf"))), findings[k].vulnerability.id, k)):
        item = decisions[key]
        groups[item["state"]].append(item)
    summaries = [item for items in groups.values() for item in items]
    edits = bundle.meta.get("fix_plan") or []
    edit_indexes = defaultdict(list)
    for i, edit in enumerate(edits):
        for key in edit.get("findings", []):
            edit_indexes[key].append(i)
    actions = build_actions(bundle)
    conclusion, metrics = action_view.action_summary(actions, bundle.findings)
    plans = {r.finding_key: r for r in bundle.remediations}
    action_items = []
    for index, action in enumerate(actions, 1):
        matching = sorted({i for key in action.findings for i in edit_indexes.get(key, [])})
        plan = _action_plan(action, [findings[k] for k in action.findings], [edits[i] for i in matching], plans, decisions)
        plan["n"] = index
        action_items.append(plan)
        for key in action.findings:
            decisions[key]["action"] = index

    components = {c.id: c for c in [*bundle.components, *(f.component for f in bundle.findings)]}
    used = {ref for item in summaries for ref in item["refs"]}
    for record in [*components.values(), *bundle.files, *bundle.anomalies]:
        used.update(record.evidence_ids)
    for edit in edits:
        used.update(edit.get("evidence_ids", []))
    citations, numbers = _citations(used, by_id)
    for item in summaries:
        item["sources"] = sorted({numbers[ref] for ref in item["refs"]})
        runs = []
        for number in item["sources"]:
            if runs and runs[-1][1] == number - 1:
                runs[-1][1] = number
            else:
                runs.append([number, number])
        item["source_ranges"] = runs
    project = meta.get("project")
    name = (meta.get("name") or meta.get("project_name") or
            (project.get("name") if isinstance(project, dict) else project) or meta.get("label") or "프로젝트 미기록")
    mails = _mail_views(meta.get("label") or name, actions)
    patch_name = meta.get("patch_name")
    patch = ("git apply " + action_view.shell_arg(patch_name)
             if patch_name and PureWindowsPath(patch_name).name == patch_name and not patch_name.startswith("-") else "")
    scan = _scan_command(meta)
    return {
        "name": name, "scope": meta.get("scope") or meta.get("source") or "범위 미기록",
        "timestamp": meta.get("generated_at") or meta.get("scanned_at") or "시각 미기록",
        "lookup_at": meta.get("lookup_at"), "lookup_sources": _lookup_sources(bundle, meta),
        "components_count": len(components), "ecosystems": sorted({c.ecosystem for c in components.values() if c.ecosystem}),
        "folders": _folders(bundle), "files_count": len(bundle.files), "file_types": _FILE_TYPES, "file_states": _FILE_SCOPE,
        "conclusion": conclusion, "metrics": metrics, "board": action_view.action_board(actions, findings, by_id),
        "action_items": action_items, "cards": [p for p in action_items if p["affected"]], "mails": mails,
        "patch": patch, "scan_command": scan, "scan_example": action_view.scan_command("<서비스>", "", bool(meta.get("scan_offline"))),
        "check_summary": action_view.check_summary(bundle.meta.get("fix_check") or {}),
        "checked": (bundle.meta.get("fix_check") or {}).get("status") == "ok",
        "groups": groups, "summaries": summaries, "states": _STATES, "conditions": _CONDITIONS,
        "citations": citations, "ref_numbers": numbers, "limits": LIMIT, "incomplete": meta.get("incomplete_coverage"),
        "limitations": meta.get("limitations") or [], "anomalies": [a.model_dump() for a in bundle.anomalies],
        "degraded": next((a.message for a in bundle.anomalies if a.kind == "judge_degraded"), ""),
        "failed": [a.message for a in bundle.anomalies if a.kind == "stage_failure"],
    }


def render_pdf(
    bundle: TriageBundle, meta: dict, out: Path, *, log: Callable[..., None] | None = None,
) -> list[Evidence]:
    """PDF를 저장하고 생성 근거를 반환한다.

    조회 기록은 meta의 lookup_at 또는 lookup_sources(name, url, retrieved_at)로 전달한다.
    """
    environment = Environment(
        autoescape=True,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    environment.filters["public_url"] = public_url
    environment.filters["link_label"] = _link_label
    environment.filters["summary_text"] = _summary_text
    environment.filters["text_width"] = _text_width
    environment.filters["compact"] = _compact
    environment.filters["css_text"] = lambda value: "".join(f"\\{ord(char):x} " for char in value)
    environment.filters["url_tail"] = lambda url: urlsplit(url).path.rstrip("/").rsplit("/", 1)[-1]
    environment.filters["local_time"] = _local_time
    context = Redactor((str(Path.home()), Path.home().as_posix())).value(_context(bundle, meta))
    font = (_DIRECTORY / "fonts" / "NotoSansKR.ttf").resolve().as_uri()
    template = (_DIRECTORY / "report.html").read_text(encoding="utf-8")
    page = environment.from_string(template).render(**context, font=font)
    pdf, engine, timing = render_with_engine(page)
    write_artifact(out, pdf)
    if log is not None:
        log("pdf", "engine", engine=engine, **timing)
    return [artifact_evidence("pdf", out, f"한국어 취약점 조치 보고서 생성 ({engine})", bundle)]
