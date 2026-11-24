"""저장된 점검 묶음으로 보고서를 다시 그린다. 입력 소스나 조회 캐시는 열지 않는다."""
import json
from pathlib import Path

from triage.action_view import saved_scan_args
from triage.models import TriageBundle

from ..runlog import RunLog
from . import render_pdf


def saved_meta(bundle: TriageBundle, web: dict) -> dict:
    command = web.get("command")
    meta = saved_scan_args(command) if isinstance(command, str) else {}
    downloads = web.get("downloads")
    plan = bundle.meta.get("fix_plan")
    applicable = plan is None or any(edit.get("kind") == "change" for edit in plan)
    if applicable and isinstance(downloads, dict) and isinstance(downloads.get("patch"), str):
        meta["patch_name"] = downloads["patch"]
    recorded = bundle.meta.get("report_meta")
    return {**meta, **bundle.meta, **(recorded if isinstance(recorded, dict) else {})}


def render_saved_report(source: Path, out: Path) -> Path:
    log_path = out.with_suffix(".report.jsonl")
    if out.suffix.lower() != ".pdf" or source.resolve() in {out.resolve(), log_path.resolve()}:
        raise ValueError("입력과 다른 .pdf 출력 파일을 지정하세요.")
    with RunLog(log_path) as log:
        log.emit("report", "start", source=source.name)
        log.add_usage(total_tokens=0)
        try:
            bundle = TriageBundle.model_validate_json(source.read_text(encoding="utf-8"))
            web = {}
            sidecar = source.with_name("meta.json")
            if source.name == "bundle.json" and sidecar.is_file():
                saved = json.loads(sidecar.read_text(encoding="utf-8"))
                if isinstance(saved, dict):
                    web = saved
            render_pdf(bundle, saved_meta(bundle, web), out, log=log.emit)
        except Exception as error:
            log.emit("report", "error", error=type(error).__name__)
            raise
        log.emit("report", "end", output=out.name, candidates=len(bundle.findings))
    return log_path
