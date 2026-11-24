"""본선 화면 전용 예시. 실제 점검과 같은 입출력 형태를 사용한다."""
from __future__ import annotations

import json
from collections.abc import Callable
from pathlib import Path
from typing import NamedTuple

from triage.models import (
    Component, Evidence, Finding, ItemResult, MissingInfo, PriorityResult,
    Remediation, Tier, TriageBundle, Verdict, Vulnerability, WorkRequest,
)
from triage.output import RunLog, render_pdf, write_cyclonedx


class ScanResult(NamedTuple):
    bundle: TriageBundle
    artifacts: dict[str, Path]
    events: list[dict]


def preview_scan(
    service: str, root: Path, out: Path, *, on_event: Callable[[dict], None],
) -> ScanResult:
    """입력 소스에 접근하지 않고, 화면 확인용 예시 산출물을 만든다."""
    service = f"{service} (화면 예시)"
    evidence = Evidence(
        id="EXAMPLE-1", kind="config", file="example/settings.toml",
        line_start=4, snippet="example_feature = true", note="화면 확인용 가상 근거",
    )
    component = Component(id="demo-component", name="예시 모듈", version="1.0")
    findings = [
        Finding(
            key=state, component=component, vulnerability=Vulnerability(
                id=f"DEMO-{index}", references=["https://example.com/"],
            ),
            verdict=Verdict(state=state, plain_ko=reason),
        )
        for index, (state, reason) in enumerate((
            ("affected", "예시 설정에서 문제가 생기는 기능을 사용 중입니다."),
            ("not_affected", "이 예시 항목은 배포 대상에서 빠져 있습니다."),
            ("undetermined", "이 예시 항목은 운영 설정을 더 확인해야 합니다."),
        ), 1)
    ]
    affected, _, pending = findings
    affected.verdict.item_results = [
        ItemResult(item_key="example_feature", status="met", evidence_ids=[evidence.id]),
    ]
    pending.verdict.missing_info = [
        MissingInfo(what="운영 설정에서 기능이 켜져 있는지", where="운영 설정 파일"),
    ]
    pending.verdict.work_request = WorkRequest(
        to_team="운영팀", title="예시 기능 사용 여부 확인",
        body="운영 환경에서 예시 기능이 켜져 있는지 확인해 주세요.",
    )
    bundle = TriageBundle(
        components=[component], findings=findings, evidence=[evidence],
        results=[PriorityResult(finding_key=affected.key, tier=Tier.P1, score=1, rank=1)],
        remediations=[Remediation(
            finding_key=affected.key, target_version="1.1",
            steps=["예시 모듈을 1.1로 올립니다."],
            verify_notes=["테스트 환경에서 해당 기능을 실행해 정상 응답을 확인합니다."],
        )],
        meta={"checklists": {affected.key: {"items": [
            {"key": "example_feature", "question": "예시 기능이 켜져 있나요?"},
        ]}}},
    )
    paths = {
        "sbom": out / "sbom-preview.json",
        "pdf": out / "report-preview.pdf",
        "log": out / "log-preview-run1.jsonl",
    }
    with RunLog(paths["log"]) as log:
        def emit(stage: str, event: str, **data) -> None:
            data["preview"] = True
            log.emit(stage, event, **data)
            on_event({"stage": stage, "event": event, "data": data})

        for stage, count in (("collect", 1), ("scope", 1), ("lookup", 3), ("judge", 3), ("verify", 1)):
            emit(stage, "start")
            emit(stage, "end", count=count)
        emit("report", "start")
        write_cyclonedx(bundle, {"name": service}, paths["sbom"])
        try:
            render_pdf(bundle, {"name": service, "scope": "입력 소스를 점검하지 않은 화면 예시"}, paths["pdf"])
        except (ImportError, OSError):
            del paths["pdf"]
        emit("report", "end", count=len(paths))
        log.close(usage_reason="화면 예시에서 모델을 호출하지 않았습니다.", preview=True)
    events = [json.loads(line) for line in paths["log"].read_text(encoding="utf-8").splitlines()]
    return ScanResult(bundle, paths, events)
