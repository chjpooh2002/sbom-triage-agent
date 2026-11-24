"""소스 수집부터 본선 제출용 산출물 생성까지 실행한다."""
from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from time import perf_counter
from typing import Protocol

from .collect import collect
from .intel import enrich
from .lookup import lookup
from .models import Anomaly, Evidence, Finding, ItemResult, SourceFileScope, Status, TriageBundle, Verdict
from .output import RunLog, render_pdf, write_cyclonedx
from .priority import load_policy, prioritize
from .remediation import remediate
from .remediation.providers.template import TemplateProvider
from .scope import apply_scope


VERDICT_STATUS = {"affected": Status.affected, "not_affected": Status.not_affected, "undetermined": Status.unknown}


class Judge(Protocol):
    def __call__(
        self, findings: list[Finding], evidence: list[Evidence], files: list[SourceFileScope], root: Path,
        log: Callable[..., None], /, *, anomalies: list[Anomaly], usage: Callable[..., None],
    ) -> list[Finding] | None: ...


@dataclass
class ScanResult:
    bundle: TriageBundle
    paths: dict[str, Path]
    failures: dict[str, str]


def default_judge() -> Judge | None:
    """판정 모듈이 설치된 경우 기본 판정기를 불러온다."""
    try:
        from .judge import judge_all
    except ModuleNotFoundError as error:
        if error.name == "triage.judge":
            return None
        raise
    return judge_all


def _prejudge(findings: list[Finding]) -> list[Finding]:
    results = []
    for finding in findings:
        evidence_ids = list(dict.fromkeys([*finding.component.evidence_ids, *finding.hints.get("evidence_ids", [])]))
        if finding.version_in_range is False:
            reason = "설치 버전이 권고문의 영향 범위 밖입니다."
            rule, state, status, condition = "out_of_range", "not_affected", Status.not_affected, "not_met"
        elif finding.component.deployed == "no":
            reason = "배포 범위에 포함되지 않는 구성요소입니다."
            rule, state, status, condition = "not_deployed", "not_affected", Status.not_affected, "not_met"
        else:
            reason = "현재 근거만으로 취약점의 영향을 확정할 수 없습니다."
            rule, state, status, condition = "insufficient_evidence", "undetermined", Status.unknown, "unknown"

        results.append(finding.model_copy(update={
            "status": status,
            "status_note": reason,
            "verdict": Verdict(state=state, decided_by=f"rule:{rule}", rationale_ko=reason, plain_ko=reason,
                               item_results=[ItemResult(item_key=rule, status=condition,
                                                        evidence_ids=evidence_ids, reason=reason)],
                               decided_at=datetime.now(timezone.utc).isoformat()),
        }))
    return results


def run_scan(
    label: str, root: Path, out_dir: Path, offline: bool = False, run_no: int = 1, judge: Judge | None = None,
    on_event: Callable[[dict], None] | None = None,
) -> ScanResult:
    """점검 결과를 반환하고 로그를 저장한 직후 on_event로 전달한다."""
    if not label.strip() or any(char in '<>:"/\\|?*' or ord(char) < 32 for char in label):
        raise ValueError("라벨은 파일 이름에 사용할 수 있는 비어 있지 않은 문자열이어야 합니다.")
    if run_no < 1:
        raise ValueError("실행 번호는 1 이상이어야 합니다.")

    root, out_dir = Path(root).resolve(), Path(out_dir)
    started_at = datetime.now(timezone.utc)
    meta = {"label": label, "name": label, "scope": root.name or label,
            "generated_at": started_at.isoformat()}
    bundle = TriageBundle(meta=meta)
    paths: dict[str, Path] = {}
    failures: dict[str, str] = {}
    log_path = out_dir / f"log-{label}-run{run_no}.jsonl"
    run_log = RunLog(log_path, on_event=on_event)
    lookup_misses = 0

    def log(stage: str, event: str, **data) -> None:
        nonlocal lookup_misses
        if stage == "lookup" and (event == "cache_miss" or event == "request_unavailable"):
            lookup_misses += 1
        if event in {"start", "end"}:
            event = f"detail.{event}"
        run_log.emit(stage, event, **data)

    def counts() -> dict:
        verdicts = Counter(finding.verdict.state for finding in bundle.findings if finding.verdict)
        return {"components": len(bundle.components), "candidates": len(bundle.findings), "files": len(bundle.files),
                "verdicts": {state: verdicts[state] for state in VERDICT_STATUS},
                "prioritized": len(bundle.results), "remediations": len(bundle.remediations)}

    def record_failure(stage: str, error: Exception) -> None:
        error_type = type(error).__name__
        reason = f"{stage} 단계 실패 ({error_type})."
        failures[stage] = reason
        evidence = Evidence(id=f"scan-{len(failures):04d}", kind="tool", file=log_path.name, note=reason)
        bundle.evidence.append(evidence)
        bundle.anomalies.append(Anomaly(kind="stage_failure", message=reason, evidence_ids=[evidence.id]))
        run_log.emit(stage, "error", error=error_type, evidence_ids=[evidence.id])

    @contextmanager
    def step(stage: str) -> Iterator[None]:
        started = perf_counter()
        run_log.emit(stage, "start")
        try:
            yield
        except Exception as error:
            record_failure(stage, error)
        finally:
            run_log.emit(stage, "end", seconds=round(perf_counter() - started, 6),
                         status="error" if stage in failures else "ok", **counts())

    completed = False
    try:
        run_log.emit("run", "start", label=label, run_no=run_no, offline=offline)
        with step("collect"):
            collected = collect(root, log=log, offline=offline)
            bundle.components = collected.components
            bundle.evidence.extend(collected.evidence)
            bundle.anomalies.extend(collected.anomalies)

        with step("scope"):
            scoped = apply_scope(root, bundle.components, log=log)
            bundle.components = scoped.components
            bundle.files = scoped.files
            bundle.evidence.extend(scoped.evidence)

        with step("lookup"):
            looked_up = lookup(bundle.components, offline=offline, log=log)
            bundle.findings = looked_up.findings
            bundle.evidence.extend(looked_up.evidence)

        with step("judge"):
            if judge is None:
                bundle.findings = _prejudge(bundle.findings)
            else:
                # 오류가 발생하면 조회 결과를 보존하고 규칙으로 다시 판정한다.
                inputs = bundle.model_copy(deep=True)
                try:
                    judged = judge(inputs.findings, inputs.evidence, inputs.files, root, log,
                                   anomalies=inputs.anomalies, usage=run_log.add_usage)
                except Exception as error:
                    record_failure("judge", error)
                    bundle.findings = _prejudge(bundle.findings)
                    run_log.emit("judge", "fallback", **counts())
                else:
                    bundle.findings = inputs.findings if judged is None else judged
                    bundle.evidence = inputs.evidence
                    bundle.anomalies = inputs.anomalies
            for finding in bundle.findings:
                if verdict := finding.verdict:
                    finding.status = VERDICT_STATUS.get(verdict.state, Status.unknown)
                    if verdict.rationale_ko:
                        finding.status_note = verdict.rationale_ko
                    run_log.emit("judge", "decision", finding_key=finding.key, state=verdict.state,
                                 decided_by=verdict.decided_by, decided_at=verdict.decided_at,
                                 evidence_ids=list(dict.fromkeys(ref for item in verdict.item_results
                                                                for ref in item.evidence_ids)))

        with step("enrich"):
            enrich(bundle)

        with step("priority"):
            prioritize(bundle, load_policy(), started_at.astimezone().date())
            unaffected = {finding.key for finding in bundle.findings if finding.status == Status.not_affected}
            bundle.results.sort(key=lambda result: result.finding_key in unaffected)
            for rank, result in enumerate(bundle.results, 1):
                result.rank = rank

        with step("remediate"):
            remediate(bundle, TemplateProvider(), llm_limit=0, offline=offline, require_registry=True)

        sbom_path = out_dir / f"sbom-{label}.json"
        with step("cyclonedx"):
            bundle.evidence.extend(write_cyclonedx(bundle, meta, sbom_path))
            paths["sbom"] = sbom_path

        report_path = out_dir / f"report-{label}.pdf"
        if lookup_misses:
            bundle.meta["limitations"] = [f"취약점 조회에서 응답이나 캐시를 확보하지 못한 요청이 {lookup_misses}건 있습니다."]
        bundle.meta["incomplete_coverage"] = bool(lookup_misses or {"collect", "lookup"}.intersection(failures))
        with step("pdf"):
            bundle.evidence.extend(render_pdf(bundle, meta, report_path))
            paths["report"] = report_path
        completed = True
    finally:
        if judge is None:
            run_log.add_usage(total_tokens=0)
        status = "partial" if failures else "ok"
        bundle.evidence.extend(run_log.close(status=status if completed else "error", failed_stages=list(failures),
                                             **counts()))
        paths["log"] = log_path
    return ScanResult(bundle, paths, failures)
