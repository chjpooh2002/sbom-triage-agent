"""조치안 생성 흐름: (자산, 구성요소) 묶음별로 후보 버전 계산 → 공급자 초안 → 규칙 재검증 → 발견 건마다 기록.

한 구성요소를 올리면 그 구성요소의 취약점이 함께 해결되므로 모델 호출은 묶음당 한 번이다.
"""
from __future__ import annotations

import hashlib
import json
from collections import OrderedDict
from typing import Optional

from ..intel.cache import cache_dir
from ..models import Remediation, Status, TriageBundle
from .prompt import SYSTEM, RemediationDraft, build_context, user_message
from .providers.base import Provider, ProviderError, get_provider
from .providers.template import TemplateProvider
from .registry import list_versions
from .verify import candidate_versions, rule_pick, verify


def _cache_key(p: Provider, ctx: dict) -> str:
    raw = f"{p.name}|{p.model}|{SYSTEM}|{user_message(ctx)}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]


def _cached_draft(p: Provider, ctx: dict) -> tuple[RemediationDraft, bool]:
    f = cache_dir() / "llm" / f"{_cache_key(p, ctx)}.json"
    if f.exists():
        return RemediationDraft.model_validate_json(f.read_text(encoding="utf-8")), True
    d = p.draft(ctx)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(d.model_dump_json(), encoding="utf-8")
    return d, False


def remediate(bundle: TriageBundle, provider: Optional[Provider] = None, llm_limit: int = 20,
              offline: bool = False) -> TriageBundle:
    if not bundle.results:
        raise ValueError("우선순위 결과가 없습니다. prioritize 를 먼저 실행하세요")
    provider = provider or get_provider()
    template = TemplateProvider()
    results = {r.finding_key: r for r in bundle.results}
    groups: "OrderedDict[tuple, list]" = OrderedDict()
    for r in bundle.results:                     # 순위 순서대로 묶음을 만든다 → 급한 묶음부터 모델 호출
        f = bundle.finding(r.finding_key)
        if f is None or f.status == Status.not_affected:
            continue
        groups.setdefault((f.asset_id, f.component.id), []).append(f)

    remediations: list[Remediation] = []
    stats = {"groups": len(groups), "llm_calls": 0, "llm_cache_hits": 0, "fallbacks": 0, "rejected_targets": 0,
             "registry_unknown": 0}
    warnings = [provider.init_warning] if getattr(provider, "init_warning", "") else []
    for i, ((asset_id, _), group) in enumerate(groups.items()):
        comp = group[0].component
        available = list_versions(comp, offline=offline)
        if available is None:
            stats["registry_unknown"] += 1
        # 반드시 고칠 취약점: 정책상 급한 등급(P1·P2) 또는 KEV. 비어 있으면 같은 메이저에서 가장 많이 줄이는 버전을 고른다
        required = {f.vulnerability.id for f in group if results[f.key].tier.rank <= 2 or f.signals.kev.listed}
        rule_target, rule_notes = rule_pick(group, available, required)
        ctx = build_context(group, results, bundle.asset(asset_id), candidate_versions(group, available),
                            rule_target, rule_notes)
        use_llm = provider.name != "template" and i < llm_limit
        used, fallback, notes = provider.name if use_llm else "template", False, []
        if use_llm:
            try:
                draft, hit = _cached_draft(provider, ctx)
                stats["llm_cache_hits" if hit else "llm_calls"] += 1
            except ProviderError as e:
                draft, used, fallback = template.draft(ctx), "template", True
                stats["fallbacks"] += 1
                notes.append(f"{provider.name} 호출 실패 → 템플릿 사용: {e}")
        else:
            draft = template.draft(ctx)
            if provider.name != "template":
                notes.append(f"모델 호출 상한({llm_limit}묶음) 밖 → 템플릿 사용")

        check = verify(draft.target_version, group, available, required)
        final = check
        if not check.ok and draft.target_version != rule_target:
            stats["rejected_targets"] += 1
            notes.append(f"제안 버전 {draft.target_version} 기각({'; '.join(check.notes)}) → 규칙 선택 {rule_target}")
            final = verify(rule_target, group, available, required) if rule_target else check
            if final.target:
                draft.steps = [s.replace(str(draft.target_version), final.target) if draft.target_version else s
                               for s in draft.steps]
        notes += final.notes
        for f in group:
            remediations.append(Remediation(
                finding_key=f.key, target_version=final.target, verified=final.ok, verify_notes=notes,
                summary_ko=draft.summary_ko, steps=draft.steps, workaround=draft.workaround,
                provider=f"{used}:{provider.model}" if used != "template" else "template", fallback_used=fallback))
    bundle.remediations = remediations
    bundle.meta["remediation"] = {"provider": provider.name, "model": provider.model, **stats, "warnings": warnings}
    return bundle
