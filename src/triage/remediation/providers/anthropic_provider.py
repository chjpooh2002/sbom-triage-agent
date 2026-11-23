"""Anthropic(Claude) 공급자. 구조화 출력(output_config.format)으로 스키마에 맞는 JSON 만 받는다."""
from __future__ import annotations

import json
import os

from ..prompt import SYSTEM, RemediationDraft, draft_schema, user_message
from .base import ProviderError

# 거절(refusal) 시 서버 쪽에서 다른 모델로 이어서 처리하게 하는 기능. 지원 모델에서만 켠다.
FALLBACK_MODELS = {"claude-opus-5-5", "claude-sonnet-5-5", "claude-fable-5-2", "claude-fable-5-1", "claude-opus-5"}


class AnthropicProvider:
    name = "anthropic"

    def __init__(self, model: str = "claude-opus-5-5", timeout: float = 60.0, client=None):
        try:
            import anthropic
        except ImportError as e:
            raise ProviderError("anthropic 패키지 없음") from e
        if client is None and not (os.environ.get("ANTHROPIC_API_KEY") or os.environ.get("ANTHROPIC_AUTH_TOKEN")):
            raise ProviderError("ANTHROPIC_API_KEY 가 비어 있음")
        self._anthropic = anthropic
        self.client = client or anthropic.Anthropic(timeout=timeout, max_retries=2)
        self.model = model
        self.use_fallbacks = model in FALLBACK_MODELS and os.environ.get("LLM_FALLBACKS", "default") != "off"

    def draft(self, ctx: dict) -> RemediationDraft:
        a = self._anthropic
        kwargs = dict(
            model=self.model, max_tokens=4000, system=SYSTEM,
            messages=[{"role": "user", "content": user_message(ctx)}],
            output_config={"effort": "low", "format": {"type": "json_schema", "schema": draft_schema()}},
        )
        try:
            if self.use_fallbacks:
                resp = self.client.beta.messages.create(betas=["server-side-fallback-2026-07-01"], fallbacks="default", **kwargs)
            else:
                resp = self.client.messages.create(**kwargs)
        except a.RateLimitError as e:
            raise ProviderError(f"요청 한도 초과: {e}") from e
        except a.APIStatusError as e:
            raise ProviderError(f"API 오류 {e.status_code}: {e.message}") from e
        except a.APIConnectionError as e:
            raise ProviderError(f"연결 실패: {e}") from e
        if resp.stop_reason == "refusal":
            raise ProviderError("모델이 응답을 거절함")
        if resp.stop_reason == "max_tokens":
            raise ProviderError("출력이 잘림(max_tokens)")
        text = next((b.text for b in resp.content if b.type == "text"), "")
        try:
            return RemediationDraft.model_validate(json.loads(text))
        except Exception as e:
            raise ProviderError(f"응답 형식 오류: {e}") from e
