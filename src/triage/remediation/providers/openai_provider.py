"""OpenAI 공급자. Chat Completions 의 json_schema 응답 형식(strict)으로 스키마에 맞는 JSON 만 받는다."""
from __future__ import annotations

import json
import os

from ..prompt import SYSTEM, RemediationDraft, draft_schema, user_message
from .base import ProviderError


class OpenAIProvider:
    name = "openai"

    def __init__(self, model: str, timeout: float = 60.0, client=None):
        try:
            import openai
        except ImportError as e:
            raise ProviderError("openai 패키지 없음") from e
        if client is None and not os.environ.get("OPENAI_API_KEY"):
            raise ProviderError("OPENAI_API_KEY 가 비어 있음")
        self._openai = openai
        self.client = client or openai.OpenAI(timeout=timeout, max_retries=2)
        self.model = model

    def draft(self, ctx: dict) -> RemediationDraft:
        o = self._openai
        try:
            resp = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "system", "content": SYSTEM}, {"role": "user", "content": user_message(ctx)}],
                response_format={"type": "json_schema",
                                 "json_schema": {"name": "remediation", "strict": True, "schema": draft_schema()}},
            )
        except o.RateLimitError as e:
            raise ProviderError(f"요청 한도 초과: {e}") from e
        except o.APIStatusError as e:
            raise ProviderError(f"API 오류 {e.status_code}: {e.message}") from e
        except o.APIConnectionError as e:
            raise ProviderError(f"연결 실패: {e}") from e
        choice = resp.choices[0]
        if getattr(choice.message, "refusal", None):
            raise ProviderError("모델이 응답을 거절함")
        if choice.finish_reason == "length":
            raise ProviderError("출력이 잘림(length)")
        try:
            return RemediationDraft.model_validate(json.loads(choice.message.content or ""))
        except Exception as e:
            raise ProviderError(f"응답 형식 오류: {e}") from e
