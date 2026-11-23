"""조치안 공급자 인터페이스와 선택. 공급자를 바꿔도 나머지 코드는 그대로다."""
from __future__ import annotations

import os
from typing import Optional, Protocol

from ..prompt import RemediationDraft


class ProviderError(RuntimeError):
    pass


class Provider(Protocol):
    name: str
    model: str

    def draft(self, ctx: dict) -> RemediationDraft: ...


def get_provider(name: Optional[str] = None) -> Provider:
    """LLM_PROVIDER(.env) 로 고른다. 키가 없거나 SDK 초기화에 실패하면 template 으로 대체한다."""
    from dotenv import load_dotenv

    load_dotenv()
    name = (name or os.environ.get("LLM_PROVIDER") or "template").lower()
    timeout = float(os.environ.get("LLM_TIMEOUT", "60"))
    from .template import TemplateProvider

    try:
        if name == "anthropic":
            from .anthropic_provider import AnthropicProvider
            return AnthropicProvider(model=os.environ.get("ANTHROPIC_MODEL") or "claude-opus-5-5", timeout=timeout)
        if name == "openai":
            from .openai_provider import OpenAIProvider
            model = os.environ.get("OPENAI_MODEL")
            if not model:
                raise ProviderError("OPENAI_MODEL 이 비어 있음")
            return OpenAIProvider(model=model, timeout=timeout)
    except ProviderError as e:
        t = TemplateProvider()
        t.init_warning = f"{name} 공급자를 쓸 수 없어 템플릿으로 대체: {e}"
        return t
    return TemplateProvider()
