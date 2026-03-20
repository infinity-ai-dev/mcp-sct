"""Model provider registry - auto-detects available providers."""

from __future__ import annotations

from .base import ModelProvider
from .ollama_provider import OllamaProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider

_PROVIDERS: list[type[ModelProvider]] = [
    OllamaProvider,
    OpenAIProvider,
    AnthropicProvider,
]


def get_provider(name: str | None = None) -> ModelProvider | None:
    """Get a provider by name, or the first available one."""
    instances = [cls() for cls in _PROVIDERS]

    if name:
        for p in instances:
            if name.lower() in p.name().lower():
                return p if p.is_available() else None
        return None

    # Auto-detect: prefer Ollama (local/free) > Anthropic > OpenAI
    for p in instances:
        if p.is_available():
            return p

    return None


def list_providers() -> list[dict[str, object]]:
    """List all providers and their availability."""
    result = []
    for cls in _PROVIDERS:
        p = cls()
        result.append({
            "name": p.name(),
            "available": p.is_available(),
        })
    return result
