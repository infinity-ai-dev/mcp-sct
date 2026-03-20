"""Anthropic provider for Claude-based analysis."""

from __future__ import annotations

import os

import httpx

from .base import AnalysisRequest, AnalysisResponse, ModelProvider, SYSTEM_PROMPT


class AnthropicProvider(ModelProvider):
    """Uses Anthropic API (Claude Sonnet, Haiku, etc.)."""

    def __init__(self) -> None:
        self.api_key = os.environ.get("ANTHROPIC_API_KEY", "")
        self.model = os.environ.get("MCP_SCT_ANTHROPIC_MODEL", "claude-sonnet-4-5-20250514")

    def name(self) -> str:
        return f"anthropic/{self.model}"

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        if not self.api_key:
            return AnalysisResponse(
                suggestions=[],
                model_used=self.name(),
                error="ANTHROPIC_API_KEY not set",
            )

        prompt = self._build_prompt(request)

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                "https://api.anthropic.com/v1/messages",
                headers={
                    "x-api-key": self.api_key,
                    "anthropic-version": "2023-06-01",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "max_tokens": 2048,
                    "system": SYSTEM_PROMPT,
                    "messages": [
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                },
            )

            if resp.status_code != 200:
                return AnalysisResponse(
                    suggestions=[],
                    model_used=self.name(),
                    error=f"Anthropic error {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()
            text = data["content"][0]["text"]

        return self._parse_response(text, self.name())
