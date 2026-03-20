"""OpenAI provider for GPT-based analysis."""

from __future__ import annotations

import os

import httpx

from .base import AnalysisRequest, AnalysisResponse, ModelProvider, SYSTEM_PROMPT


class OpenAIProvider(ModelProvider):
    """Uses OpenAI API (GPT-4o, GPT-4-turbo, etc.)."""

    def __init__(self) -> None:
        self.api_key = os.environ.get("OPENAI_API_KEY", "")
        self.model = os.environ.get("MCP_SCT_OPENAI_MODEL", "gpt-4o-mini")
        self.base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1")

    def name(self) -> str:
        return f"openai/{self.model}"

    def is_available(self) -> bool:
        return bool(self.api_key)

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        if not self.api_key:
            return AnalysisResponse(
                suggestions=[],
                model_used=self.name(),
                error="OPENAI_API_KEY not set",
            )

        prompt = self._build_prompt(request)

        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.post(
                f"{self.base_url}/chat/completions",
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 2048,
                },
            )

            if resp.status_code != 200:
                return AnalysisResponse(
                    suggestions=[],
                    model_used=self.name(),
                    error=f"OpenAI error {resp.status_code}: {resp.text[:200]}",
                )

            data = resp.json()
            text = data["choices"][0]["message"]["content"]

        return self._parse_response(text, self.name())
