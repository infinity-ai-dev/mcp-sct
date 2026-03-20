"""Ollama provider for local LLM inference."""

from __future__ import annotations

import os

import httpx

from .base import AnalysisRequest, AnalysisResponse, ModelProvider, SYSTEM_PROMPT


class OllamaProvider(ModelProvider):
    """Uses Ollama for local model inference (no API key needed)."""

    def __init__(self) -> None:
        self.base_url = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
        self.model = os.environ.get("MCP_SCT_OLLAMA_MODEL", "llama3.2")

    def name(self) -> str:
        return f"ollama/{self.model}"

    def is_available(self) -> bool:
        try:
            resp = httpx.get(f"{self.base_url}/api/tags", timeout=3)
            return resp.status_code == 200
        except Exception:
            return False

    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        prompt = self._build_prompt(request)

        async with httpx.AsyncClient(timeout=120) as client:
            resp = await client.post(
                f"{self.base_url}/api/chat",
                json={
                    "model": self.model,
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "stream": False,
                    "options": {
                        "temperature": 0.2,
                        "num_predict": 2048,
                    },
                },
            )

            if resp.status_code != 200:
                return AnalysisResponse(
                    suggestions=[],
                    model_used=self.name(),
                    error=f"Ollama error {resp.status_code}: {resp.text}",
                )

            data = resp.json()
            text = data.get("message", {}).get("content", "")

        return self._parse_response(text, self.name())
