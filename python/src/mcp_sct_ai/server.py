"""HTTP server for AI Bridge - Go communicates with this process."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import signal
import sys
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from .models.base import AnalysisRequest
from .models.registry import get_provider, list_providers

logging.basicConfig(
    level=logging.INFO,
    format="[mcp-sct-ai] %(asctime)s %(levelname)s %(message)s",
    stream=sys.stderr,
)
log = logging.getLogger(__name__)


class AIBridgeHandler(BaseHTTPRequestHandler):
    """Handles HTTP requests from the Go MCP server."""

    provider = None  # set at startup

    def log_message(self, format: str, *args: Any) -> None:
        """Redirect HTTP logs to stderr."""
        log.debug(format, *args)

    def _send_json(self, status: int, data: dict) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        return json.loads(body) if body else {}

    def do_GET(self) -> None:
        if self.path == "/health":
            provider_info = list_providers()
            active = self.provider.name() if self.provider else "none"
            self._send_json(200, {
                "status": "ok",
                "active_provider": active,
                "providers": provider_info,
            })
        else:
            self._send_json(404, {"error": "not found"})

    def do_POST(self) -> None:
        if self.path == "/analyze":
            self._handle_analyze()
        elif self.path == "/suggest-fix":
            self._handle_suggest_fix()
        else:
            self._send_json(404, {"error": "not found"})

    def _handle_analyze(self) -> None:
        if not self.provider:
            self._send_json(503, {"error": "no AI provider available"})
            return

        try:
            data = self._read_json()
            request = AnalysisRequest(
                code=data.get("code", ""),
                language=data.get("language", ""),
                file_path=data.get("file_path", ""),
                vulnerability_type=data.get("vulnerability_type", ""),
                context=data.get("context", {}),
            )

            response = asyncio.run(self.provider.analyze(request))

            result = {
                "model_used": response.model_used,
                "error": response.error,
                "suggestions": [
                    {
                        "fixed_code": s.fixed_code,
                        "explanation": s.explanation,
                        "confidence": s.confidence,
                        "references": s.references,
                    }
                    for s in response.suggestions
                ],
            }
            self._send_json(200, result)

        except Exception as e:
            log.exception("Analysis failed")
            self._send_json(500, {"error": str(e)})

    def _handle_suggest_fix(self) -> None:
        if not self.provider:
            self._send_json(503, {"error": "no AI provider available"})
            return

        try:
            data = self._read_json()
            request = AnalysisRequest(
                code=data.get("code", ""),
                language=data.get("language", ""),
                file_path=data.get("file_path", ""),
                vulnerability_type=data.get("vulnerability_type", ""),
                rule_id=data.get("rule_id", ""),
                finding_message=data.get("finding_message", ""),
                start_line=data.get("start_line", 0),
                end_line=data.get("end_line", 0),
            )

            response = asyncio.run(self.provider.analyze(request))

            result = {
                "model_used": response.model_used,
                "error": response.error,
                "suggestions": [
                    {
                        "fixed_code": s.fixed_code,
                        "explanation": s.explanation,
                        "confidence": s.confidence,
                        "references": s.references,
                    }
                    for s in response.suggestions
                ],
            }
            self._send_json(200, result)

        except Exception as e:
            log.exception("Fix suggestion failed")
            self._send_json(500, {"error": str(e)})


def main() -> None:
    host = os.environ.get("MCP_SCT_AI_HOST", "127.0.0.1")
    port = int(os.environ.get("MCP_SCT_AI_PORT", "9817"))
    provider_name = os.environ.get("MCP_SCT_AI_PROVIDER", "")

    provider = get_provider(provider_name or None)
    if provider:
        log.info("AI provider: %s", provider.name())
    else:
        log.warning("No AI provider available. Set OPENAI_API_KEY, ANTHROPIC_API_KEY, or start Ollama.")
        log.info("Available providers: %s", list_providers())

    AIBridgeHandler.provider = provider

    server = HTTPServer((host, port), AIBridgeHandler)

    def shutdown(signum, frame):
        log.info("Shutting down AI bridge...")
        server.shutdown()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    log.info("AI Bridge listening on %s:%d", host, port)
    # Signal to parent process that we're ready
    print(json.dumps({"status": "ready", "port": port}), flush=True)

    server.serve_forever()


if __name__ == "__main__":
    main()
