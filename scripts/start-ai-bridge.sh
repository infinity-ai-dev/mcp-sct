#!/bin/bash
# Start the MCP-SCT AI Bridge server
# Usage: ./scripts/start-ai-bridge.sh
#
# Environment variables:
#   OPENAI_API_KEY        - For OpenAI provider
#   ANTHROPIC_API_KEY     - For Anthropic provider
#   OLLAMA_HOST           - Ollama host (default: http://localhost:11434)
#   MCP_SCT_AI_PORT       - Bridge port (default: 9817)
#   MCP_SCT_AI_PROVIDER   - Force provider: "ollama", "openai", "anthropic"

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_DIR/python/.venv"

# Create venv if needed
if [ ! -d "$VENV_DIR" ]; then
    echo "Creating Python virtual environment..."
    python3 -m venv "$VENV_DIR"
    "$VENV_DIR/bin/pip" install -e "$PROJECT_DIR/python[all]"
fi

export PYTHONPATH="$PROJECT_DIR/python/src"
exec "$VENV_DIR/bin/python3" -m mcp_sct_ai.server "$@"
