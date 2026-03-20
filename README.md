# MCP-SCT - Security Code Testing

MCP server for cybersecurity analysis. Scans code for vulnerabilities, checks dependencies for CVEs, suggests fixes with AI, and generates security reports.

## Tools

| Tool | Description |
|------|-------------|
| `scan_code` | Static security analysis (OWASP Top 10). 28 rules for Python, JS/TS, Go, Java + taint analysis |
| `check_dependencies` | CVE detection via OSV.dev. Supports go.mod, package.json, requirements.txt, pom.xml, Cargo.lock, composer.lock |
| `suggest_fixes` | AI-powered fix suggestions (Ollama, OpenAI, Anthropic). Falls back to rule-based suggestions |
| `generate_report` | Consolidated security report in Markdown, JSON, or SARIF format |
| `run_security_test` | Run external tools (semgrep, bandit, gosec, npm audit) |
| `get_security_guidelines` | Security best practices for 13+ topics |

## Quick Start

### Local (stdio)

```bash
# Build
make build

# Add to Claude Code (~/.claude/settings.json)
{
  "mcpServers": {
    "mcp-sct": {
      "command": "/path/to/bin/mcp-sct"
    }
  }
}
```

### Cloud (Docker)

```bash
# Deploy with Docker Swarm
docker stack deploy -c deployments/docker/stack-mcp-sct.yml mcp_sct

# Connect from Claude Code
{
  "mcpServers": {
    "mcp-sct": {
      "url": "https://your-domain.com/mcp",
      "headers": {
        "Authorization": "Bearer YOUR_TOKEN"
      }
    }
  }
}
```

### Docker Image

```bash
docker pull infinitytools/mcp-sct:latest
```

Available for `linux/amd64` and `linux/arm64`.

## Features

### Security Scanning
- **28 built-in rules** covering OWASP Top 10: SQL injection, XSS, command injection, hardcoded secrets, path traversal, insecure deserialization, weak crypto, SSRF, prototype pollution, XXE, NoSQL injection, insecure cookies, ReDoS, open redirect, log injection, error info leak
- **Taint analysis** - tracks data flow from user input (sources) to dangerous functions (sinks) with sanitizer detection
- **4 languages**: Python (9 rules), JavaScript/TypeScript (9 rules), Go (5 rules), Java (5 rules)

### Dependency Checking
- **6 ecosystems**: Go, npm, PyPI, Maven, Cargo, Composer
- **OSV.dev API** for real-time vulnerability data
- CVSS severity scoring and fix version recommendations

### AI Fix Suggestions
- **3 providers**: Ollama (local/free), OpenAI, Anthropic
- Graceful degradation to rule-based suggestions when AI is unavailable
- Structured output: fixed code + explanation + references

### Reports
- **Markdown** - human-readable
- **JSON** - machine-readable
- **SARIF 2.1.0** - integrates with GitHub Code Scanning and GitLab SAST

### Cloud Mode
- HTTP transport with Streamable HTTP (MCP spec compliant)
- Bearer token authentication
- Rate limiting (60 req/min default)
- CORS support
- PostgreSQL persistence with auto-migration
- Docker Swarm / Kubernetes ready

### Security Guidelines
13+ topics: SQL injection, XSS, CSRF, command injection, authentication, input validation, secrets management, cryptography, CORS, path traversal, deserialization, logging, error handling, API security, Docker security

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MCP_SCT_MODE` | `stdio` or `cloud` | `stdio` |
| `MCP_SCT_ADDR` | HTTP listen address (cloud mode) | `:8080` |
| `MCP_SCT_ADMIN_TOKEN` | Fixed auth token (cloud mode) | auto-generated |
| `MCP_SCT_NO_AUTH` | Disable auth (`true`/`false`) | `false` |
| `MCP_SCT_AI_ENABLED` | Enable AI bridge | `false` |
| `OPENAI_API_KEY` | OpenAI API key | - |
| `ANTHROPIC_API_KEY` | Anthropic API key | - |
| `OLLAMA_HOST` | Ollama host URL | `http://localhost:11434` |
| `DB_HOST` | PostgreSQL host | - |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `mcp_sct` |
| `DB_USER` | Database user | `postgres` |
| `DB_PASSWORD` | Database password | - |

### CLI Flags

```
mcp-sct [flags]
  --config     Path to config file
  --rules-dir  Path to custom rules directory
  --ai         Enable AI bridge
  --mode       Server mode: stdio or cloud
  --addr       HTTP address (cloud mode)
  --version    Show version
```

## Custom Rules

Add YAML rules to `rules/custom/`:

```yaml
id: my-custom-rule
version: "1.0"
languages: [python]
severity: HIGH
category: injection
cwe: CWE-89
owasp: "A03:2021"
message: Description of the vulnerability
patterns:
  - pattern: 'dangerous_function\(.*user_input'
    type: regex
exclude_patterns:
  - pattern: 'sanitize\('
    type: regex
fix_template: |
  How to fix this issue
```

## Architecture

```
Go (core)          Python (AI bridge)
├── MCP Server     ├── Ollama provider
├── Scanner        ├── OpenAI provider
├── Rules Engine   ├── Anthropic provider
├── Taint Engine   └── HTTP server
├── Dep Checker
├── Report Gen
├── Auth/Middleware
└── PostgreSQL store
```

## License

MIT
