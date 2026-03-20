-- MCP-SCT Migration 002: Audit Log
-- Tracks API usage for metering and security auditing

CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    project_id TEXT REFERENCES projects(id) ON DELETE SET NULL,
    token_id TEXT,
    action TEXT NOT NULL,
    tool_name TEXT,
    path TEXT,
    status TEXT DEFAULT 'success',
    duration_ms INTEGER DEFAULT 0,
    metadata JSONB DEFAULT '{}'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_audit_project ON audit_log(project_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp DESC);

-- Record migration
INSERT INTO schema_migrations (version)
VALUES ('002_audit_log')
ON CONFLICT (version) DO NOTHING;
