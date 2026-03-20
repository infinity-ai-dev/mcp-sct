-- MCP-SCT Migration 001: Initial Schema
-- Creates core tables for scan history, tokens, and projects

-- Projects table
CREATE TABLE IF NOT EXISTS projects (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    description TEXT DEFAULT '',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tokens table (authentication)
CREATE TABLE IF NOT EXISTS tokens (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    hash TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL DEFAULT 'default',
    scopes TEXT DEFAULT '*',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    expires_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX IF NOT EXISTS idx_tokens_hash ON tokens(hash);
CREATE INDEX IF NOT EXISTS idx_tokens_project ON tokens(project_id);

-- Scan history table
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    files_scanned INTEGER DEFAULT 0,
    finding_count INTEGER DEFAULT 0,
    critical INTEGER DEFAULT 0,
    high INTEGER DEFAULT 0,
    medium INTEGER DEFAULT 0,
    low INTEGER DEFAULT 0,
    findings_json JSONB DEFAULT '[]'::jsonb,
    deps_json JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_scans_timestamp ON scans(timestamp DESC);

-- Dependency check history
CREATE TABLE IF NOT EXISTS dep_checks (
    id TEXT PRIMARY KEY,
    project_id TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path TEXT NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    ecosystem TEXT NOT NULL,
    total_deps INTEGER DEFAULT 0,
    vulnerable_deps INTEGER DEFAULT 0,
    vulnerabilities_json JSONB DEFAULT '[]'::jsonb
);

CREATE INDEX IF NOT EXISTS idx_dep_checks_project ON dep_checks(project_id, timestamp DESC);

-- Migration tracking
CREATE TABLE IF NOT EXISTS schema_migrations (
    version TEXT PRIMARY KEY,
    applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Insert default project
INSERT INTO projects (id, name, description)
VALUES ('default', 'Default Project', 'Auto-created default project')
ON CONFLICT (id) DO NOTHING;

-- Record migration
INSERT INTO schema_migrations (version)
VALUES ('001_initial')
ON CONFLICT (version) DO NOTHING;
