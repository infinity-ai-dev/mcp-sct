#!/bin/sh
set -e

# =============================================================
# MCP-SCT Entrypoint
# Executa migrações do banco de dados e inicia o servidor
# =============================================================

LOG_PREFIX="[mcp-sct-init]"

log_info() {
    echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') INFO  $1"
}

log_ok() {
    echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') OK    $1"
}

log_warn() {
    echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') WARN  $1"
}

log_error() {
    echo "$LOG_PREFIX $(date '+%Y-%m-%d %H:%M:%S') ERROR $1"
}

# =============================================================
# Aguarda o PostgreSQL ficar disponível
# =============================================================
wait_for_postgres() {
    if [ -z "$DB_HOST" ]; then
        log_warn "DB_HOST not set, skipping database migration"
        return 1
    fi

    local max_attempts=30
    local attempt=0

    log_info "Waiting for PostgreSQL at $DB_HOST:${DB_PORT:-5432}..."

    while [ $attempt -lt $max_attempts ]; do
        if pg_isready -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" > /dev/null 2>&1; then
            log_ok "PostgreSQL is ready"
            return 0
        fi
        attempt=$((attempt + 1))
        sleep 1
    done

    log_error "PostgreSQL not available after ${max_attempts}s"
    return 1
}

# =============================================================
# Cria o banco de dados se não existir
# =============================================================
create_database() {
    local db_name="${DB_NAME:-mcp_sct}"

    log_info "Checking database '$db_name'..."

    # Verifica se o banco existe
    local exists=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -tAc \
        "SELECT 1 FROM pg_database WHERE datname='$db_name'" 2>/dev/null || echo "")

    if [ "$exists" = "1" ]; then
        log_ok "Database '$db_name' already exists"
    else
        log_info "Creating database '$db_name'..."
        PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -c \
            "CREATE DATABASE $db_name" 2>/dev/null
        log_ok "Database '$db_name' created successfully"
    fi
}

# =============================================================
# Executa migrations SQL
# =============================================================
run_migrations() {
    local db_name="${DB_NAME:-mcp_sct}"
    local migrations_dir="/app/migrations"

    if [ ! -d "$migrations_dir" ]; then
        log_warn "Migrations directory not found: $migrations_dir"
        return 0
    fi

    log_info "Running database migrations..."

    # Cria tabela de controle de migrações se não existir
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -d "$db_name" -c \
        "CREATE TABLE IF NOT EXISTS schema_migrations (version TEXT PRIMARY KEY, applied_at TIMESTAMP WITH TIME ZONE DEFAULT NOW())" \
        > /dev/null 2>&1

    local applied=0
    local skipped=0

    # Executa cada arquivo SQL em ordem
    for migration_file in $(ls "$migrations_dir"/*.sql 2>/dev/null | sort); do
        local version=$(basename "$migration_file" .sql)

        # Verifica se já foi aplicada
        local already_applied=$(PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -d "$db_name" -tAc \
            "SELECT 1 FROM schema_migrations WHERE version='$version'" 2>/dev/null || echo "")

        if [ "$already_applied" = "1" ]; then
            skipped=$((skipped + 1))
            continue
        fi

        log_info "Applying migration: $version"

        # Executa a migration
        if PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -d "$db_name" \
            -f "$migration_file" > /dev/null 2>&1; then
            log_ok "Migration $version applied successfully"
            applied=$((applied + 1))

            # Lista tabelas criadas nesta migration
            log_info "Tables after $version:"
            PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -d "$db_name" -tAc \
                "SELECT tablename FROM pg_tables WHERE schemaname='public' ORDER BY tablename" 2>/dev/null | while read table; do
                log_info "  - $table"
            done
        else
            log_error "Migration $version failed!"
            return 1
        fi
    done

    if [ $applied -gt 0 ]; then
        log_ok "Migrations complete: $applied applied, $skipped already up-to-date"
    else
        log_ok "Database is up-to-date ($skipped migrations already applied)"
    fi

    # Log final das tabelas
    log_info "Database schema summary:"
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "${DB_PORT:-5432}" -U "${DB_USER:-postgres}" -d "$db_name" -tAc \
        "SELECT tablename || ' (' || (SELECT count(*) FROM information_schema.columns WHERE table_name=tablename AND table_schema='public') || ' columns)' FROM pg_tables WHERE schemaname='public' ORDER BY tablename" 2>/dev/null | while read info; do
        log_info "  $info"
    done
}

# =============================================================
# Main
# =============================================================
log_info "============================================"
log_info "MCP-SCT v0.6.0 starting..."
log_info "Mode: ${MCP_SCT_MODE:-stdio}"
log_info "============================================"

# Executa migrações se banco configurado
if [ -n "$DB_HOST" ]; then
    if wait_for_postgres; then
        create_database
        run_migrations
    fi

    # Monta a DATABASE_URL para o Go
    export DATABASE_URL="postgres://${DB_USER:-postgres}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT:-5432}/${DB_NAME:-mcp_sct}?sslmode=${DB_SSLMODE:-disable}"
    log_info "Database URL configured"
else
    log_info "No database configured (DB_HOST not set)"
    log_info "Using in-memory storage"
fi

# MCPize sets PORT env var - use it if MCP_SCT_ADDR not explicitly set
if [ -n "$PORT" ] && [ "$MCP_SCT_ADDR" = ":8080" ]; then
    export MCP_SCT_ADDR=":$PORT"
    log_info "Using MCPize PORT: $PORT"
fi

log_info "Listening on ${MCP_SCT_ADDR}"
log_info "============================================"
log_info "Starting MCP-SCT server..."
log_info "============================================"

# Executa o servidor MCP-SCT passando todos os argumentos
exec mcp-sct "$@"
