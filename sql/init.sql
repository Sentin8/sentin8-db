-- SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
-- SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
-- SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
-- SPDX-License-Identifier: Apache-2.0

-- Sentin8:DB — table registry and DDL audit log.
-- The table registry stores metadata about all Sentin8:DB-managed tenant tables.
-- The DDL audit log (Story 1.3.18) records every DDL operation on tenant
-- tables for full auditability.

-- Sentin8:DB table registry — stores metadata about all Sentin8:DB-managed tenant tables.
CREATE SCHEMA IF NOT EXISTS db;
CREATE TABLE IF NOT EXISTS db.table_registry (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    logical_name    TEXT NOT NULL,
    physical_name   TEXT NOT NULL,
    status          TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'archived', 'pending_delete', 'dropped')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- physical_name is unique per env, not globally: two envs may each own
    -- a table with the same logical (and physical) name because every
    -- physical table carries env-scoped RLS. Cross-env uniqueness is
    -- guaranteed by the env hash embedded in the physical name.
    UNIQUE (env_id, physical_name),
    UNIQUE (env_id, logical_name, status)
);

CREATE INDEX IF NOT EXISTS idx_db_table_registry_env ON db.table_registry (env_id);

ALTER TABLE db.table_registry ENABLE ROW LEVEL SECURITY;
ALTER TABLE db.table_registry FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS db_table_registry_select_policy ON db.table_registry;
CREATE POLICY db_table_registry_select_policy ON db.table_registry
    FOR SELECT USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS db_table_registry_modify_policy ON db.table_registry;
CREATE POLICY db_table_registry_modify_policy ON db.table_registry
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS db_table_registry_update_policy ON db.table_registry;
CREATE POLICY db_table_registry_update_policy ON db.table_registry
    FOR UPDATE USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS db_table_registry_delete_policy ON db.table_registry;
CREATE POLICY db_table_registry_delete_policy ON db.table_registry
    FOR DELETE USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

-- Story 1.3.18 — Sentin8:DB DDL audit log.
-- Records all DDL operations (create, alter, archive, drop) for auditability.
CREATE TABLE IF NOT EXISTS db.ddl_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id  UUID NOT NULL,
    table_id        UUID NOT NULL,
    table_name      TEXT NOT NULL,
    operation       TEXT NOT NULL CHECK (operation IN ('create', 'alter', 'archive', 'drop', 'restore')),
    actor_id        UUID,
    actor_scope     TEXT,
    detail          JSONB,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_db_ddl_audit_env
    ON db.ddl_audit (env_id);
CREATE INDEX IF NOT EXISTS idx_db_ddl_audit_table
    ON db.ddl_audit (table_id);
CREATE INDEX IF NOT EXISTS idx_db_ddl_audit_created
    ON db.ddl_audit (created_at DESC);

ALTER TABLE db.ddl_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE db.ddl_audit FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS db_ddl_audit_select_policy ON db.ddl_audit;
CREATE POLICY db_ddl_audit_select_policy ON db.ddl_audit
    FOR SELECT USING (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

DROP POLICY IF EXISTS db_ddl_audit_insert_policy ON db.ddl_audit;
CREATE POLICY db_ddl_audit_insert_policy ON db.ddl_audit
    FOR INSERT WITH CHECK (
        sentin8_context_initialized()
        AND env_id = sentin8_current_env_id()
    );

-- ── Grants ──

-- sentin8_db_service: DML on all db tables + CREATE on the schema —
-- tenant-table DDL (`CREATE TABLE sentin8_db_*`, `ALTER TABLE`, `CREATE
-- POLICY`) runs under the service's own per-service role (DBX §6.6:
-- "through its own per-service role + declared grants in that database").
-- The physical tables live in THIS schema; the CREATE privilege is the
-- declared grant that makes the data-API's dynamic DDL work (design
-- "Table placement"). No BYPASSRLS — every table gets RLS immediately.
GRANT CREATE ON SCHEMA db TO sentin8_db_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON
    db.table_registry, db.ddl_audit
    TO sentin8_db_service;


-- ── Local outbox (DBX, architecture-principles §6.7) ─────────────────────
-- Producer path: db.outbox rows commit in the SAME transaction as the
-- domain change; a post-commit relay pushes them to Bus POST /v1/produce.
-- Generated from sentin8-outbox::outbox_table_sql("db").
CREATE TABLE IF NOT EXISTS db.outbox (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    event_type      TEXT NOT NULL,
    stream_family   TEXT NOT NULL,
    payload         JSONB NOT NULL,
    publisher_id_token  TEXT,
    publisher_subject   TEXT,
    relayed         BOOLEAN NOT NULL DEFAULT false,
    relayed_at      TIMESTAMPTZ,
    relay_attempts  INT NOT NULL DEFAULT 0,
    next_retry_at   TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_db_outbox_unrelayed
    ON db.outbox (created_at) WHERE relayed = false;
ALTER TABLE db.outbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE db.outbox FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS outbox_select ON db.outbox;
CREATE POLICY outbox_select ON db.outbox FOR SELECT
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_insert ON db.outbox;
CREATE POLICY outbox_insert ON db.outbox FOR INSERT
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
DROP POLICY IF EXISTS outbox_update ON db.outbox;
CREATE POLICY outbox_update ON db.outbox FOR UPDATE
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id());
CREATE OR REPLACE FUNCTION db.db_notify_outbox() RETURNS TRIGGER
LANGUAGE plpgsql AS $fn$
BEGIN
    PERFORM pg_notify('db_outbox_changed', '');
    RETURN NEW;
END;
$fn$;
DROP TRIGGER IF EXISTS outbox_notify_trigger ON db.outbox;
CREATE TRIGGER outbox_notify_trigger
    AFTER INSERT ON db.outbox
    FOR EACH ROW
    EXECUTE FUNCTION db.db_notify_outbox();


-- ── Local audit journal (DBX §6.8) ────────────────────────────────────────
-- Spill journal for the canonical audit push: rows written same-tx as the
-- domain change, pushed to Sys POST /v1/audit (sentin8:sys:audit:write), then
-- marked pushed. A Sys outage never drops audit. Generated from
-- sentin8-audit::audit_journal_sql("db").
CREATE TABLE IF NOT EXISTS db.audit_journal (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    env_id          UUID NOT NULL,
    action          TEXT NOT NULL,
    target_resource_type TEXT,
    target_resource_id    TEXT,
    actor_user_id   TEXT,
    actor_subject_type TEXT,
    severity        TEXT NOT NULL DEFAULT 'info',
    correlation_id  TEXT,
    before_state    JSONB,
    after_state     JSONB,
    details         JSONB,
    pushed          BOOLEAN NOT NULL DEFAULT false,
    pushed_at       TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_db_audit_journal_unpushed
    ON db.audit_journal (created_at) WHERE pushed = false;
ALTER TABLE db.audit_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE db.audit_journal FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS audit_journal_dml ON db.audit_journal;
CREATE POLICY audit_journal_dml ON db.audit_journal
    USING (sentin8_context_initialized() AND env_id = sentin8_current_env_id())
    WITH CHECK (sentin8_context_initialized() AND env_id = sentin8_current_env_id());


-- ── Schema grants (service-owned — the 2026-10-03 ownership pass) ─────
-- This service's own schema: USAGE for its role (platform.sql no longer
-- seeds per-service USAGE; the service declares it here).
GRANT USAGE ON SCHEMA db TO sentin8_db_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON db.outbox TO sentin8_db_service;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA db TO sentin8_db_service;
GRANT SELECT, INSERT, UPDATE, DELETE ON db.audit_journal TO sentin8_db_service;
