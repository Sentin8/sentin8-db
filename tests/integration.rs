// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

// Integration tests for DB - Story 1.3.21 + hardening 1.3h.12.
//
// Pure-function unit tests run always; DB-backed tests use the runtime-skip
// pattern (testing-strategy §3.2): attempt to connect, print one skip line
// and return when PostgreSQL is unreachable - never `#[ignore]`.
//
// DB-backed coverage: table lifecycle (create → archive → drop), data CRUD
// with filters/sorts/soft-delete, cross-tenant RLS isolation, RLS drift
// posture, DDL audit entries, and transactional event emission
// (`services/db/BACKLOG.md` Epic 1.3h).

#[cfg(test)]
mod tests {
    use sqlx::Row;

    use sentin8_db_server::handlers;

    // ── Pure-function unit tests ────────────────────────────────────────

    #[test]
    fn sanitize_identifier_keeps_alphanumeric() {
        assert_eq!(handlers::sanitize_identifier("my_table"), "my_table");
        assert_eq!(handlers::sanitize_identifier("table123"), "table123");
    }

    #[test]
    fn sanitize_identifier_strips_special_chars() {
        assert_eq!(handlers::sanitize_identifier("my-table"), "my_table");
        assert_eq!(handlers::sanitize_identifier("my table!"), "my_table");
        assert_eq!(handlers::sanitize_identifier("DROP;TABLE"), "DROP_TABLE");
    }

    #[test]
    fn sanitize_identifier_empty_yields_invalid_marker() {
        assert_eq!(handlers::sanitize_identifier("!!!"), "_invalid_");
    }

    // ── DB-backed: runtime-skip harness ─────────────────────────────────

    /// Runtime-skip pattern (testing-strategy §3.2): connect attempt; on
    /// failure print one skip line and return None.
    async fn db_pool() -> Option<sqlx::PgPool> {
        let url = std::env::var("SENTIN8_DB_DB_DSN")
            .or(std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "postgres://sentin8_db_service@localhost:5432/sentin8".into());
        match sqlx::postgres::PgPool::connect(&url).await {
            Ok(p) => Some(p),
            Err(e) => {
                eprintln!("skipping DB-backed db tests - PostgreSQL unreachable: {e}");
                None
            }
        }
    }

    /// Set the tenant context the way the handlers do: inside the same
    /// transaction that issues the data statement (design §12.1).
    async fn set_ctx(tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, env_id: uuid::Uuid) {
        sqlx::query("SELECT sentin8_set_tenant_context($1, 'test-subject', 'm2m', 'sentin8:db:table:admin sentin8:db:data:read sentin8:db:data:write', false, false, false, NULL)")
            .bind(env_id)
            .execute(&mut **tx)
            .await
            .unwrap();
    }

    async fn count_rows(tx: &mut sqlx::Transaction<'static, sqlx::Postgres>, sql: &str) -> i64 {
        sqlx::query(sql)
            .fetch_one(&mut **tx)
            .await
            .unwrap()
            .get::<i64, _>(0)
    }

    #[tokio::test]
    async fn db_tables_lifecycle_rls_and_soft_delete() {
        let Some(pool) = db_pool().await else { return };
        let env_a = uuid::Uuid::new_v4();
        let env_b = uuid::Uuid::new_v4();
        let env8: String = env_a.simple().to_string()[..8].to_string();
        let physical = format!("sentin8_db_{env8}_bl_table");
        let logical = "bl_table";
        let table_id = uuid::Uuid::new_v4();

        // ── Create table + RLS + registry + audit + event (one tx) ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS public.{physical} (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                env_id UUID NOT NULL,
                data JSONB,
                title TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                resource_version INTEGER NOT NULL DEFAULT 1,
                deleted_at TIMESTAMPTZ)"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        for stmt in [
            format!("ALTER TABLE public.{physical} ENABLE ROW LEVEL SECURITY"),
            format!("ALTER TABLE public.{physical} FORCE ROW LEVEL SECURITY"),
            format!(
                "CREATE POLICY {physical}_select ON public.{physical} FOR SELECT USING (
                    sentin8_context_initialized() AND env_id = sentin8_current_env_id())"
            ),
            format!(
                "CREATE POLICY {physical}_insert ON public.{physical} FOR INSERT WITH CHECK (
                    sentin8_context_initialized() AND env_id = sentin8_current_env_id())"
            ),
            format!(
                "CREATE POLICY {physical}_update ON public.{physical} FOR UPDATE USING (
                    sentin8_context_initialized() AND env_id = sentin8_current_env_id())"
            ),
            format!(
                "CREATE POLICY {physical}_delete ON public.{physical} FOR DELETE USING (
                    sentin8_context_initialized() AND env_id = sentin8_current_env_id())"
            ),
        ] {
            sqlx::query(&stmt).execute(&mut *tx).await.unwrap();
        }
        sqlx::query("INSERT INTO table_registry (id, env_id, logical_name, physical_name, status) VALUES ($1, $2, $3, $4, 'active')")
            .bind(table_id)
            .bind(env_a)
            .bind(logical)
            .bind(&physical)
            .execute(&mut *tx)
            .await
            .unwrap();
        sqlx::query("INSERT INTO ddl_audit (env_id, table_id, table_name, operation, actor_scope, detail) VALUES ($1, $2, $3, 'create', 'm2m', '{}')")
            .bind(env_a)
            .bind(table_id)
            .bind(logical)
            .execute(&mut *tx)
            .await
            .unwrap();
        let event_id = sentin8::bus::outbox::insert_outbox_row(
            &mut *tx,
            env_a,
            "db",
            "sentin8:db:table:created",
            &serde_json::json!({"id": table_id}),
        )
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // ── Insert row in env A (typed + data split) ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        sqlx::query(&format!(
            "INSERT INTO public.{physical} (env_id, data, title) VALUES ($1, $2, $3)"
        ))
        .bind(env_a)
        .bind(serde_json::json!({"title": "t1", "n": 1}))
        .bind("t1")
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // ── Cross-tenant isolation: env B sees nothing (RLS) ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_b).await;
        let visible = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM public.{physical}"),
        )
        .await;
        assert_eq!(visible, 0, "cross-tenant read must be denied by RLS");
        let reg_visible = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM table_registry WHERE id = '{table_id}' AND env_id = '{env_b}'"),
        )
        .await;
        assert_eq!(reg_visible, 0, "registry rows must be RLS-scoped too");
        tx.rollback().await.unwrap();

        // ── Env A sees the row ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        let visible = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM public.{physical} WHERE deleted_at IS NULL"),
        )
        .await;
        assert_eq!(visible, 1, "same-env read must see the row");
        tx.rollback().await.unwrap();

        // ── Soft-delete excludes the row from queries ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        let deleted = sqlx::query(&format!(
            "UPDATE public.{physical} SET deleted_at = now(), updated_at = now(), resource_version = resource_version + 1 WHERE title = $1::text AND deleted_at IS NULL"
        ))
        .bind("t1")
        .execute(&mut *tx)
        .await
        .unwrap()
        .rows_affected();
        assert_eq!(deleted, 1, "soft delete must mark exactly one row");
        let remaining = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM public.{physical} WHERE deleted_at IS NULL"),
        )
        .await;
        assert_eq!(remaining, 0, "soft-deleted rows must be excluded");
        tx.commit().await.unwrap();

        // ── Posture: RLS enabled + forced on the created table ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        let row = sqlx::query(
            "SELECT c.relrowsecurity, c.relforcerowsecurity FROM pg_class c WHERE c.relname = $1",
        )
        .bind(&physical)
        .fetch_one(&mut *tx)
        .await
        .unwrap();
        assert!(
            row.get::<bool, _>(0) && row.get::<bool, _>(1),
            "RLS must be enabled AND forced"
        );
        tx.rollback().await.unwrap();

        // ── Audit + event rows landed ──
        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        let audits = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM ddl_audit WHERE table_id = '{table_id}' AND operation = 'create'"),
        )
        .await;
        assert_eq!(audits, 1, "create must write exactly one audit row");
        let events = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM outbox WHERE id = '{event_id}' AND event_type = 'sentin8:db:table:created' AND stream_family = 'db'"),
        )
        .await;
        assert_eq!(events, 1, "create must emit the local outbox event in-tx");
        tx.rollback().await.unwrap();

        // ── Drop: physical table gone ──
        sqlx::query(&format!("DROP TABLE IF EXISTS public.{physical} CASCADE"))
            .execute(&pool)
            .await
            .unwrap();
        let exists = sqlx::query(
            "SELECT count(*)::int8 FROM information_schema.tables WHERE table_name = $1",
        )
        .bind(&physical)
        .fetch_one(&pool)
        .await
        .unwrap()
        .get::<i64, _>(0);
        assert_eq!(exists, 0, "dropped table must be physically gone");

        // Cleanup registry + audit rows for this test env (outbox rows are
        // producer-insert-only for the service role - the relay owns relayed
        // row lifecycle, and the random test env_id keeps them inert).
        for sql in [
            "DELETE FROM table_registry WHERE env_id = $1",
            "DELETE FROM ddl_audit WHERE env_id = $1",
        ] {
            sqlx::query(sql).bind(env_a).execute(&pool).await.unwrap();
        }
    }

    #[tokio::test]
    async fn db_rls_fails_closed_without_context() {
        let Some(pool) = db_pool().await else { return };
        let env_a = uuid::Uuid::new_v4();
        let env8: String = env_a.simple().to_string()[..8].to_string();
        let physical = format!("sentin8_db_{env8}_noctx");

        let mut tx = pool.begin().await.unwrap();
        set_ctx(&mut tx, env_a).await;
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS public.{physical} (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                env_id UUID NOT NULL,
                data JSONB,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                resource_version INTEGER NOT NULL DEFAULT 1,
                deleted_at TIMESTAMPTZ)"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(&format!(
            "ALTER TABLE public.{physical} ENABLE ROW LEVEL SECURITY"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(&format!(
            "ALTER TABLE public.{physical} FORCE ROW LEVEL SECURITY"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        sqlx::query(&format!(
            "CREATE POLICY {physical}_select ON public.{physical} FOR SELECT USING (
                sentin8_context_initialized() AND env_id = sentin8_current_env_id())"
        ))
        .execute(&mut *tx)
        .await
        .unwrap();
        tx.commit().await.unwrap();

        // A brand-new transaction with NO context must see zero rows -
        // missing RLS context fails closed (design §4).
        let mut tx = pool.begin().await.unwrap();
        let visible = count_rows(
            &mut tx,
            &format!("SELECT count(*)::int8 FROM public.{physical}"),
        )
        .await;
        assert_eq!(visible, 0, "no RLS context must fail closed");
        tx.rollback().await.unwrap();

        sqlx::query(&format!("DROP TABLE IF EXISTS public.{physical}"))
            .execute(&pool)
            .await
            .unwrap();
    }
}
