// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! HTTP handlers for DB's table-lifecycle and data-CRUD APIs.
//!
//! Stories; hardening pass -
//! (`design/sentin8-sentin8-db-technical-design.md` ).
//!
//! Every handler that touches tenant data follows the same shape:
//! verify bearer token → check scope → resolve + validate target env →
//! open an explicit transaction → set RLS context on that transaction →
//! execute the statement on the same transaction → commit. RLS context is
//! always stamped from the verified token claims.

use sentin8::middleware::health::LiveHealth;
use std::sync::Arc;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use sqlx::{Column, Row};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::config::Db8Config;
use crate::rls;

type DdlAuditRow = (
    Uuid,
    Option<Uuid>,
    String,
    String,
    Option<Uuid>,
    Option<String>,
    serde_json::Value,
    chrono::DateTime<chrono::Utc>,
);

#[derive(Clone)]
/// app state.
pub struct AppState {
    /// The config.
    pub config: Arc<Db8Config>,
    /// The pool.
    pub pool: sqlx::PgPool,
    /// Shield engine : additional gate after scope.
    /// The policy.
    pub policy: Arc<crate::policy::Engine>,
    /// Shared Sentin8:Policy admin surface ( - one
    /// implementation for every service; mounted in server::routes).
    /// The admin.
    pub admin: sentin8::shield::admin::SharedAdminState,
}

type HandlerError = (StatusCode, String);

/// Query parameter for cross-env operations - allows callers (e.g. BFF) to
/// target a specific env. Only honored when the caller carries platform-admin
/// authority (`sentin8:sys:admin`) or targets their own env.
#[derive(Debug, Deserialize, Default, utoipa::IntoParams, utoipa::ToSchema)]
/// The targetenvquery type.
pub struct TargetEnvQuery {
    #[serde(default)]
    /// target env identifier.
    pub target_env_id: Option<String>,
}

/// Resolve the requested target env from the query param or the
/// `x-sentin8-env-id` header, falling back to the token's env. A caller may
/// name a foreign env only if it is a platform admin (`sentin8:sys:admin`) or holds
/// an RBAC role/group in the target env (mirrors app's
/// `require_target_env_access` - design ,
/// rule 5: requests that cannot resolve a valid tenant context are
/// rejected, never silently retargeted).
async fn resolve_env_id(
    pool: &sqlx::PgPool,
    teq: &TargetEnvQuery,
    headers: &axum::http::HeaderMap,
    auth: &sentin8::auth::client::AuthContext,
) -> Result<Uuid, HandlerError> {
    let requested = teq
        .target_env_id
        .as_deref()
        .and_then(|s| Uuid::parse_str(s).ok())
        .or_else(|| {
            headers
                .get("x-sentin8-env-id")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| Uuid::parse_str(s).ok())
        });

    let Some(target) = requested else {
        return Ok(auth.env_id());
    };
    if target == auth.env_id() || auth.is_platform_admin() {
        return Ok(target);
    }
    // Cross-env callers must hold RBAC membership in the target env (direct
    // role or group role). - the RBAC tables are RLS'd; set the
    // SYSTEM_ENV context on this helper's own transaction ( rule 2).
    let user_id = uuid::Uuid::parse_str(auth.claims.sub.as_str()).unwrap_or(uuid::Uuid::nil());
    let mut tx = pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let _ = sqlx::query("SELECT sentin8_set_tenant_context($1)")
        .bind(sentin8::config::SYSTEM_ENV_ID)
        .execute(&mut *tx)
        .await;
    let member: Option<bool> = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM user_roles ur
            JOIN roles r ON r.id = ur.role_id
            WHERE ur.user_id = $1 AND r.env_id = $2
            UNION
            SELECT 1 FROM group_members gm
            JOIN groups g ON g.id = gm.group_id
            WHERE gm.user_id = $1 AND g.env_id = $2
        )"#,
    )
    .bind(user_id)
    .bind(target)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    if member == Some(true) {
        Ok(target)
    } else {
        Err((
            StatusCode::FORBIDDEN,
            "caller has no role or group in the target env".into(),
        ))
    }
}

/// Resolve the target env and require the caller to be authorized for it.
async fn require_env(
    pool: &sqlx::PgPool,
    teq: &TargetEnvQuery,
    headers: &axum::http::HeaderMap,
    auth: &sentin8::auth::client::AuthContext,
) -> Result<Uuid, HandlerError> {
    resolve_env_id(pool, teq, headers, auth).await
}

/// Public wrapper used by the admin-UI handlers (same validation path as
/// the main handlers - design ).
/// Resolve admin env.
pub async fn resolve_admin_env(
    pool: &sqlx::PgPool,
    teq: &TargetEnvQuery,
    headers: &axum::http::HeaderMap,
    auth: &sentin8::auth::client::AuthContext,
) -> Result<Uuid, HandlerError> {
    require_env(pool, teq, headers, auth).await
}

// ── Table lifecycle ─────────────────────────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for createtable.
pub struct CreateTableRequest {
    /// The table name.
    pub table_name: String,
    /// The display name.
    pub display_name: String,
    #[serde(default)]
    /// The columns.
    pub columns: Vec<sentin8_db_sdk::contracts::ColumnDef>,
}

#[derive(Serialize, ToSchema)]
/// Response payload for table.
pub struct TableResponse {
    /// Identifier.
    pub id: Uuid,
    /// The table name.
    pub table_name: String,
    /// The display name.
    pub display_name: String,
    /// The status.
    pub status: String,
}

/// `POST /v1/tables` - create a table with mandatory system columns + RLS.
///
/// Creates the physical PostgreSQL table with the mandatory system column set
/// (`id`, `env_id`, `data` JSONB, `created_at`, `updated_at`,
/// `resource_version`, `deleted_at`), enables + forces RLS, creates the four
/// env-scoped policies, registers the table in `table_registry`, writes the
/// `create` DDL audit row, and emits the `sentin8:db:table:created` event -
/// registry, audit, and event all in the SAME transaction as the domain
/// change.
#[utoipa::path(
    post,
    operation_id = "table.create",
    path = "/v1/tables",
    request_body = CreateTableRequest,
    responses(
        (status = 200, description = "Table created", body = TableResponse),
        (status = 403, description = "Missing db:table:admin scope"),
    ),
    security(("sentin8:db:table:admin" = [])),
    tag = "db",
)]
/// Create table.
pub async fn create_table(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<CreateTableRequest>,
) -> Result<Json<TableResponse>, HandlerError> {
    if req.table_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "table_name is required".into()));
    }

    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:table:admin"),
    )
    .await?;

    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let logical_name = sanitize_identifier(&req.table_name);
    if logical_name.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "table_name is required".into()));
    }
    let display_name = req.display_name.clone();
    let table_id = Uuid::new_v4();

    let env_hash: String = env_id.simple().to_string()[..8].to_string();
    let physical_name = format!("sentin8_db_{}_{}", env_hash, logical_name);

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    // Purge a dropped prior incarnation so the logical name is reusable.
    // Only 'dropped' rows are purged; active/archived collisions surface
    // as 409 from the registry insert below.
    sqlx::query(
        "DELETE FROM table_registry WHERE env_id = $1 AND logical_name = $2 AND status = 'dropped'",
    )
    .bind(env_id)
    .bind(&logical_name)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry purge failed: {e}"),
        )
    })?;

    // Mandatory system columns + user-defined typed columns.
    let mut ddl = format!(
        r#"CREATE TABLE IF NOT EXISTS {physical_name} (
            id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            env_id           UUID NOT NULL,
            data             JSONB,
            created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            updated_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
            resource_version INTEGER NOT NULL DEFAULT 1,
            deleted_at       TIMESTAMPTZ"#
    );
    for col in &req.columns {
        let col_name = sanitize_identifier(&col.name);
        if col_name.is_empty() || is_reserved_column(&col_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("column name '{col_name}' is reserved or invalid"),
            ));
        }
        let nullable = if col.nullable { "" } else { " NOT NULL" };
        let default = col
            .default
            .as_ref()
            .map(|d| format!(" DEFAULT {d}"))
            .unwrap_or_default();
        ddl.push_str(&format!(
            ",\n            {col_name} {}{nullable}{default}",
            col.data_type
        ));
    }
    ddl.push_str("\n        )");

    sqlx::query(&ddl).execute(&mut *tx).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("DDL failed: {e}"),
        )
    })?;

    // RLS enable + force + four policies.
    for stmt in [
        format!("ALTER TABLE {physical_name} ENABLE ROW LEVEL SECURITY"),
        format!("ALTER TABLE {physical_name} FORCE ROW LEVEL SECURITY"),
        format!(
            r#"CREATE POLICY {physical_name}_select ON {physical_name} FOR SELECT USING (
                sentin8_context_initialized()
                AND env_id = sentin8_current_env_id()
            )"#
        ),
        format!(
            r#"CREATE POLICY {physical_name}_insert ON {physical_name} FOR INSERT WITH CHECK (
                sentin8_context_initialized()
                AND env_id = sentin8_current_env_id()
            )"#
        ),
        format!(
            r#"CREATE POLICY {physical_name}_update ON {physical_name} FOR UPDATE USING (
                sentin8_context_initialized()
                AND env_id = sentin8_current_env_id()
            )"#
        ),
        format!(
            r#"CREATE POLICY {physical_name}_delete ON {physical_name} FOR DELETE USING (
                sentin8_context_initialized()
                AND env_id = sentin8_current_env_id()
            )"#
        ),
    ] {
        sqlx::query(&stmt).execute(&mut *tx).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("RLS setup failed: {e}"),
            )
        })?;
    }

    // Register + audit + event in the same transaction as the domain change.
    let insert_result =
        sqlx::query("INSERT INTO table_registry (id, env_id, logical_name, physical_name, status) VALUES ($1, $2, $3, $4, 'active')")
            .bind(table_id)
            .bind(env_id)
            .bind(&logical_name)
            .bind(&physical_name)
            .execute(&mut *tx)
            .await;
    if let Err(sqlx::Error::Database(ref e)) = insert_result {
        if e.is_unique_violation() {
            return Err((
                StatusCode::CONFLICT,
                "a table with this name already exists in this environment".into(),
            ));
        }
    }
    insert_result.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("registry insert failed: {e}"),
        )
    })?;

    write_ddl_audit(
        &mut tx,
        env_id,
        table_id,
        &logical_name,
        "create",
        &auth,
        serde_json::json!({"physical_name": physical_name, "columns": req.columns.len()}),
    )
    .await?;

    emit_event_tx(
        &mut tx,
        env_id,
        &state.config.stream_family,
        "sentin8:db:table:created",
        &serde_json::json!({"id": table_id, "table_name": logical_name}),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(TableResponse {
        id: table_id,
        table_name: logical_name,
        display_name,
        status: "active".into(),
    }))
}

/// `GET /v1/tables` - list active tables for the resolved env.
#[utoipa::path(
    get,
    operation_id = "table.list",
    path = "/v1/tables",
    params(("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "List of tables", body = [TableResponse]),
    ),
    security(("sentin8:db:data:read" = [])),
    tag = "db",
)]
/// List tables.
pub async fn list_tables(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<Json<Vec<TableResponse>>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:read"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, logical_name, status FROM table_registry WHERE env_id = $1 AND status = 'active' ORDER BY logical_name",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let tables = rows
        .into_iter()
        .map(|(id, logical_name, status)| TableResponse {
            id,
            display_name: logical_name.clone(),
            table_name: logical_name,
            status,
        })
        .collect();
    Ok(Json(tables))
}

/// `GET /v1/tables/{id}` - get table metadata. Env-scoped + authenticated
/// ; a foreign-env id 404s.
#[utoipa::path(
    get,
    operation_id = "table.get",
    path = "/v1/tables/{id}",
    params(("id" = Uuid, Path, description = "Table ID"), ("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "Table metadata", body = TableResponse),
        (status = 404, description = "Table not found"),
        (status = 403, description = "Missing db:data:read scope"),
    ),
    security(("sentin8:db:data:read" = [])),
    tag = "db",
)]
/// Fetch table.
pub async fn get_table(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<TableResponse>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:read"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query_as::<_, (Uuid, String, String)>(
        "SELECT id, logical_name, status FROM table_registry WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    match row {
        Some((id, logical_name, status)) => Ok(Json(TableResponse {
            id,
            table_name: logical_name.clone(),
            display_name: logical_name,
            status,
        })),
        None => Err((StatusCode::NOT_FOUND, format!("table {id} not found"))),
    }
}

/// Resolve a logical table name to its physical PostgreSQL table via
/// `table_registry`. Must run inside a transaction that already has the
/// RLS context set; the physical name is the only name that exists in the
/// database - data handlers never query the bare logical name.
async fn resolve_physical_table(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    logical: &str,
) -> Result<String, HandlerError> {
    let logical = sanitize_identifier(logical);
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT physical_name FROM table_registry WHERE logical_name = $1 AND env_id = $2 AND status = 'active'",
    )
    .bind(&logical)
    .bind(env_id)
    .fetch_optional(&mut **tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    row.map(|r| r.0).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            format!("table {logical} not found in this environment"),
        )
    })
}

// ── Data CRUD ───────────────────────────────────────────────────────────

/// `POST /v1/data/query` - query rows with filters, sorts, pagination.
/// Soft-deleted rows (`deleted_at IS NOT NULL`) are excluded.
#[utoipa::path(
    post,
    operation_id = "data.query",
    path = "/v1/data/query",
    request_body = sentin8_db_sdk::contracts::QueryRequest,
    responses(
        (status = 200, description = "Query results", body = sentin8_db_sdk::contracts::QueryResponse),
        (status = 403, description = "Missing db:data:read scope"),
    ),
    security(("sentin8:db:data:read" = [])),
    tag = "db",
)]
/// Handle query.
pub async fn query(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<sentin8_db_sdk::contracts::QueryRequest>,
) -> Result<Json<sentin8_db_sdk::contracts::QueryResponse>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:read"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Interactive tier (db README §7): a 5s cap bounds runaway reads.
    rls::set_statement_timeout(&mut tx, rls::STATEMENT_TIMEOUT_INTERACTIVE_MS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let table_name = resolve_physical_table(&mut tx, env_id, &req.table).await?;

    let limit = req.pagination.limit.unwrap_or(100).min(1000) as i64;
    // Keyset cursor (DB-3, db README §7): when set, it takes precedence over
    // the offset window - stable under inserts between pages.
    let after = req.pagination.after;
    let keyset = after.is_some();

    // WHERE: soft-delete exclusion + sanitized exact-match filters.
    // Filter grammar (db design): "update and delete accept the same filters
    // object (an `id` filter is simply one predicate)" - system columns are
    // only reserved for SET/INSERT (managed by handlers), not for WHERE.
    let mut where_parts = vec!["deleted_at IS NULL".to_string()];
    let mut bindings: Vec<String> = Vec::new();
    if let Some(filters) = req.filters.as_object() {
        for (col, value) in filters {
            let col_name = sanitize_identifier(col);
            if col_name.is_empty() {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("invalid filter column '{col}'"),
                ));
            }
            let param = format!("${}", bindings.len() + 1);
            // Cast the bound text param to the column's type - system UUID
            // columns (`id`) reject a bare text comparison, and typed columns
            // keep their declared type (design "Filter grammar": exact-match
            // predicates against the physical column).
            let cast = if col_name == "id" || col_name == "env_id" {
                "::uuid"
            } else {
                "::text"
            };
            where_parts.push(format!("{col_name} = {param}{cast}"));
            bindings.push(json_scalar_text(value)?);
        }
    }

    // ORDER BY: sanitized columns, direction restricted to ASC/DESC.
    let mut order_by = String::new();
    if !req.sort.is_empty() {
        let mut parts = Vec::new();
        for s in &req.sort {
            let col_name = sanitize_identifier(&s.column);
            if col_name.is_empty() || is_reserved_column(&col_name) {
                return Err((
                    StatusCode::BAD_REQUEST,
                    format!("invalid sort column '{}'", s.column),
                ));
            }
            let dir = if s.descending { "DESC" } else { "ASC" };
            parts.push(format!("{col_name} {dir}"));
        }
        order_by = format!(" ORDER BY {}", parts.join(", "));
    }
    // Keyset mode (DB-3): the cursor is the last-seen row id - pin the
    // order to (requested sort, id) so the scan is deterministic and the
    // `id > $after` predicate aligns with it.
    let mut cursor_where = String::new();
    if keyset {
        if !order_by.contains(" id ") {
            let dir = if req.sort.first().map(|s| s.descending).unwrap_or(false) {
                "DESC"
            } else {
                "ASC"
            };
            if order_by.is_empty() {
                order_by = format!(" ORDER BY id {dir}");
            } else {
                order_by = format!("{order_by}, id {dir}");
            }
        }
        cursor_where = format!(" AND id > ${}", bindings.len() + 2);
    }

    // LIMIT/OFFSET bind slots come after the filter bindings.
    let limit_param = bindings.len() + 1;
    let (sql, _offset_sql) = if keyset {
        (
            format!(
                "SELECT * FROM {table_name} WHERE {}{cursor_where}{order_by} LIMIT ${limit_param}",
                where_parts.join(" AND ")
            ),
            String::new(),
        )
    } else {
        let offset_param = bindings.len() + 2;
        (
            format!(
                "SELECT * FROM {table_name} WHERE {}{order_by} LIMIT ${limit_param} OFFSET ${offset_param}",
                where_parts.join(" AND ")
            ),
            String::new(),
        )
    };

    let mut q = sqlx::query(&sql);
    for b in &bindings {
        q = q.bind(b);
    }
    // Bind exactly what the chosen SQL form declares: keyset pins `LIMIT $n`
    // (after the filter binds + the `id > ${n+1}` cursor), the offset window
    // has `LIMIT $n OFFSET ${n+1}` - one page parameter each. A mismatch
    // aborts the statement ("bind message supplies N parameters, but
    // prepared statement requires M").
    q = q.bind(limit);
    if keyset {
        q = q.bind(after.expect("keyset implies an after cursor"));
    } else {
        q = q.bind(0_i64);
    }
    let rows = q.fetch_all(&mut *tx).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("query failed: {e}"),
        )
    })?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let json_rows: Vec<serde_json::Value> = rows.into_iter().map(row_to_json).collect();
    // next_cursor (DB-3): the last row's id when the page is full - null
    // when the page is short (end of the stream).
    let next_cursor = if json_rows.len() as i64 == limit {
        json_rows.last().and_then(|r| {
            r.get("id")
                .and_then(|v| v.as_str().and_then(|s| uuid::Uuid::parse_str(s).ok()))
        })
    } else {
        None
    };
    let total = json_rows.len() as u64;
    Ok(Json(sentin8_db_sdk::contracts::QueryResponse {
        rows: json_rows,
        total,
        next_cursor,
    }))
}

#[derive(Debug, Deserialize, ToSchema)]
/// Request body for insert.
pub struct InsertRequest {
    /// The table.
    pub table: String,
    /// The rows.
    pub rows: Vec<serde_json::Value>,
}

/// `POST /v1/data/insert` - insert rows with mandatory system columns.
///
/// Each row is split per design : `env_id` system column, the full JSON
/// body into `data`, and any keys matching a declared typed column into that
/// column. Typed columns are resolved from the physical table schema at
/// insert time.
#[utoipa::path(
    post,
    operation_id = "data.insert",
    path = "/v1/data/insert",
    request_body = InsertRequest,
    responses(
        (status = 200, description = "Rows inserted"),
        (status = 403, description = "Missing db:data:write scope"),
    ),
    security(("sentin8:db:data:write" = [])),
    tag = "db",
)]
/// Handle insert.
pub async fn insert(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<InsertRequest>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    if req.rows.is_empty() {
        return Ok(Json(serde_json::json!({"inserted": 0})));
    }

    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:write"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Batch tier (db README §7): multi-row insert gets the 60s cap.
    rls::set_statement_timeout(&mut tx, rls::STATEMENT_TIMEOUT_BATCH_MS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let table_name = resolve_physical_table(&mut tx, env_id, &req.table).await?;

    // Declared typed columns are read from the physical table itself -
    // a single round-trip, always in sync with the schema.
    let typed = physical_columns(&mut tx, &table_name).await?;

    let mut inserted = 0u64;
    let mut inserted_ids: Vec<serde_json::Value> = Vec::new();
    for row in &req.rows {
        let obj = row.as_object().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "each row must be a JSON object".into(),
            )
        })?;
        let mut cols = vec!["env_id".to_string(), "data".to_string()];
        let mut vals = vec!["$1".to_string(), "$2".to_string()];
        for name in &typed {
            if obj.contains_key(name) {
                let param = format!("${}", cols.len() + 1);
                cols.push(name.clone());
                vals.push(param);
            }
        }

        let insert_sql = format!(
            "INSERT INTO {table_name} ({}) VALUES ({}) RETURNING id",
            cols.join(", "),
            vals.join(", ")
        );
        let mut q = sqlx::query_as::<_, (Uuid,)>(&insert_sql)
            .bind(env_id)
            .bind(row);
        for name in &typed {
            if let Some(v) = obj.get(name) {
                q = q.bind(v);
            }
        }
        let r: (Uuid,) = q.fetch_one(&mut *tx).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("insert failed: {e}"),
            )
        })?;
        inserted += 1;
        inserted_ids.push(serde_json::json!(r.0));
    }
    // Row-level audit (db README §7, DB-4): one journal row per mutation
    // carrying the affected row ids in `details` - the shell's journal
    // pusher (step 8c) forwards it to Sys so admin UIs can show exactly
    // which rows a data mutation touched.
    write_data_audit(
        &mut tx,
        env_id,
        &auth,
        "insert",
        &req.table,
        &serde_json::json!({ "table": req.table, "affected_ids": inserted_ids }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"inserted": inserted})))
}

/// DB-4 (db README §7): write a data-mutation audit journal row with the
/// affected row ids in `details`. Same transaction as the mutation -
/// exactly-once with the domain change (the journal pusher retries until
/// Sys accepts the push).
async fn write_data_audit(
    tx: &mut sqlx::PgConnection,
    env_id: Uuid,
    auth: &sentin8::auth::client::AuthContext,
    action: &str,
    resource: &str,
    details: &serde_json::Value,
) -> Result<(), HandlerError> {
    sqlx::query(
        r#"INSERT INTO audit_journal
             (env_id, action, target_resource_type, target_resource_id,
              actor_user_id, actor_subject_type, details)
           VALUES ($1, $2, 'table', $3, $4, $5, $6)"#,
    )
    .bind(env_id)
    .bind(action)
    .bind(resource)
    .bind(&auth.claims.sub)
    .bind(&auth.claims.token_tp)
    .bind(details)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("audit journal insert failed: {e}"),
        )
    })?;
    Ok(())
}

// ── Health ──────────────────────────────────────────────────────────────

/// Handle health.
#[utoipa::path(
    get,
    path = "/v1/health",
    responses(
        (status = 200, description = "Liveness (version, build, active connections)", body = sentin8::middleware::health::LiveHealth),
    ),
    security(),
    tag = "meta",
)]
pub async fn health() -> Json<LiveHealth> {
    Json(LiveHealth {
        status: "ok".to_string(),
        service: None,
        version: Some(sentin8::build_info::id()),
        build: Some(sentin8::build_info::build_hash().to_string()),
        active_connections: sentin8::middleware::traffic_counter::process_active_connections()
            .map(|n| n as i64),
    })
}

// ── Table Alter (Stories) ───────────────────────────────────────────

/// `POST /v1/tables/{id}/alter` - safe schema alteration (ADD COLUMN only).
/// Env-scoped; audited + event emitted in the same transaction.
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for altertable.
pub struct AlterTableRequest {
    /// The add columns.
    pub add_columns: Vec<sentin8_db_sdk::contracts::ColumnDef>,
}

#[utoipa::path(
    post,
    operation_id = "table.alter",
    path = "/v1/tables/{id}/alter",
    params(("id" = Uuid, Path, description = "Table ID"), ("target_env_id" = Option<String>, Query, description = "Target env ID")),
    request_body = AlterTableRequest,
    responses(
        (status = 200, description = "Table altered"),
        (status = 404, description = "Table not found"),
        (status = 403, description = "Missing db:table:admin scope"),
    ),
    security(("sentin8:db:table:admin" = [])),
    tag = "db",
)]
/// Handle alter table.
pub async fn alter_table(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
    Json(req): Json<AlterTableRequest>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    if req.add_columns.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "add_columns is required".into()));
    }

    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:table:admin"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT physical_name, logical_name FROM table_registry WHERE id = $1 AND env_id = $2",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (physical_name, logical_name) =
        row.ok_or_else(|| (StatusCode::NOT_FOUND, format!("table {id} not found")))?;

    let mut stmts = Vec::new();
    for col in &req.add_columns {
        let col_name = sanitize_identifier(&col.name);
        if col_name.is_empty() || is_reserved_column(&col_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("column name '{}' is reserved or invalid", col.name),
            ));
        }
        let nullable = if col.nullable { "" } else { " NOT NULL" };
        let default = col
            .default
            .as_ref()
            .map(|d| format!(" DEFAULT {d}"))
            .unwrap_or_default();
        stmts.push(format!(
            "ALTER TABLE {physical_name} ADD COLUMN IF NOT EXISTS {col_name} {}{nullable}{default}",
            col.data_type
        ));
    }
    for stmt in &stmts {
        sqlx::query(stmt).execute(&mut *tx).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("alter table failed: {e}"),
            )
        })?;
    }

    write_ddl_audit(
        &mut tx,
        env_id,
        id,
        &logical_name,
        "alter",
        &auth,
        serde_json::json!({"columns_added": req.add_columns.len(), "physical_name": physical_name}),
    )
    .await?;

    emit_event_tx(
        &mut tx,
        env_id,
        &state.config.stream_family,
        "sentin8:db:table:altered",
        &serde_json::json!({"id": id, "columns_added": req.add_columns.len()}),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(
        serde_json::json!({"altered": true, "columns_added": req.add_columns.len()}),
    ))
}

// ── Data Update (Stories) ──────────────────────────────────────────

/// `POST /v1/data/update` - update rows by filter with resource version check.
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for update.
pub struct UpdateRequest {
    /// The table.
    pub table: String,
    #[serde(default)]
    /// The filter.
    pub filter: serde_json::Value,
    /// The set.
    pub set: serde_json::Value,
    #[serde(default)]
    /// The resource version.
    pub resource_version: Option<i32>,
}

#[utoipa::path(
    post,
    operation_id = "data.update",
    path = "/v1/data/update",
    request_body = UpdateRequest,
    responses(
        (status = 200, description = "Rows updated"),
        (status = 403, description = "Missing db:data:write scope"),
    ),
    security(("sentin8:db:data:write" = [])),
    tag = "db",
)]
/// Update it.
pub async fn update(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<UpdateRequest>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:write"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let set_obj = req
        .set
        .as_object()
        .ok_or_else(|| (StatusCode::BAD_REQUEST, "set must be a JSON object".into()))?;
    if set_obj.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "set must not be empty".into()));
    }

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Interactive tier (db README §7): a 5s cap bounds runaway updates.
    rls::set_statement_timeout(&mut tx, rls::STATEMENT_TIMEOUT_INTERACTIVE_MS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let table_name = resolve_physical_table(&mut tx, env_id, &req.table).await?;

    // SET clause - values are bound parameters; only names are interpolated.
    let mut set_parts = Vec::new();
    let mut bindings: Vec<String> = Vec::new();
    for (key, value) in set_obj {
        let col_name = sanitize_identifier(key);
        if col_name.is_empty() || is_reserved_column(&col_name) {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid set column '{key}'"),
            ));
        }
        let param = format!("${}", bindings.len() + 1);
        set_parts.push(format!("{col_name} = {param}::text"));
        bindings.push(value.to_string());
    }

    // WHERE: soft-deleted rows are not updatable; exact-match filters are
    // mandatory (an empty filter object is a request bug, design ).
    let filter_obj = req
        .filter
        .as_object()
        .filter(|f| !f.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "filter must be a non-empty JSON object".into(),
            )
        })?;
    let mut where_parts = vec!["deleted_at IS NULL".to_string()];
    for (col, value) in filter_obj {
        let col_name = sanitize_identifier(col);
        // Filter grammar: an `id` filter is one predicate (db design) -
        // reserved columns are rejected for SET only.
        if col_name.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid filter column '{col}'"),
            ));
        }
        let param = format!("${}", bindings.len() + 1);
        let cast = if col_name == "id" || col_name == "env_id" {
            "::uuid"
        } else {
            "::text"
        };
        where_parts.push(format!("{col_name} = {param}{cast}"));
        bindings.push(json_scalar_text(value)?);
    }

    // Optimistic concurrency on resource_version.
    if let Some(rv) = req.resource_version {
        let param = format!("${}", bindings.len() + 1);
        where_parts.push(format!("resource_version = {param}"));
        bindings.push(rv.to_string());
    }

    set_parts.push("updated_at = now()".to_string());
    set_parts.push("resource_version = resource_version + 1".to_string());

    let sql = format!(
        "UPDATE {table_name} SET {} WHERE {} RETURNING id",
        set_parts.join(", "),
        where_parts.join(" AND ")
    );
    let mut q = sqlx::query_as::<_, (Uuid,)>(&sql);
    for b in &bindings {
        q = q.bind(b);
    }
    let affected: Vec<(Uuid,)> = q.fetch_all(&mut *tx).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("update failed: {e}"),
        )
    })?;
    let updated = affected.len() as u64;
    let affected_ids: Vec<serde_json::Value> = affected
        .into_iter()
        .map(|r| serde_json::json!(r.0))
        .collect();
    // Row-level audit (db README §7, DB-4): affected ids in the journal row.
    write_data_audit(
        &mut tx,
        env_id,
        &auth,
        "update",
        &req.table,
        &serde_json::json!({
            "table": req.table,
            "set": req.set,
            "filter": req.filter,
            "affected_ids": affected_ids,
        }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"updated": updated})))
}

// ── Data Delete (Stories) ───────────────────────────────────────────

/// `POST /v1/data/delete` - soft-delete rows by filter (`deleted_at = now`).
/// No hard-delete fallback: physical removal happens only via the controlled
/// drop flow.
#[derive(Debug, Deserialize, ToSchema)]
/// Request body for delete.
pub struct DeleteRequest {
    /// The table.
    pub table: String,
    #[serde(default)]
    /// The filter.
    pub filter: serde_json::Value,
}

#[utoipa::path(
    post,
    operation_id = "data.delete",
    path = "/v1/data/delete",
    request_body = DeleteRequest,
    responses(
        (status = 200, description = "Rows deleted"),
        (status = 403, description = "Missing db:data:write scope"),
    ),
    security(("sentin8:db:data:write" = [])),
    tag = "db",
)]
/// Delete it.
pub async fn delete(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<DeleteRequest>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:data:write"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let filter_obj = req
        .filter
        .as_object()
        .filter(|f| !f.is_empty())
        .ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                "filter must be a non-empty JSON object".into(),
            )
        })?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    // Interactive tier (db README §7): a 5s cap bounds runaway deletes.
    rls::set_statement_timeout(&mut tx, rls::STATEMENT_TIMEOUT_INTERACTIVE_MS)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let table_name = resolve_physical_table(&mut tx, env_id, &req.table).await?;

    let mut where_parts = vec!["deleted_at IS NULL".to_string()];
    let mut bindings: Vec<String> = Vec::new();
    for (col, value) in filter_obj {
        let col_name = sanitize_identifier(col);
        // Filter grammar: an `id` filter is one predicate (db design) -
        // reserved columns are rejected for SET/INSERT only.
        if col_name.is_empty() {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("invalid filter column '{col}'"),
            ));
        }
        let param = format!("${}", bindings.len() + 1);
        let cast = if col_name == "id" || col_name == "env_id" {
            "::uuid"
        } else {
            "::text"
        };
        where_parts.push(format!("{col_name} = {param}{cast}"));
        bindings.push(json_scalar_text(value)?);
    }

    let sql = format!(
        "UPDATE {table_name} SET deleted_at = now(), updated_at = now(), resource_version = resource_version + 1 WHERE {} RETURNING id",
        where_parts.join(" AND ")
    );
    let mut q = sqlx::query_as::<_, (Uuid,)>(&sql);
    for b in &bindings {
        q = q.bind(b);
    }
    let affected: Vec<(Uuid,)> = q.fetch_all(&mut *tx).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("delete failed: {e}"),
        )
    })?;
    let deleted = affected.len() as u64;
    let affected_ids: Vec<serde_json::Value> = affected
        .into_iter()
        .map(|r| serde_json::json!(r.0))
        .collect();
    // Row-level audit (db README §7, DB-4): affected ids in the journal row.
    write_data_audit(
        &mut tx,
        env_id,
        &auth,
        "delete",
        &req.table,
        &serde_json::json!({
            "table": req.table,
            "filter": req.filter,
            "affected_ids": affected_ids,
        }),
    )
    .await?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({"deleted": deleted})))
}

// ── Helpers ─────────────────────────────────────────────────────────────

/// Sanitize an identifier for use in SQL - only ASCII alphanumeric + underscore.
/// Extract a filter/set value's scalar text from a JSON value. A JSON
/// string `"abc"` binds as `abc` (not `"abc"` - the quotes are JSON syntax,
/// never data); numbers and booleans bind as their literal text; objects /
/// arrays / nulls are rejected (exact-match predicates are scalar-only).
/// Handle JSON scalar text.
pub fn json_scalar_text(v: &serde_json::Value) -> Result<String, (StatusCode, String)> {
    match v {
        serde_json::Value::String(s) => Ok(s.clone()),
        serde_json::Value::Number(n) => Ok(n.to_string()),
        serde_json::Value::Bool(b) => Ok(b.to_string()),
        other => Err((
            StatusCode::BAD_REQUEST,
            format!("filter value must be a JSON string, number, or boolean, got: {other}"),
        )),
    }
}

/// Handle sanitize identifier.
pub fn sanitize_identifier(name: &str) -> String {
    let cleaned: String = name
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim_matches('_').to_string();
    if trimmed.is_empty() {
        "_invalid_".to_string()
    } else {
        trimmed
    }
}

/// Columns that handlers manage themselves; callers may never set or filter on them.
fn is_reserved_column(name: &str) -> bool {
    matches!(
        name,
        "id" | "env_id"
            | "data"
            | "created_at"
            | "updated_at"
            | "resource_version"
            | "deleted_at"
            | "usr_id"
            | "visibility"
    )
}

/// Typed column names present on the physical table (from CREATE/ALTER).
async fn physical_columns(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    physical_name: &str,
) -> Result<Vec<String>, HandlerError> {
    let rows: Vec<(String,)> = sqlx::query_as(
        "SELECT column_name FROM information_schema.columns
         WHERE table_name = $1 AND column_name NOT IN
         ('id','env_id','data','created_at','updated_at','resource_version','deleted_at')",
    )
    .bind(physical_name)
    .fetch_all(&mut **tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(rows.into_iter().map(|r| r.0).collect())
}

/// Convert a sqlx Row to JSON: system columns typed directly, `data` payload
/// flattened (typed columns take precedence - design row shape).
fn row_to_json(row: sqlx::postgres::PgRow) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    for col in row.columns() {
        let name = col.name().to_string();
        let val: serde_json::Value = {
            if let Ok(v) = row.try_get::<Option<Uuid>, _>(name.as_str()) {
                v.map(|u| serde_json::Value::from(u.to_string()))
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) =
                row.try_get::<Option<chrono::DateTime<chrono::Utc>>, _>(name.as_str())
            {
                v.map(|t| serde_json::Value::from(t.to_rfc3339()))
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) = row.try_get::<Option<serde_json::Value>, _>(name.as_str()) {
                v.unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) = row.try_get::<Option<i64>, _>(name.as_str()) {
                v.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) = row.try_get::<Option<i32>, _>(name.as_str()) {
                v.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) = row.try_get::<Option<bool>, _>(name.as_str()) {
                v.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null)
            } else if let Ok(v) = row.try_get::<Option<String>, _>(name.as_str()) {
                v.map(serde_json::Value::from)
                    .unwrap_or(serde_json::Value::Null)
            } else {
                serde_json::Value::Null
            }
        };
        if name == "data" {
            if let serde_json::Value::Object(inner) = val {
                for (k, v) in inner {
                    obj.entry(k).or_insert(v);
                }
                continue;
            }
            if val.is_null() {
                continue;
            }
        }
        obj.insert(name, val);
    }
    serde_json::Value::Object(obj)
}

/// Write a `ddl_audit` row on the given transaction.
async fn write_ddl_audit(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    table_id: Uuid,
    table_name: &str,
    operation: &str,
    auth: &sentin8::auth::client::AuthContext,
    detail: serde_json::Value,
) -> Result<(), HandlerError> {
    sqlx::query(
        "INSERT INTO ddl_audit (env_id, table_id, table_name, operation, actor_id, actor_scope, detail)
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(env_id)
    .bind(table_id)
    .bind(table_name)
    .bind(operation)
    .bind(Uuid::parse_str(&auth.claims.sub).ok())
    .bind(&auth.claims.token_tp)
    .bind(&detail)
    .execute(&mut **tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("audit write failed: {e}")))?;
    Ok(())
}

// ── Table lifecycle: archive + drop (Stories) ─────────────

/// `POST /v1/tables/{id}/archive` - mark a table as archived (Stories).
/// Env-scoped; registry update, audit row, and event commit together.
#[utoipa::path(
    post,
    operation_id = "table.archive",
    path = "/v1/tables/{id}/archive",
    params(("id" = Uuid, Path, description = "Table ID"), ("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "Table archived"),
        (status = 404, description = "Table not found or not active"),
        (status = 403, description = "Missing db:table:admin scope"),
    ),
    security(("sentin8:db:table:admin" = [])),
    tag = "db",
)]
/// Archive table.
pub async fn archive_table(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:table:admin"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query_as::<_, (String, String)>(
        "UPDATE table_registry SET status = 'archived', updated_at = now()
         WHERE id = $1 AND env_id = $2 AND status = 'active'
         RETURNING logical_name, physical_name",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (logical_name, physical_name) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "table not found or not active".into(),
        )
    })?;

    write_ddl_audit(
        &mut tx,
        env_id,
        id,
        &logical_name,
        "archive",
        &auth,
        serde_json::json!({"physical_name": physical_name}),
    )
    .await?;

    emit_event_tx(
        &mut tx,
        env_id,
        &state.config.stream_family,
        "sentin8:db:table:archived",
        &serde_json::json!({"id": id, "table_name": logical_name}),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "status": "archived",
        "table_name": logical_name,
    })))
}

/// `POST /v1/tables/{id}/drop` - pending-delete then drop (Stories).
/// Env-scoped; registry status, physical DROP, audit row, and event commit
/// together - a failed DROP rolls the registry status back.
#[utoipa::path(
    post,
    operation_id = "table.drop",
    path = "/v1/tables/{id}/drop",
    params(("id" = Uuid, Path, description = "Table ID"), ("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "Table dropped"),
        (status = 404, description = "Table not found or already dropped"),
        (status = 403, description = "Missing db:table:admin scope"),
    ),
    security(("sentin8:db:table:admin" = [])),
    tag = "db",
)]
/// Handle drop table.
pub async fn drop_table(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<Uuid>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:table:admin"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let row = sqlx::query_as::<_, (String, String)>(
        "UPDATE table_registry SET status = 'pending_delete', updated_at = now()
         WHERE id = $1 AND env_id = $2 AND status IN ('active', 'archived')
         RETURNING logical_name, physical_name",
    )
    .bind(id)
    .bind(env_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    let (logical_name, physical_name) = row.ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            "table not found or already dropped".into(),
        )
    })?;

    sqlx::query(&format!("DROP TABLE IF EXISTS {physical_name} CASCADE"))
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("DROP failed: {e}"),
            )
        })?;

    sqlx::query("UPDATE table_registry SET status = 'dropped', updated_at = now() WHERE id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    write_ddl_audit(
        &mut tx,
        env_id,
        id,
        &logical_name,
        "drop",
        &auth,
        serde_json::json!({"physical_name": physical_name}),
    )
    .await?;

    emit_event_tx(
        &mut tx,
        env_id,
        &state.config.stream_family,
        "sentin8:db:table:dropped",
        &serde_json::json!({"id": id, "table_name": logical_name}),
    )
    .await?;

    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(serde_json::json!({
        "id": id,
        "status": "dropped",
        "table_name": logical_name,
    })))
}

// ── Operational APIs: posture + audit (Stories) ─────────

/// `GET /v1/posture` - RLS drift detection (Stories).
#[utoipa::path(
    get,
    operation_id = "posture.get",
    path = "/v1/posture",
    params(("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "RLS posture report"),
        (status = 403, description = "Missing db:table:admin or db:posture:read scope"),
    ),
    security(("sentin8:db:posture:read" = [])),
    tag = "db",
)]
/// Handle posture.
pub async fn posture(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:posture:read"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows = sqlx::query(
        r#"SELECT
               r.id AS table_id,
               r.logical_name,
               r.physical_name,
               r.status,
               c.relrowsecurity AS rls_enabled,
               c.relforcerowsecurity AS rls_forced,
               (SELECT COUNT(*) FROM pg_policies p WHERE p.schemaname = 'public' AND p.tablename = r.physical_name) AS policy_count
           FROM table_registry r
           JOIN pg_class c ON c.relname = r.physical_name
           WHERE r.env_id = $1 AND r.status IN ('active', 'archived')"#,
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let mut findings = Vec::new();
    for row in &rows {
        let mut issues = Vec::new();
        let rls_enabled: bool = row.get("rls_enabled");
        let rls_forced: bool = row.get("rls_forced");
        let policy_count: i64 = row.try_get::<i64, _>("policy_count").unwrap_or(0);
        if !rls_enabled {
            issues.push("rls_not_enabled");
        }
        if !rls_forced {
            issues.push("rls_not_forced");
        }
        if policy_count < 4 {
            issues.push("missing_policies");
        }
        if !issues.is_empty() {
            findings.push(serde_json::json!({
                "table_id": row.get::<Uuid, _>("table_id"),
                "table_name": row.get::<String, _>("logical_name"),
                "physical_name": row.get::<String, _>("physical_name"),
                "status": row.get::<String, _>("status"),
                "issues": issues,
            }));
        }
    }

    Ok(Json(serde_json::json!({
        "total_tables": rows.len(),
        "drift_count": findings.len(),
        "findings": findings,
    })))
}

/// `GET /v1/audit` - DDL audit log (Stories).
#[utoipa::path(
    get,
    operation_id = "audit.list",
    path = "/v1/audit",
    params(("target_env_id" = Option<String>, Query, description = "Target env ID")),
    responses(
        (status = 200, description = "DDL audit log"),
        (status = 403, description = "Missing db:audit:read scope"),
    ),
    security(("sentin8:db:audit:read" = [])),
    tag = "db",
)]
/// Handle audit log.
pub async fn audit_log(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, HandlerError> {
    let auth =
        sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    crate::policy::require_policy(
        &state.policy,
        &auth,
        &headers,
        sentin8::shield::EvalTarget::new("sentin8:db:audit:read"),
    )
    .await?;
    let env_id = require_env(&state.pool, &teq, &headers, &auth).await?;

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    rls::set_rls_context(
        &mut tx,
        env_id,
        &auth.claims.sub,
        &auth.claims.token_tp,
        &auth.claims.scope,
        auth.is_platform_admin(),
    )
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<DdlAuditRow> = sqlx::query_as(
        "SELECT id, table_id, table_name, operation, actor_id, actor_scope, detail, created_at
             FROM ddl_audit WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100",
    )
    .bind(env_id)
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    tx.commit()
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let entries: Vec<serde_json::Value> = rows
        .into_iter()
        .map(
            |(id, table_id, table_name, operation, actor_id, actor_scope, detail, created_at)| {
                serde_json::json!({
                    "id": id,
                    "table_id": table_id,
                    "table_name": table_name,
                    "operation": operation,
                    "actor_id": actor_id,
                    "actor_scope": actor_scope,
                    "detail": detail,
                    "created_at": created_at,
                })
            },
        )
        .collect();

    Ok(Json(serde_json::json!({
        "entries": entries,
        "count": entries.len(),
    })))
}

/// Append an event to the shared `inbox` table **inside the domain
/// transaction** (inbox-first, design ). Failure aborts the transaction -
/// the event and the domain change commit together. The stream family
/// comes from the service config (`DB_STREAM_FAMILY`, default `db`).
async fn emit_event_tx(
    tx: &mut sqlx::Transaction<'static, sqlx::Postgres>,
    env_id: Uuid,
    stream_family: &str,
    event_type: &str,
    payload: &serde_json::Value,
) -> Result<(), HandlerError> {
    sentin8::bus::outbox::insert_outbox_row(&mut **tx, env_id, stream_family, event_type, payload)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, event_type = %event_type, "db: inbox event insert failed - rolling back domain change");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("event emit failed: {e}"),
            )
        })?;
    Ok(())
}
