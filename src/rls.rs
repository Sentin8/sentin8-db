// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! RLS context setter — sets transaction-local PostgreSQL session variables
//! before any query executes.
//!
//! ```sql
//! SET LOCAL app.env_id = '<env-id>';
//! SET LOCAL app.subject_id = '<subject-id>';
//! SET LOCAL app.token_tp = '<token-tp>';
//! SET LOCAL app.scopes = '<scopes>';
//! SET LOCAL app.is_platform_admin = '<bool>';
//! SET LOCAL app.bypass_rls = '<bool>';
//! SET LOCAL app.is_env_admin = '<bool>'; -- Epic 15.5/15.6 option a
//! SET LOCAL app.sentin8_auth_user_id = '<uuid>'; -- Epic 15.6 holder-scoped RLS
//! SET LOCAL app.context_initialized = 'true';
//! ```

use uuid::Uuid;

/// Handle set RLS context.
pub async fn set_rls_context(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    subject_id: &str,
    token_tp: &str,
    scopes: &str,
    is_platform_admin: bool,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false)")
        .bind(env_id)
        .bind(subject_id)
        .bind(token_tp)
        .bind(scopes)
        .bind(is_platform_admin)
        .execute(conn)
        .await?;
    Ok(())
}

/// Statement timeout tiers (db README §7): interactive request paths get a
/// 5s cap, batch writes (multi-row insert) get 60s. `SET LOCAL` is
/// transaction-scoped — the timeout must be set INSIDE the caller's
/// transaction (same discipline as the RLS context) and evaporates at
/// commit, so pooled connections are never left with a stale cap.
/// Interactive tier statement timeout (db README §7).
pub const STATEMENT_TIMEOUT_INTERACTIVE_MS: i64 = 5_000;
/// Batch tier statement timeout (db README §7).
pub const STATEMENT_TIMEOUT_BATCH_MS: i64 = 60_000;

/// Set the transaction-local statement timeout (DB-2, db README §7).
/// Call immediately after `set_rls_context` inside the same transaction.
/// `set_config(..., is_local => true)` is the bind-safe equivalent of
/// `SET LOCAL` (the PostgreSQL protocol does not accept bind parameters
/// in `SET`); the setting evaporates at commit/rollback.
pub async fn set_statement_timeout(
    conn: &mut sqlx::PgConnection,
    timeout_ms: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('statement_timeout', $1, true)")
        .bind(timeout_ms.to_string())
        .execute(conn)
        .await?;
    Ok(())
}

/// Extended RLS context setter (Epics 15.5 / ). Resolves the admin flags
/// from the caller's scopes (option a — no per-row group-membership join) and
/// passes the Auth user UUID for holder-scoped RLS. All services that
/// set tenant context should call this instead of the legacy 6-arg form.
/// Handle set RLS context ext.
#[allow(clippy::too_many_arguments)]
pub async fn set_rls_context_ext(
    conn: &mut sqlx::PgConnection,
    env_id: Uuid,
    subject_id: &str,
    token_tp: &str,
    scopes: &str,
    is_platform_admin: bool,
    is_env_admin: bool,
    sentin8_auth_user_id: Option<Uuid>,
) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT sentin8_set_tenant_context($1, $2, $3, $4, $5, false, $6, $7)")
        .bind(env_id)
        .bind(subject_id)
        .bind(token_tp)
        .bind(scopes)
        .bind(is_platform_admin)
        .bind(is_env_admin)
        .bind(sentin8_auth_user_id)
        .execute(conn)
        .await?;
    Ok(())
}
