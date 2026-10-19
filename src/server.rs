// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! Axum server setup for DB.

use axum::routing::{get, post};

use crate::handlers;

/// Add this service's routes onto the shell-provided router.
///
/// The shell (sentin8-shell) owns the boot sequence (pool, PG18 check,
/// TLS listener), the state binding, the OpenAPI merge, and the standard
/// middleware stack (correlation, host context, TLS context, request
/// logging, traffic counter, CORS). This function adds ONLY routes -
/// including the service's own `/v1/health` (custom payload).
pub fn routes(
    router: axum::Router<crate::handlers::AppState>,
) -> axum::Router<crate::handlers::AppState> {
    router
        .route("/v1/health", get(handlers::health))
        // ── Admin UI (RFW) ─────────────────────────────────────────────────
        .route("/v1/admin/ui/{*page}", get(crate::admin_ui::get_admin_ui))
        .route("/v1/admin/{resource}", get(crate::admin_ui::get_admin_data))
        // ── Sentin8:Policy admin API ( - shared implementation;
        // the state already carries `SharedAdminState` - the routes were the
        // only missing piece; RFW renderer aliases included).
        .route(
            "/v1/admin/policy-sets",
            get(sentin8::shield::admin::list_policy_sets::<handlers::AppState>)
                .post(sentin8::shield::admin::create_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}",
            get(sentin8::shield::admin::get_policy_set::<handlers::AppState>)
                .put(sentin8::shield::admin::put_policy_set::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/test",
            post(sentin8::shield::admin::test_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/save",
            post(sentin8::shield::admin::save_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/{name}/{action}",
            post(sentin8::shield::admin::admin_flip_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/enforce",
            post(sentin8::shield::admin::admin_enforce_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/shadow",
            post(sentin8::shield::admin::admin_shadow_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-sets/disable",
            post(sentin8::shield::admin::admin_disable_policy_set::<handlers::AppState>),
        )
        .route(
            "/v1/admin/policy-decisions",
            get(sentin8::shield::admin::list_policy_decisions::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations",
            get(sentin8::shield::admin::list_relations::<handlers::AppState>)
                .put(sentin8::shield::admin::put_relation::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/check",
            get(sentin8::shield::admin::check_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/relations/{id}/delete",
            post(sentin8::shield::admin::admin_delete_relation::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes",
            get(sentin8::shield::admin::list_attributes::<handlers::AppState>)
                .put(sentin8::shield::admin::put_attribute::<handlers::AppState>)
                .delete(sentin8::shield::admin::delete_attribute::<handlers::AppState>),
        )
        .route(
            "/v1/admin/attributes/{id}/delete",
            post(sentin8::shield::admin::admin_delete_attribute::<handlers::AppState>),
        )
        // Admin mutation aliases - the RFW renderer only supports POST
        // . The page defs also use
        // "/v1/admin/tables" as the DATA endpoint (GET) - register GET
        // explicitly, otherwise the POST-only literal shadows the
        // GET /v1/admin/{resource} catch-all and every read 405s.
        .route(
            "/v1/admin/tables",
            post(crate::admin_ui::admin_create_table)
                .get(crate::admin_ui::get_admin_data_for_tables),
        )
        .route(
            "/v1/admin/tables/{id}/archive",
            post(crate::admin_ui::admin_archive_table),
        )
        .route(
            "/v1/admin/tables/{id}/drop",
            post(crate::admin_ui::admin_drop_table),
        )
        .route(
            "/v1/tables",
            post(handlers::create_table).get(handlers::list_tables),
        )
        .route("/v1/tables/{id}", get(handlers::get_table))
        .route("/v1/tables/{id}/alter", post(handlers::alter_table))
        // Table lifecycle - Stories
        .route("/v1/tables/{id}/archive", post(handlers::archive_table))
        .route("/v1/tables/{id}/drop", post(handlers::drop_table))
        .route("/v1/data/query", post(handlers::query))
        .route("/v1/data/insert", post(handlers::insert))
        .route("/v1/data/update", post(handlers::update))
        .route("/v1/data/delete", post(handlers::delete))
        // Operational APIs - Stories
        .route("/v1/posture", get(handlers::posture))
        .route("/v1/audit", get(handlers::audit_log))
    // Traffic counter - counts every inbound request (excludes health checks).
}

/// Shared policy-admin surface accessor - the generic
/// `sentin8::shield::admin` handlers mounted above extract this service's
/// admin state via the `HasPolicyAdmin` trait (stat/acme pattern: derive
/// from the AppState's `admin` field).
impl sentin8::shield::admin::HasPolicyAdmin for handlers::AppState {
    fn policy_admin(&self) -> &sentin8::shield::admin::SharedAdminState {
        &self.admin
    }
}
