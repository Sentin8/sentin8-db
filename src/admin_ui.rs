// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! Sentin8:DB Admin UI handlers — RFW definitions.
//! Served from `GET /v1/admin/ui/{page}`, rendered by Sentin8:Dash at runtime.
//! Mutation forms POST to the `/v1/admin/{resource}` alias routes
//! ( — RFW renderer only supports POST).
//! All data handlers resolve + validate `target_env_id` and run inside a
//! transaction with the RLS context set on it.

use crate::handlers::AppState;
use axum::{
    extract::{Path, Query, State},
    http::HeaderMap,
    Json,
};
use sentin8::rfw::page::*;
use sentin8::rfw::response::AdminUiResponse;
use sentin8::rfw::widget::*;
use sqlx::Row;

use crate::handlers::TargetEnvQuery;

/// Shared scope gate for all admin endpoints.
const ADMIN_SCOPES: &[&str] = &[
    "sentin8:db:data:read",
    "sentin8:db:data:write",
    "sentin8:db:table:admin",
    "sentin8:db:posture:read",
];

/// Fetch admin ui.
#[utoipa::path(
    get,
    path = "/v1/admin/ui/{page}",
    params(
        ("page" = String, Path, description = "RFW page name"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "RFW page definition (rendered by Sentin8:Dash)", body = serde_json::Value),
        (status = 403, description = "Caller lacks a db read/admin scope"),
        (status = 404, description = "Unknown page"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_ui(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(page): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    a.require_any_scope(ADMIN_SCOPES)?;
    let def = match page.as_str() {
        "overview" => AdminPage::new("DB Overview")
            .widget(card(
                "Summary",
                "Table catalog, RLS posture, schema inspection, quota monitoring.",
            ))
            .widget(RemoteWidget::DataTable(WidgetDataTable {
                columns: vec![cols("table_name", "Table"), cols("status", "Status")],
                data_endpoint: "/v1/admin/tables".into(),
                sortable: true,
                filterable: true,
                page_size: 20,
                empty_message: Some("No registered tables.".into()),
                row_link: Some("/admin/db/tables/{id}".into()),
                row_actions: vec![],
            }))
            .build(),
        "tables" => AdminPage::new("Tables")
            .action(link("Create Table", "tables/new"))
            .widget(table_with_actions(
                vec![cols("table_name", "Table Name"), col("status", "Status")],
                "/v1/admin/tables",
                vec![
                    row_action_post("Archive", "/v1/admin/tables/{id}/archive"),
                    row_action_post("Drop", "/v1/admin/tables/{id}/drop"),
                ],
            ))
            .build(),
        "tables/new" => AdminPage::new("Create Table")
            .widget(RemoteWidget::Form(WidgetForm {
                fields: vec![
                    WidgetFormField {
                        key: "table_name".into(),
                        label: "Table Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. my_data".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: Some(
                            "The logical table name (letters, numbers, underscores only).".into(),
                        ),
                        visible_if: None,
                    },
                    WidgetFormField {
                        key: "display_name".into(),
                        label: "Display Name".into(),
                        field_type: FormFieldType::Text,
                        required: true,
                        placeholder: Some("e.g. My Data".into()),
                        default_value: None,
                        options: None,
                        validation: None,
                        width: None,
                        help_text: None,
                        visible_if: None,
                    },
                ],
                submit_endpoint: "/v1/admin/tables".into(),
                submit_label: "Create Table".into(),
                cancel_label: "Cancel".into(),
                method: FormMethod::Post,
            }))
            .build(),
        "posture" => AdminPage::new("RLS Posture")
            .widget(RemoteWidget::DataTable(WidgetDataTable {
                columns: vec![
                    col("table_name", "Table"),
                    col("physical_name", "Physical"),
                    col("issues", "Issues"),
                ],
                data_endpoint: "/v1/admin/posture".into(),
                sortable: true,
                filterable: true,
                page_size: 20,
                empty_message: Some("No RLS drift detected.".into()),
                row_link: None,
                row_actions: vec![],
            }))
            .build(),
        "audit" => AdminPage::new("DDL Audit")
            .widget(RemoteWidget::DataTable(WidgetDataTable {
                columns: vec![
                    col("table_name", "Table"),
                    col("operation", "Operation"),
                    col("actor_id", "Actor"),
                    col("created_at", "At"),
                ],
                data_endpoint: "/v1/admin/audit".into(),
                sortable: true,
                filterable: true,
                page_size: 20,
                empty_message: Some("No DDL operations recorded.".into()),
                row_link: None,
                row_actions: vec![],
            }))
            .build(),
        "settings" => AdminPage::new("DB Settings")
            .widget(card("Settings", "Sentin8:DB settings."))
            .build(),
        // ── Policy Studio — shared page
        // constructors; the guard guarantees `Some` ( dispatch).
        p if sentin8::rfw::policy_page("sentin8:db", p).is_some() => {
            sentin8::rfw::policy_page("sentin8:db", p)
                .expect("policy_page checked in guard")
                .build()
        }
        _ => {
            return Err((
                axum::http::StatusCode::NOT_FOUND,
                format!("Unknown admin UI page: {page}"),
            ))
        }
    };
    Ok(Json(
        serde_json::to_value(AdminUiResponse::page(def)).unwrap(),
    ))
}

/// `GET /v1/admin/{resource}` — returns a JSON array of admin data rows.
/// Registry-backed for `tables`, live posture findings for `posture`,
/// recent DDL audit entries for `audit`. Cross-env via `target_env_id`
/// requires `sentin8:sys:admin` (handlers::TargetEnvQuery validation applies).
/// Fetch admin data.
#[utoipa::path(
    get,
    path = "/v1/admin/{resource}",
    params(
        ("resource" = String, Path, description = "Admin data resource"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "The resource's rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a db read/admin scope"),
        (status = 404, description = "Unknown resource"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(resource): Path<String>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    admin_data(state, headers, teq, resource).await
}

/// GET handler for the literal `/v1/admin/tables` route (the POST alias
/// shares the path; without an explicit GET registration axum answers 405).
/// Fetch admin data for tables.
#[utoipa::path(
    get,
    path = "/v1/admin/tables",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    responses(
        (status = 200, description = "The tables rows for the RFW table", body = serde_json::Value),
        (status = 403, description = "Caller lacks a db read/admin scope"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn get_admin_data_for_tables(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    admin_data(state, headers, teq, "tables".to_string()).await
}

async fn admin_data(
    state: AppState,
    headers: HeaderMap,
    teq: TargetEnvQuery,
    resource: String,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    let a = sentin8::auth::client::verify_bearer_token(&state.config.auth_client, &headers).await?;
    a.require_any_scope(ADMIN_SCOPES)?;
    let env_id = match crate::handlers::resolve_admin_env(&state.pool, &teq, &headers, &a).await {
        Ok(id) => id,
        Err((s, m)) => return Err((s, m)),
    };

    let mut tx = state
        .pool
        .begin()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    crate::rls::set_rls_context(
        &mut tx,
        env_id,
        &a.claims.sub,
        &a.claims.token_tp,
        &a.claims.scope,
        a.is_platform_admin(),
    )
    .await
    .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let rows: Vec<serde_json::Value> = match resource.as_str() {
        "tables" => sqlx::query(
            "SELECT logical_name, status FROM table_registry WHERE env_id = $1 AND status = 'active' ORDER BY logical_name LIMIT 200",
        )
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .iter()
        .map(|row| {
            serde_json::json!({
                "table_name": row.get::<String, _>("logical_name"),
                "status": row.get::<String, _>("status"),
            })
        })
        .collect(),
        "posture" => sqlx::query(
            r#"SELECT r.logical_name, r.physical_name,
                      c.relrowsecurity AS rls_enabled,
                      c.relforcerowsecurity AS rls_forced,
                      (SELECT COUNT(*) FROM pg_policies p
                       WHERE p.schemaname = 'public' AND p.tablename = r.physical_name) AS policy_count
               FROM table_registry r
               JOIN pg_class c ON c.relname = r.physical_name
               WHERE r.env_id = $1 AND r.status IN ('active', 'archived')"#,
        )
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .iter()
        .filter_map(|row| {
            let mut issues = Vec::new();
            if !row.get::<bool, _>("rls_enabled") {
                issues.push("rls_not_enabled");
            }
            if !row.get::<bool, _>("rls_forced") {
                issues.push("rls_not_forced");
            }
            if row.get::<i64, _>("policy_count") < 4 {
                issues.push("missing_policies");
            }
            if issues.is_empty() {
                None
            } else {
                Some(serde_json::json!({
                    "table_name": row.get::<String, _>("logical_name"),
                    "physical_name": row.get::<String, _>("physical_name"),
                    "issues": issues.join(", "),
                }))
            }
        })
        .collect(),
        "audit" => sqlx::query(
            "SELECT table_name, operation, actor_id, created_at FROM ddl_audit WHERE env_id = $1 ORDER BY created_at DESC LIMIT 100",
        )
        .bind(env_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
        .iter()
        .map(|row| {
            serde_json::json!({
                "table_name": row.get::<String, _>("table_name"),
                "operation": row.get::<String, _>("operation"),
                "actor_id": row.get::<Option<uuid::Uuid>, _>("actor_id").map(|u| u.to_string()),
                "created_at": row.get::<Option<chrono::DateTime<chrono::Utc>>, _>("created_at").map(|t| t.to_rfc3339()),
            })
        })
        .collect(),
        _ => vec![],
    };
    tx.commit()
        .await
        .map_err(|e| (axum::http::StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
    Ok(Json(serde_json::Value::Array(rows)))
}

/// `POST /v1/admin/tables` — create-table form submission (RFW renderer
/// only supports POST). Delegates to the main create handler.
/// Handle admin create table.
#[utoipa::path(
    post,
    path = "/v1/admin/tables",
    params(("target_env_id" = String, Query, description = "Target env (RLS context)")),
    request_body = crate::handlers::CreateTableRequest,
    responses(
        (status = 200, description = "Table created", body = serde_json::Value),
        (status = 400, description = "Invalid create-table form"),
        (status = 403, description = "Caller lacks a db admin scope"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn admin_create_table(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Json(req): Json<crate::handlers::CreateTableRequest>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    crate::handlers::create_table(State(state), headers, Query(teq), Json(req))
        .await
        .map(|Json(resp)| Json(serde_json::json!({"ok": true, "table": resp})))
}

/// `POST /v1/admin/tables/{id}/archive` — archive row action.
/// Handle admin archive table.
#[utoipa::path(
    post,
    path = "/v1/admin/tables/{id}/archive",
    params(
        ("id" = uuid::Uuid, Path, description = "Table id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Table archived", body = serde_json::Value),
        (status = 403, description = "Caller lacks a db admin scope"),
        (status = 404, description = "Unknown table"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn admin_archive_table(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    crate::handlers::archive_table(State(state), headers, Query(teq), Path(id))
        .await
        .map(|Json(resp)| Json(serde_json::json!({"ok": true, "result": resp})))
}

/// `POST /v1/admin/tables/{id}/drop` — drop row action.
/// Handle admin drop table.
#[utoipa::path(
    post,
    path = "/v1/admin/tables/{id}/drop",
    params(
        ("id" = uuid::Uuid, Path, description = "Table id"),
        ("target_env_id" = String, Query, description = "Target env (RLS context)")
    ),
    responses(
        (status = 200, description = "Table dropped", body = serde_json::Value),
        (status = 403, description = "Caller lacks a db admin scope"),
        (status = 404, description = "Unknown table"),
    ),
    security(("sentin8:db:admin" = [])),
    tag = "admin-ui",
)]
pub async fn admin_drop_table(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(teq): Query<TargetEnvQuery>,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<serde_json::Value>, (axum::http::StatusCode, String)> {
    crate::handlers::drop_table(State(state), headers, Query(teq), Path(id))
        .await
        .map(|Json(resp)| Json(serde_json::json!({"ok": true, "result": resp})))
}

fn col(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: false,
        width: None,
        format: None,
    }
}
fn cols(key: &str, label: &str) -> WidgetDataTableColumn {
    WidgetDataTableColumn {
        key: key.into(),
        label: label.into(),
        sortable: true,
        width: None,
        format: None,
    }
}
fn table_with_actions(
    columns: Vec<WidgetDataTableColumn>,
    endpoint: &str,
    row_actions: Vec<WidgetButton>,
) -> RemoteWidget {
    RemoteWidget::DataTable(WidgetDataTable {
        columns,
        data_endpoint: endpoint.into(),
        sortable: true,
        filterable: true,
        page_size: 20,
        empty_message: Some("No data.".into()),
        row_link: None,
        row_actions,
    })
}
fn row_action_post(label: &str, endpoint: &str) -> WidgetButton {
    WidgetButton {
        label: label.into(),
        button_type: ButtonType::Primary,
        route: None,
        endpoint: Some(endpoint.into()),
        icon: None,
    }
}
fn card(title: &str, body: &str) -> RemoteWidget {
    RemoteWidget::Card(WidgetCard {
        title: Some(title.into()),
        subtitle: None,
        children: vec![RemoteWidget::Text(WidgetText {
            text: body.into(),
            text_type: WidgetTextType::Body,
            align: TextAlign::Left,
            max_lines: None,
        })],
        actions: vec![],
    })
}
fn link(label: &str, route: &str) -> AdminUiAction {
    AdminUiAction {
        label: label.into(),
        action_type: AdminUiActionType::Link,
        route: Some(route.into()),
        endpoint: None,
        icon: Some("add".into()),
    }
}
