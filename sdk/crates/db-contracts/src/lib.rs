// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! # db-contracts
//!
//! Rust types for the DB structured-persistence HTTP API - registered
//! tables, schema definitions, and the query/insert/update/delete wire
//! contract.

#![deny(missing_docs)]

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

/// Registered tenant table metadata.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct TableInfo {
    /// Table identity.
    pub id: Uuid,
    /// Owning organization (enrichment).
    pub org_id: Uuid,
    /// Owning environment (the tenant key).
    pub env_id: Uuid,
    /// Physical table name.
    pub table_name: String,
    /// Human-facing name.
    pub display_name: String,
    /// Optional description.
    pub description: Option<String>,
    /// Column schema (JSON).
    pub schema: serde_json::Value,
    /// Lifecycle status (e.g. `active`).
    pub status: String,
    /// Creation timestamp (UTC).
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last modification (UTC).
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Request body for `POST /v1/tables`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateTableRequest {
    /// Physical table name to create.
    pub table_name: String,
    /// Human-facing name.
    pub display_name: String,
    /// Optional description.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Column definitions.
    pub columns: Vec<ColumnDef>,
}

/// One column definition of a created table.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ColumnDef {
    /// Column name.
    pub name: String,
    /// Logical data type.
    pub data_type: String,
    /// Whether nulls are allowed.
    pub nullable: bool,
    /// Optional SQL default expression.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default: Option<String>,
}

/// Request body for `POST /v1/data/query`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueryRequest {
    /// The table to query.
    pub table: String,
    /// Opaque filter expression (the server interprets per table).
    #[serde(default)]
    pub filters: serde_json::Value,
    /// Sort clauses in priority order.
    #[serde(default)]
    pub sort: Vec<SortClause>,
    /// Limit/offset window.
    #[serde(default)]
    pub pagination: Pagination,
}

/// Limit/offset pagination window.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct Pagination {
    /// Maximum rows to return.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u32>,
    /// Rows to skip (offset mode).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub offset: Option<u32>,
    /// Keyset cursor (DB-3, db README §7): return rows strictly after this
    /// `id`. Takes precedence over `offset` when set - stable under inserts
    /// between pages, unlike the offset window. Paired with `sort` on `id`
    /// enforced server-side when the cursor is used.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub after: Option<uuid::Uuid>,
}

/// One sort instruction.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SortClause {
    /// Column to sort by.
    pub column: String,
    /// Sort descending when true (default ascending).
    #[serde(default)]
    pub descending: bool,
}

/// Response from `POST /v1/data/query`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct QueryResponse {
    /// The matched rows as JSON objects.
    pub rows: Vec<serde_json::Value>,
    /// Total matching row count (ignoring pagination).
    pub total: u64,
    /// Keyset cursor (DB-3): the last returned row's `id` - pass it back as
    /// `pagination.after` to fetch the next page. `null` when the page was
    /// the last (fewer rows than `limit` returned).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_cursor: Option<Uuid>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn utc(s: &str) -> chrono::DateTime<chrono::Utc> {
        chrono::DateTime::parse_from_rfc3339(s)
            .unwrap()
            .with_timezone(&chrono::Utc)
    }

    #[test]
    fn table_info_roundtrip() {
        let t = TableInfo {
            id: uuid::Uuid::new_v4(),
            org_id: uuid::Uuid::new_v4(),
            env_id: uuid::Uuid::new_v4(),
            table_name: "ledger_accounts".into(),
            display_name: "Ledger Accounts".into(),
            description: Some("Accounts".into()),
            schema: json!({"columns": [{"name": "id", "type": "uuid"}]}),
            status: "active".into(),
            created_at: utc("2026-01-01T00:00:00Z"),
            updated_at: utc("2026-01-02T00:00:00Z"),
        };
        let v = serde_json::to_value(&t).unwrap();
        assert_eq!(v["table_name"], "ledger_accounts");
        let back: TableInfo = serde_json::from_value(v).unwrap();
        assert_eq!(back.id, t.id);
        assert_eq!(back.schema, t.schema);
        assert_eq!(back.created_at, t.created_at);
    }

    #[test]
    fn create_table_request_optional_description_omitted() {
        let req = CreateTableRequest {
            table_name: "t1".into(),
            display_name: "T1".into(),
            description: None,
            columns: vec![ColumnDef {
                name: "amount".into(),
                data_type: "decimal".into(),
                nullable: false,
                default: Some("0".into()),
            }],
        };
        let v = serde_json::to_value(&req).unwrap();
        // skip_serializing_if - absent when None (wire-format stability).
        assert!(v.get("description").is_none());
        assert_eq!(v["columns"][0]["default"], "0");
        let back: CreateTableRequest = serde_json::from_value(v).unwrap();
        assert!(back.description.is_none());
        assert_eq!(back.columns.len(), 1);
    }

    #[test]
    fn query_request_defaults() {
        // filters/sort/pagination all #[serde(default)] - minimal body works.
        let req: QueryRequest = serde_json::from_value(json!({ "table": "t" })).unwrap();
        assert_eq!(req.table, "t");
        assert!(req.filters.is_null());
        assert!(req.sort.is_empty());
        assert!(req.pagination.limit.is_none());
        assert!(req.pagination.offset.is_none());
    }

    #[test]
    fn query_request_with_sort_and_pagination_roundtrip() {
        let req = QueryRequest {
            table: "accounts".into(),
            filters: json!({"status": "active", "balance_gt": "100.00"}),
            sort: vec![SortClause {
                column: "created_at".into(),
                descending: true,
            }],
            pagination: Pagination {
                limit: Some(50),
                offset: Some(100),
                after: None,
            },
        };
        let v = serde_json::to_value(&req).unwrap();
        let back: QueryRequest = serde_json::from_value(v).unwrap();
        assert_eq!(back.sort[0].column, "created_at");
        assert!(back.sort[0].descending);
        assert_eq!(back.pagination.limit, Some(50));
        assert_eq!(back.pagination.offset, Some(100));
        // Filters survive as an opaque JSON value - DB never interprets them.
        assert_eq!(back.filters["balance_gt"], "100.00");
    }

    #[test]
    fn query_response_shape() {
        let resp: QueryResponse =
            serde_json::from_value(json!({ "rows": [{"id": "abc"}], "total": 1 })).unwrap();
        assert_eq!(resp.rows.len(), 1);
        assert_eq!(resp.total, 1);
    }
}
