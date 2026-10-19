// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! # db-client
//!
//! Rust HTTP client for the DB structured-persistence service: schema
//! (tables) and data (query/insert/update/delete) against registered
//! tenant tables.

#![deny(missing_docs)]

use std::sync::Arc;

use sentin8_db_contracts::{QueryRequest, QueryResponse};
use sentin8_middleware::http_client::Sentin8HttpClient;
use thiserror::Error;

#[derive(Debug, Error)]
/// Failure surface for DB client calls.
pub enum DbError {
    /// An HTTP request failed (transport error or non-success status).
    #[error("DB HTTP error: {0}")]
    Http(String),
    /// A response body could not be decoded.
    #[error("DB response decode error: {0}")]
    Decode(String),
}

/// Authenticated DB client. Cheap to clone (wraps an `Arc`).
#[derive(Clone)]
pub struct DbClient {
    /// Trimmed base URL of the DB service.
    base_url: String,
    /// Static bearer token.
    auth_token: Arc<String>,
    http: Sentin8HttpClient,
}

impl DbClient {
    /// Create a client with a static bearer token.
    pub fn new(base_url: impl Into<String>, auth_token: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into().trim_end_matches('/').to_string(),
            auth_token: Arc::new(auth_token.into()),
            http: Sentin8HttpClient::new(),
        }
    }

    fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `POST /v1/data/query` - filtered/sorted/paginated row selection.
    pub async fn query(&self, req: &QueryRequest) -> Result<QueryResponse, DbError> {
        let resp = self
            .http
            .post(self.url("/v1/data/query"))
            .bearer_auth(self.auth_token.as_str())
            .json(req)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `POST /v1/data/insert`
    pub async fn insert(
        &self,
        table: &str,
        rows: &[serde_json::Value],
    ) -> Result<serde_json::Value, DbError> {
        let body = serde_json::json!({ "table": table, "rows": rows });
        let resp = self
            .http
            .post(self.url("/v1/data/insert"))
            .bearer_auth(self.auth_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `POST /v1/data/update` - update rows by filter with an optional
    /// resource-version (optimistic concurrency) check.
    pub async fn update(
        &self,
        table: &str,
        filter: serde_json::Value,
        set: serde_json::Value,
        resource_version: Option<i32>,
    ) -> Result<serde_json::Value, DbError> {
        let body = serde_json::json!({
            "table": table,
            "filter": filter,
            "set": set,
            "resource_version": resource_version,
        });
        let resp = self
            .http
            .post(self.url("/v1/data/update"))
            .bearer_auth(self.auth_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `POST /v1/data/delete` - soft-delete rows by filter.
    pub async fn delete(
        &self,
        table: &str,
        filter: serde_json::Value,
    ) -> Result<serde_json::Value, DbError> {
        let body = serde_json::json!({ "table": table, "filter": filter });
        let resp = self
            .http
            .post(self.url("/v1/data/delete"))
            .bearer_auth(self.auth_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `POST /v1/tables` - create a table (system columns + RLS applied
    /// server-side).
    pub async fn create_table(
        &self,
        table_name: &str,
        display_name: &str,
        columns: &[serde_json::Value],
    ) -> Result<serde_json::Value, DbError> {
        let body = serde_json::json!({
            "table_name": table_name,
            "display_name": display_name,
            "columns": columns,
        });
        let resp = self
            .http
            .post(self.url("/v1/tables"))
            .bearer_auth(self.auth_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `GET /v1/tables` - list tables for the caller's tenant.
    pub async fn list_tables(&self) -> Result<Vec<serde_json::Value>, DbError> {
        let resp = self
            .http
            .get(self.url("/v1/tables"))
            .bearer_auth(self.auth_token.as_str())
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `GET /v1/tables/{id}` - get one table's metadata.
    pub async fn get_table(&self, id: &str) -> Result<serde_json::Value, DbError> {
        let resp = self
            .http
            .get(self.url(&format!("/v1/tables/{id}")))
            .bearer_auth(self.auth_token.as_str())
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `POST /v1/tables/{id}/alter` - safe schema alteration (additive
    /// columns only).
    pub async fn alter_table(
        &self,
        id: &str,
        add_columns: &[serde_json::Value],
    ) -> Result<serde_json::Value, DbError> {
        let body = serde_json::json!({ "add_columns": add_columns });
        let resp = self
            .http
            .post(self.url(&format!("/v1/tables/{id}/alter")))
            .bearer_auth(self.auth_token.as_str())
            .json(&body)
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }

    /// `GET /v1/health` - health check.
    pub async fn health(&self) -> Result<serde_json::Value, DbError> {
        let resp = self
            .http
            .get(self.url("/v1/health"))
            .send()
            .await
            .map_err(|e| DbError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(DbError::Http(format!("status {}", resp.status())));
        }
        resp.json()
            .await
            .map_err(|e| DbError::Decode(e.to_string()))
    }
}

// Pure tests: the client's URL assembly, bearer-token attachment, and
// error mapping against a local TCP listener acting as the DB service -
// no backing services.

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// One-shot local HTTP server: reads the request, replies with
    /// `(status, body)`. Returns `(join_handle_for_raw_request, addr)` -
    /// await the handle after the client call to assert on the request.
    async fn serve_once(
        status_line: &'static str,
        body: &'static str,
    ) -> (tokio::task::JoinHandle<String>, std::net::SocketAddr) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap_or(0);
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let resp = format!(
                "{status_line}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        (handle, addr)
    }

    fn client_for(addr: std::net::SocketAddr, token: &str) -> DbClient {
        DbClient::new(format!("http://{addr}"), token)
    }

    fn install_provider() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = sentin8_tls::crypto::sentin8_pq_provider().install_default();
        });
    }

    #[tokio::test]
    async fn query_posts_path_bearer_and_body() {
        install_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"rows":[{"id":"a"}],"total":1}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });

        let c = client_for(addr, "tok-1");
        let req = QueryRequest {
            table: "accounts".into(),
            filters: serde_json::json!({"status": "active"}),
            sort: vec![],
            pagination: sentin8_db_contracts::Pagination::default(),
        };
        let resp = c.query(&req).await.unwrap();
        assert_eq!(resp.total, 1);
        assert_eq!(resp.rows[0]["id"], "a");

        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("POST /v1/data/query HTTP/1.1"),
            "got: {raw}"
        );
        assert!(
            raw.contains("authorization: Bearer tok-1")
                || raw.contains("Authorization: Bearer tok-1")
        );
        assert!(raw.contains("\"table\":\"accounts\""));
    }

    #[tokio::test]
    async fn non_success_status_maps_to_http_error() {
        install_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let _ = sock.read(&mut buf).await;
            let resp = "HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
            sock.write_all(resp.as_bytes()).await.unwrap();
        });

        let c = client_for(addr, "tok-1");
        let req = QueryRequest {
            table: "t".into(),
            filters: serde_json::json!({}),
            sort: vec![],
            pagination: sentin8_db_contracts::Pagination::default(),
        };
        let err = c.query(&req).await.unwrap_err();
        assert!(
            matches!(err, DbError::Http(ref m) if m.contains("403")),
            "unexpected error: {err:?}"
        );
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn base_url_trailing_slash_stripped() {
        install_provider();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let handle = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = vec![0u8; 8192];
            let n = sock.read(&mut buf).await.unwrap();
            let req = String::from_utf8_lossy(&buf[..n]).to_string();
            let body = r#"{"status":"ok"}"#;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            sock.write_all(resp.as_bytes()).await.unwrap();
            req
        });
        // Double slash would break path matching - trailing slash must be cut.
        let c = DbClient::new(format!("http://{addr}/"), "t");
        c.health().await.unwrap();
        let raw = handle.await.unwrap();
        assert!(raw.starts_with("GET /v1/health HTTP/1.1"), "got: {raw}");
    }

    #[tokio::test]
    async fn insert_sends_table_and_rows() {
        install_provider();
        let (handle, addr) = serve_once("HTTP/1.1 200 OK", r#"{"inserted":1}"#).await;
        let c = client_for(addr, "t");
        c.insert("t1", &[serde_json::json!({"k": "v"})])
            .await
            .unwrap();
        let raw = handle.await.unwrap();
        assert!(
            raw.starts_with("POST /v1/data/insert HTTP/1.1"),
            "got: {raw}"
        );
        assert!(raw.contains("\"table\":\"t1\""));
        assert!(raw.contains("\"rows\":[{\"k\":\"v\"}]"));
    }
}
