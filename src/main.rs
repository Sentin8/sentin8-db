// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! Sentin8 DB - structured persistence over PostgreSQL with RLS.
//!
//! Boot runs on the platform `sentin8-shell` crate (design
//! ): registration
//! flag, PQ provider, config, capped pool, PG18 check, state binding, OpenAPI
//! merge, middleware stack and PQ-TLS listener are owned by the shell. This
//! binary supplies only its registration data, state and routes.

#[allow(dead_code)]
mod admin_ui;
#[allow(dead_code)]
mod auth;
#[allow(dead_code)]
mod config;
#[allow(dead_code)]
mod handlers;
mod openapi;
mod policy;
mod registration;
#[allow(dead_code)]
mod rls;
#[allow(dead_code)]
mod server;

use utoipa::OpenApi;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    sentin8::shell::serve(
        sentin8::shell::Sentin8Shell::new("sentin8:db", "SENTIN8_DB")
            .with_registration(registration::print)
            .with_state(|core| async move {
                // Config is built INSIDE the state closure - after
                // `shell::serve` has handled the `--print-registration` flag
                // (shell step 1). `Db8Config::from_env` constructs an
                // `AuthClient` (reqwest), which panics without the PQ crypto
                // provider; the provider is installed by `serve` after the
                // flag check. Building config here previously crashed
                // `--print-registration` (vertical init / enroll) with "No
                // provider set".
                let cfg = config::Db8Config::from_env();
                // ── Sentin8:Policy (- shell-owned boot):
                // the engine arrived already booted from the shell (step 8,
                // in `core.admin.policy`). This state closure only copies
                // the Arc - no second engine, consumer, or DCR registration.
                let policy_engine = core.admin.policy.clone();
                Ok(handlers::AppState {
                    config: std::sync::Arc::new(cfg.clone()),
                    pool: core.pool.clone(),
                    policy: policy_engine.clone(),
                    admin: sentin8::shield::admin::SharedAdminState {
                        service: "sentin8:db".to_string(),
                        pool: core.pool.clone(),
                        policy: policy_engine.clone(),
                        auth_client: std::sync::Arc::new(cfg.auth_client.clone()),
                    },
                })
            })
            .with_own_health()
            .with_router(|router, _state| server::routes(router))
            .with_openapi(openapi::DbOpenApi::openapi()),
    )
    .await
}
