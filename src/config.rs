// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! DB configuration loaded from environment variables.

use std::env;

use sentin8::auth::client::{Client as AuthClient, ClientOptions};

#[derive(Debug, Clone)]
/// Configuration for DB.
pub struct Db8Config {
    /// The port.
    pub port: u16,
    /// The database URL.
    pub database_url: String,
    /// Auth JWKS URL for token verification.
    /// The sentin8 auth JWKS URL.
    pub sentin8_auth_jwks_url: String,
    /// Auth issuer for token verification.
    /// The sentin8 auth issuer.
    pub sentin8_auth_issuer: String,
    /// Shared Auth client - constructed once so the discovery and JWKS
    /// caches are reused across every request (5-minute TTL each).
    /// Cloning is cheap (the caches live behind an `Arc`).
    /// The auth client.
    pub auth_client: AuthClient,
    /// Bus base URL for event publication.
    /// The sentin8 bus URL.
    pub sentin8_bus_url: String,
    /// Bus stream family for DB events (default `"db"`).
    /// The stream family.
    pub stream_family: String,
}

/// System Organization ID - used as fallback when token has no org claim.
/// The system org id constant.
pub const SYSTEM_ORG_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000001);
/// System Environment ID - used as fallback when token has no env claim.
/// The system env id constant.
pub const SYSTEM_ENV_ID: uuid::Uuid = uuid::Uuid::from_u128(0x00000000_0000_0000_0000_000000000002);

impl Db8Config {
    /// Handle from env.
    pub fn from_env() -> Self {
        let cfg = sentin8::config::Sentin8Config::from_env();
        Self {
            port: env::var("SENTIN8_DB_PORT")
                .expect("SENTIN8_DB_PORT must be set by captain")
                .parse()
                .expect("SENTIN8_DB_PORT must be a valid u16"),
            database_url: env::var("DB_DATABASE_URL").unwrap_or_else(|_| {
                env::var("DATABASE_URL").unwrap_or_else(|_| {
                    sentin8::config::Sentin8Config::default_database_url().to_string()
                })
            }),
            sentin8_auth_jwks_url: env::var("SENTIN8_AUTH_JWKS_URL")
                .unwrap_or_else(|_| cfg.sentin8_auth_jwks_url()),
            sentin8_auth_issuer: env::var("SENTIN8_AUTH_ISSUER")
                .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
            auth_client: AuthClient::new(ClientOptions {
                base_url: env::var("SENTIN8_AUTH_ISSUER")
                    .unwrap_or_else(|_| cfg.sentin8_auth_issuer()),
                ..Default::default()
            }),
            sentin8_bus_url: env::var("SENTIN8_BUS_URL").unwrap_or_else(|_| cfg.sentin8_bus_url()),
            stream_family: env::var("DB_STREAM_FAMILY").unwrap_or_else(|_| "db".into()),
        }
    }
}
