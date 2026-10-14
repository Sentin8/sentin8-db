// SPDX-FileCopyrightText: Copyright Logically Magic Inc. <hello@logicallymagic.com>
// SPDX-FileCopyrightText: Copyright Hamid Jahanzad <Hamid@Jahanzad.com>
// SPDX-FileCopyrightText: Copyright Contributors to the Sentin8:DB
// SPDX-License-Identifier: Apache-2.0

//! Auth token verification — re-exported from the sentin8-auth-client SDK.
//!
//! db does not currently use auth in its handlers; this module exists
//! for future use and to keep the service structure consistent.

#[allow(unused_imports)] // re-export seam for handler adoption (POLICY-DB wiring)
pub use sentin8::auth::client::{AuthContext, VerifiedClaims};
