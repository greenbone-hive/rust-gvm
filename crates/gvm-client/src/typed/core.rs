// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

use crate::{GmpClient, GvmError};
use gvm_connection::GvmConnection;
use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::responses::{AuthenticateResponse, GetVersionResponse};

impl<C: GvmConnection + Send> GmpClient<C> {
    // ── Version & Auth ────────────────────────────────────────────────────────

    /// Send a `get_version` request and return a typed [`GetVersionResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn get_version(&mut self) -> Result<GetVersionResponse, GvmError> {
        self.execute(GetVersionRequest::new()).await
    }

    /// Send an `authenticate` request and return a typed [`AuthenticateResponse`].
    ///
    /// # Errors
    /// Returns an error if the request fails or response parsing fails.
    pub async fn authenticate(
        &mut self,
        username: &str,
        password: &str,
    ) -> Result<AuthenticateResponse, GvmError> {
        self.execute(AuthenticateRequest::new(username, password))
            .await
    }
}
