// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical pre-authentication request.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::responses::AuthenticateResponse;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Credentials accepted by current gvmd authentication.
#[derive(Clone, PartialEq, Eq)]
pub enum AuthenticationCredentials {
    /// Authenticate with a username and password.
    UsernamePassword {
        /// Login name.
        username: String,
        /// Login password.
        password: String,
    },
    /// Authenticate with a previously issued access token.
    Token {
        /// Opaque access token.
        token: String,
    },
}

impl fmt::Debug for AuthenticationCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UsernamePassword { .. } => f
                .debug_struct("UsernamePassword")
                .field("credentials", &"[REDACTED]")
                .finish(),
            Self::Token { .. } => f
                .debug_struct("Token")
                .field("credentials", &"[REDACTED]")
                .finish(),
        }
    }
}

/// Canonical `authenticate` request.
#[derive(Clone)]
pub struct AuthenticateRequest {
    /// Credentials to present.
    pub credentials: AuthenticationCredentials,
    /// Whether a successful password authentication should return an access token.
    pub request_token: Option<bool>,
}

impl AuthenticateRequest {
    /// Create a username/password authentication request.
    #[must_use]
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            credentials: AuthenticationCredentials::UsernamePassword {
                username: username.into(),
                password: password.into(),
            },
            request_token: None,
        }
    }

    /// Create an access-token authentication request.
    #[must_use]
    pub fn with_token(token: impl Into<String>) -> Self {
        Self {
            credentials: AuthenticationCredentials::Token {
                token: token.into(),
            },
            request_token: None,
        }
    }
}

impl fmt::Debug for AuthenticateRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticateRequest")
            .field("credentials", &"[REDACTED]")
            .field("request_token", &self.request_token)
            .finish()
    }
}

impl GmpRequestCodec for AuthenticateRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        match &self.credentials {
            AuthenticationCredentials::UsernamePassword { username, password } => {
                validate_secret(username, "username")?;
                validate_secret(password, "password")
            }
            AuthenticationCredentials::Token { token } => validate_secret(token, "token"),
        }
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("authenticate"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("authenticate");
        if let Some(request_token) = self.request_token {
            command.set_attribute("token", if request_token { "1" } else { "0" });
        }
        let credentials = command.add_element("credentials");
        match &self.credentials {
            AuthenticationCredentials::UsernamePassword { username, password } => {
                credentials.add_child_with_text("username", username);
                credentials.add_child_with_text("password", password);
            }
            AuthenticationCredentials::Token { token } => {
                credentials.add_child_with_text("token", token);
            }
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for AuthenticateRequest {
    type Response = AuthenticateResponse;
}

fn validate_secret(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    if value.chars().all(|character| {
        matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
            || matches!(
                character as u32,
                0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
            )
    }) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn password_and_token_modes_encode_and_redact() {
        let mut password = AuthenticateRequest::new("admin", "pass");
        password.request_token = Some(true);
        assert_eq!(
            password.encode(GmpVersion(22, 8)).expect("valid request"),
            b"<authenticate token=\"1\"><credentials><username>admin</username><password>pass</password></credentials></authenticate>"
        );

        let token = AuthenticateRequest::with_token("token-secret");
        assert_eq!(
            token.encode(GmpVersion(22, 8)).expect("valid request"),
            b"<authenticate><credentials><token>token-secret</token></credentials></authenticate>"
        );

        for debug in [format!("{password:?}"), format!("{token:?}")] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("admin"));
            assert!(!debug.contains("pass"));
            assert!(!debug.contains("token-secret"));
        }
    }

    #[test]
    fn empty_credentials_fail_without_retaining_values() {
        let error = AuthenticateRequest::new("", "secret")
            .validate()
            .expect_err("empty username must fail");
        assert_eq!(
            error,
            GmpRequestError::invalid_field("username", "must not be empty")
        );
        assert!(!error.to_string().contains("secret"));
    }
}
