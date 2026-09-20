// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Authentication response models.

use std::fmt;

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};
use crate::{GmpResponse, GmpVersion};

#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct AuthenticateResponse {
    pub status: u16,
    pub status_text: String,
    pub role: Option<String>,
    pub timezone: Option<String>,
    pub password_warning: Option<String>,
    pub token: Option<String>,
}

impl fmt::Debug for AuthenticateResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthenticateResponse")
            .field("status", &self.status)
            .field("status_text", &self.status_text)
            .field("role", &self.role)
            .field("timezone", &self.timezone)
            .field("password_warning", &self.password_warning)
            .field("token", &self.token.as_ref().map(|_| "[REDACTED]"))
            .finish()
    }
}

impl AuthenticateResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
            role: root.optional_child_text("role"),
            timezone: root.optional_child_text("timezone"),
            password_warning: root.optional_child_text("password_warning"),
            token: root.optional_child_text("token"),
        })
    }
}

impl GmpResponse for AuthenticateResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn parses_authenticate_response() {
        let response = Response::from(
            r#"<authenticate_response status="200" status_text="OK"><role>Admin</role><timezone>Europe/Berlin</timezone><password_warning>change it</password_warning><token>issued-token</token></authenticate_response>"#,
        );

        let parsed = AuthenticateResponse::from_response(&response).expect("authenticate parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
        assert_eq!(parsed.role.as_deref(), Some("Admin"));
        assert_eq!(parsed.timezone.as_deref(), Some("Europe/Berlin"));
        assert_eq!(parsed.password_warning.as_deref(), Some("change it"));
        assert_eq!(parsed.token.as_deref(), Some("issued-token"));
        let debug = format!("{parsed:?}");
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("issued-token"));
    }

    #[test]
    fn parses_self_closing_authenticate_response() {
        let response = Response::from(r#"<authenticate_response status="200" status_text="OK"/>"#);

        let parsed = AuthenticateResponse::from_response(&response).expect("authenticate parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.role, None);
        assert_eq!(parsed.token, None);
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<authenticate_response status="401" status_text="Denied"/>"#);

        let error = AuthenticateResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 401,
                message
            } if message == "Denied"
        ));
    }
}
