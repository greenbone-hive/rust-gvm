// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Typed convenience methods for [`GmpClient`](crate::GmpClient).
//!
//! Each private resource-family module implements inherent methods on
//! [`GmpClient`](crate::GmpClient). Public method paths, signatures, and
//! behavior remain independent of these internal module boundaries. All
//! families except the deliberately frozen ticket surface delegate to
//! [`GmpClient::execute`](crate::GmpClient::execute).

mod agents;
mod automation;
mod core;
mod identity;
mod reports;
mod resources;
mod scan;
mod security;
mod system;
mod targets;
mod tickets;

#[cfg(test)]
mod tests {
    use gvm_gmp::responses::{common::ParseError, GetVersionResponse};

    use crate::GvmError;

    #[test]
    fn parse_error_converts_to_gvm_error() {
        let parse_err = ParseError::MissingElement("test".to_string());
        let gvm_err: GvmError = parse_err.into();
        assert!(matches!(gvm_err, GvmError::Parse(_)));
    }

    #[test]
    fn parse_error_display_forwarded() {
        let gvm_err = GvmError::Parse(ParseError::MissingElement("version".to_string()));
        assert!(gvm_err.to_string().contains("version"));
    }

    #[test]
    fn get_version_response_from_response_compiles() {
        use gvm_protocol::Response;
        let response = Response::from(
            r#"<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>"#,
        );
        let result = GetVersionResponse::from_response(&response);
        assert!(result.is_ok());
    }
}
