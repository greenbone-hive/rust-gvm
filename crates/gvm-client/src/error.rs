// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Error types for the high-level GMP client.

use std::time::Duration;

use gvm_connection::ConnectionError;
use gvm_gmp::commands::tasks::ModifyTaskError;
use gvm_gmp::responses::ParseError;
use gvm_gmp::types::GmpVersion;
use gvm_gmp::GmpRequestError;
use thiserror::Error;

/// High-level client errors.
#[derive(Debug, Error)]
pub enum GvmError {
    /// Transport-level failure.
    #[error("connection error: {0}")]
    Connection(#[source] ConnectionError),

    /// Malformed or uninterpretable response-model failure.
    #[error("parse error: {0}")]
    Parse(#[source] ParseError),

    /// A semantic request failed final-value validation or encoding.
    #[error("request error: {0}")]
    Request(#[from] GmpRequestError),

    /// A typed `modify_task` update cannot be represented safely by gvmd.
    #[error("modify_task request error: {0}")]
    ModifyTask(#[from] ModifyTaskError),

    /// Response or version XML could not be parsed.
    #[error("XML parse error: {0}")]
    XmlParse(String),

    /// Client state does not permit the requested operation.
    #[error("invalid state: {0}")]
    InvalidState(String),

    /// Server returned a valid non-success GMP status code.
    ///
    /// [`crate::GmpClient::call`], [`crate::GmpClient::execute`], and typed
    /// convenience methods use this variant consistently. Raw
    /// [`crate::GmpClient::send`] leaves status inspection to the caller.
    #[error("server error (status {status}): {message}")]
    Server {
        /// GMP status code returned by the server.
        status: u16,
        /// GMP status text returned by the server.
        message: String,
    },

    /// Server advertised an unsupported GMP version.
    #[error("unsupported GMP version: {0}.{1}")]
    UnsupportedVersion(u16, u16),

    /// Command is known but not supported by the negotiated GMP version.
    #[error("command '{command}' requires GMP >= {required}; server reports {version}")]
    UnsupportedCommand {
        /// Command name.
        command: String,
        /// Negotiated GMP version.
        version: GmpVersion,
        /// Minimum required GMP version or version family.
        required: &'static str,
    },

    /// Command support requires explicit XML-help discovery before execution.
    #[error("command '{command}' requires XML help discovery before execution")]
    CommandDiscoveryRequired {
        /// Registered command that requires discovery.
        command: String,
    },

    /// The server's discovered XML-help inventory omitted the command.
    #[error("command '{command}' was not advertised by the server's XML help response")]
    CommandNotAdvertised {
        /// Registered command absent from the discovered server inventory.
        command: String,
    },

    /// Operation timed out.
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

impl From<ConnectionError> for GvmError {
    fn from(value: ConnectionError) -> Self {
        match value {
            ConnectionError::Timeout(duration) => Self::Timeout(duration),
            other => Self::Connection(other),
        }
    }
}

impl From<ParseError> for GvmError {
    fn from(value: ParseError) -> Self {
        match value {
            ParseError::ServerError { status, message } => Self::Server { status, message },
            other => Self::Parse(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn server_parse_error_is_promoted_to_client_server_error() {
        let error = GvmError::from(ParseError::ServerError {
            status: 409,
            message: "conflict".to_string(),
        });

        assert!(matches!(
            error,
            GvmError::Server { status: 409, message } if message == "conflict"
        ));
    }

    #[test]
    fn structural_parse_errors_remain_client_parse_errors() {
        let missing = GvmError::from(ParseError::MissingElement("id".to_string()));
        assert!(matches!(
            missing,
            GvmError::Parse(ParseError::MissingElement(field)) if field == "id"
        ));

        let invalid = GvmError::from(ParseError::InvalidValue {
            field: "port".to_string(),
            value: "invalid".to_string(),
        });
        assert!(matches!(
            invalid,
            GvmError::Parse(ParseError::InvalidValue { field, value })
                if field == "port" && value == "invalid"
        ));
    }

    #[test]
    fn discovery_errors_describe_the_required_action_without_version_wording() {
        let pending = GvmError::CommandDiscoveryRequired {
            command: "export_scan_report".to_string(),
        };
        assert_eq!(
            pending.to_string(),
            "command 'export_scan_report' requires XML help discovery before execution"
        );

        let absent = GvmError::CommandNotAdvertised {
            command: "export_scan_report".to_string(),
        };
        assert_eq!(
            absent.to_string(),
            "command 'export_scan_report' was not advertised by the server's XML help response"
        );
    }
}
