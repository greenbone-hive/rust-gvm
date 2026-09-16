// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Statically associated GMP request and response contracts.

use gvm_protocol::{Request, Response};

use crate::{responses::ParseError, GmpVersion};

/// Failure while validating or encoding a semantic GMP request.
///
/// Reasons are static by design: errors identify the invalid field or field
/// combination without retaining caller-provided values that may be secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum GmpRequestError {
    /// One field in the final semantic request violates an input constraint.
    #[error("invalid request field '{field}': {reason}")]
    InvalidField {
        /// Stable field name, never the caller-provided value.
        field: &'static str,
        /// Value-independent explanation of the violated constraint.
        reason: &'static str,
    },
    /// A relationship between fields violates an input constraint.
    #[error("invalid request field combination {fields:?}: {reason}")]
    InvalidCombination {
        /// Stable field names participating in the invalid combination.
        fields: &'static [&'static str],
        /// Value-independent explanation of the violated constraint.
        reason: &'static str,
    },
    /// A valid semantic value cannot be represented for the negotiated version.
    #[error("request encoding failed for GMP {version}: {reason}")]
    Encoding {
        /// Negotiated GMP version for which representation failed.
        version: GmpVersion,
        /// Value-independent explanation of the representation failure.
        reason: &'static str,
    },
}

impl GmpRequestError {
    /// Construct a final-value field validation error.
    #[must_use]
    pub const fn invalid_field(field: &'static str, reason: &'static str) -> Self {
        Self::InvalidField { field, reason }
    }

    /// Construct a final-value field-combination validation error.
    #[must_use]
    pub const fn invalid_combination(
        fields: &'static [&'static str],
        reason: &'static str,
    ) -> Self {
        Self::InvalidCombination { fields, reason }
    }

    /// Construct a version-aware representation error.
    #[must_use]
    pub const fn encoding(version: GmpVersion, reason: &'static str) -> Self {
        Self::Encoding { version, reason }
    }
}

/// Semantic command identity used for typed capability checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GmpCommand {
    wire_name: &'static str,
    semantic_name: Option<&'static str>,
}

impl GmpCommand {
    /// Describe a request whose semantic operation is its wire command.
    #[must_use]
    pub const fn new(wire_name: &'static str) -> Self {
        Self {
            wire_name,
            semantic_name: None,
        }
    }

    /// Describe a semantic operation that reuses another command's wire root.
    #[must_use]
    pub const fn with_semantic_name(wire_name: &'static str, semantic_name: &'static str) -> Self {
        Self {
            wire_name,
            semantic_name: Some(semantic_name),
        }
    }

    /// Return the command's encoded XML root name.
    #[must_use]
    pub const fn wire_name(self) -> &'static str {
        self.wire_name
    }

    /// Return the distinct semantic capability name, when present.
    #[must_use]
    pub const fn semantic_name(self) -> Option<&'static str> {
        self.semantic_name
    }
}

/// Validation, capability metadata, and version-aware encoding for a typed request.
///
/// Canonical complete-request types implement this trait directly and do not
/// implement raw [`Request`]. The blanket implementation below is a temporary
/// adapter for the existing builder-backed semantic requests. It keeps family
/// migration separate from the execution-foundation change.
pub trait GmpRequestCodec: Send {
    /// Validate the final semantic value before capability checks or encoding.
    ///
    /// # Errors
    /// Returns a typed request error when the final value is invalid.
    fn validate(&self) -> Result<(), GmpRequestError> {
        Ok(())
    }

    /// Return semantic capability metadata without inspecting encoded XML.
    ///
    /// Existing builder-backed requests return `None` through the transitional
    /// raw-request adapter and retain the legacy encoded-root gate until their
    /// resource family is converted.
    fn command(&self) -> Option<GmpCommand> {
        None
    }

    /// Encode this request for the negotiated GMP version.
    ///
    /// # Errors
    /// Returns a typed request error when version-specific encoding fails.
    fn encode(&self, version: GmpVersion) -> Result<Vec<u8>, GmpRequestError>;

    /// Preserve semantic aliases while a request uses the raw adapter.
    #[doc(hidden)]
    fn legacy_semantic_command_name(&self) -> Option<&'static str> {
        None
    }
}

impl<T: Request> GmpRequestCodec for T {
    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(self.to_bytes())
    }

    fn legacy_semantic_command_name(&self) -> Option<&'static str> {
        self.semantic_command_name()
    }
}

/// A semantic GMP request whose response type is known at compile time.
///
/// Canonical requests implement [`GmpRequestCodec`] directly, so final-value
/// validation and semantic capability checks can run before version-aware
/// encoding and transport. Existing builder-backed request types continue to
/// work through the temporary raw [`Request`] adapter during family migration.
///
/// A downstream custom codec uses the same public contracts:
///
/// ```
/// use gvm_gmp::responses::ParseError;
/// use gvm_gmp::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse, GmpVersion};
/// use gvm_protocol::{Request as _, Response, XmlCommand};
///
/// struct CustomRequest {
///     resource_id: String,
/// }
///
/// impl GmpRequestCodec for CustomRequest {
///     fn validate(&self) -> Result<(), GmpRequestError> {
///         if self.resource_id.is_empty() {
///             return Err(GmpRequestError::invalid_field(
///                 "resource_id",
///                 "must not be empty",
///             ));
///         }
///         Ok(())
///     }
///
///     fn command(&self) -> Option<GmpCommand> {
///         Some(GmpCommand::new("custom_command"))
///     }
///
///     fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
///         Ok(XmlCommand::new("custom_command")
///             .attribute("resource_id", &self.resource_id)
///             .to_bytes())
///     }
/// }
///
/// #[derive(Debug, PartialEq, Eq)]
/// struct CustomResponse(u16);
///
/// impl GmpResponse for CustomResponse {
///     fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
///         let status = response
///             .status_code()
///             .ok_or_else(|| ParseError::MissingElement("status".into()))?;
///         let message = response
///             .status_text()
///             .ok_or_else(|| ParseError::MissingElement("status_text".into()))?;
///         if !(200..300).contains(&status) {
///             return Err(ParseError::ServerError { status, message });
///         }
///         Ok(Self(status))
///     }
/// }
///
/// impl GmpRequest for CustomRequest {
///     type Response = CustomResponse;
/// }
///
/// fn require_custom_response<R: GmpRequest<Response = CustomResponse>>(_: R) {}
/// require_custom_response(CustomRequest { resource_id: "id-1".into() });
/// let raw = Response::new(
///     br#"<custom_command_response status="200" status_text="OK"/>"#.to_vec(),
/// );
/// assert_eq!(CustomResponse::decode(&raw, GmpVersion(22, 8))?, CustomResponse(200));
/// # Ok::<(), ParseError>(())
/// ```
///
/// A request cannot be associated with an unrelated response type:
///
/// ```compile_fail
/// use gvm_gmp::commands::version::GetVersionRequest;
/// use gvm_gmp::responses::AuthenticateResponse;
/// use gvm_gmp::GmpRequest;
///
/// fn require_authentication<R: GmpRequest<Response = AuthenticateResponse>>(_: R) {}
/// require_authentication(GetVersionRequest::new());
/// ```
pub trait GmpRequest: GmpRequestCodec {
    /// The only typed response produced by this request.
    type Response: GmpResponse;
}

/// A typed GMP response that can decode the protocol response envelope.
///
/// Implementations must preserve the typed response contract: non-2xx GMP
/// statuses are returned as [`ParseError::ServerError`], and structural parse
/// errors retain enough field context to identify the malformed value. This is
/// the extension point for irregular or application-owned response codecs.
pub trait GmpResponse: Sized {
    /// Decode a typed value from a raw GMP response.
    ///
    /// The negotiated `version` is available to response models whose wire
    /// shape varies by GMP version. Models that are version-independent may
    /// ignore it.
    ///
    /// # Errors
    /// Returns the response model's existing parse or server-status error.
    fn decode(response: &Response, version: GmpVersion) -> Result<Self, ParseError>;
}
