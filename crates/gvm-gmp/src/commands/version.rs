// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical version discovery request.

use gvm_protocol::{Request as _, XmlCommand};

use crate::responses::GetVersionResponse;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical pre-authentication `get_version` request.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetVersionRequest;

impl GetVersionRequest {
    /// Create a version request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for GetVersionRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_version"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_version").to_bytes())
    }
}

impl GmpRequest for GetVersionRequest {
    type Response = GetVersionResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_version_request_builds_xml() {
        assert_eq!(
            GetVersionRequest::new()
                .encode(GmpVersion(22, 4))
                .expect("version request encodes"),
            b"<get_version/>"
        );
    }
}
