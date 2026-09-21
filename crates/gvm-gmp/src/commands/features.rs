// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical feature discovery request.

use gvm_protocol::{Request as _, XmlCommand};

use crate::responses::GetFeaturesResponse;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical request for discovering compiled and enabled gvmd features.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetFeaturesRequest;

impl GetFeaturesRequest {
    /// Create a feature-discovery request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for GetFeaturesRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_features"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_features").to_bytes())
    }
}

impl GmpRequest for GetFeaturesRequest {
    type Response = GetFeaturesResponse;
}
