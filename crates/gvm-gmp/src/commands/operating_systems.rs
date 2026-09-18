// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for operating-system assets.
//!
//! Asset operating systems use `get_assets` and are not interchangeable with
//! the distinct SecInfo operating-system response:
//!
//! ```compile_fail
//! use gvm_gmp::commands::operating_systems::GetOperatingSystemAssetRequest;
//! use gvm_gmp::responses::GetOperatingSystemsResponse;
//! use gvm_gmp::{EntityId, GmpRequest};
//!
//! fn require_secinfo<R: GmpRequest<Response = GetOperatingSystemsResponse>>(_: R) {}
//! require_secinfo(GetOperatingSystemAssetRequest::new(
//!     EntityId::new("os-1").unwrap(),
//! ));
//! ```

use gvm_protocol::Request as _;

use crate::commands::assets::{delete_asset_command, get_assets_command, AssetType};
use crate::responses::{DeleteAssetResponse, GetOperatingSystemAssetsResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing operating-system assets through `get_assets`.
#[derive(Debug, Clone, Default)]
pub struct GetOperatingSystemAssetsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether gvmd should ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetOperatingSystemAssetsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_assets",
            "get_operating_system_assets",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_assets_command(
            &AssetType::OperatingSystem,
            None,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.ignore_pagination,
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetOperatingSystemAssetsRequest {
    type Response = GetOperatingSystemAssetsResponse;
}

/// Request for retrieving one operating-system asset.
#[derive(Debug, Clone)]
pub struct GetOperatingSystemAssetRequest {
    /// Operating-system asset identifier to retrieve.
    pub operating_system_id: EntityId,
    /// Optional details flag. Omission preserves the existing gvmd default.
    pub details: Option<bool>,
}

impl GetOperatingSystemAssetRequest {
    /// Create a single operating-system asset request.
    #[must_use]
    pub fn new(operating_system_id: EntityId) -> Self {
        Self {
            operating_system_id,
            details: None,
        }
    }
}

impl GmpRequestCodec for GetOperatingSystemAssetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_assets",
            "get_operating_system_asset",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_assets_command(
            &AssetType::OperatingSystem,
            Some(&self.operating_system_id),
            None,
            None,
            None,
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetOperatingSystemAssetRequest {
    type Response = GetOperatingSystemAssetsResponse;
}

/// Request for deleting an unreferenced operating-system asset.
#[derive(Debug, Clone)]
pub struct DeleteOperatingSystemAssetRequest {
    /// Operating-system asset identifier to delete.
    pub operating_system_id: EntityId,
}

impl DeleteOperatingSystemAssetRequest {
    /// Create an operating-system asset-deletion request.
    #[must_use]
    pub fn new(operating_system_id: EntityId) -> Self {
        Self {
            operating_system_id,
        }
    }
}

impl GmpRequestCodec for DeleteOperatingSystemAssetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "delete_asset",
            "delete_operating_system_asset",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_asset_command(&self.operating_system_id).to_bytes())
    }
}

impl GmpRequest for DeleteOperatingSystemAssetRequest {
    type Response = DeleteAssetResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request"))
            .expect("valid UTF-8")
    }

    #[test]
    fn operating_system_requests_encode_exact_xml_and_associate_responses() {
        fn response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let list = GetOperatingSystemAssetsRequest {
            filter_string: Some("name=Debian".into()),
            filter_id: Some(id("f1")),
            ignore_pagination: Some(true),
            details: Some(true),
        };
        assert_eq!(
            xml(&list),
            "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=Debian\" ignore_pagination=\"1\" type=\"os\"/>"
        );
        response::<_, GetOperatingSystemAssetsResponse>(&list);

        let mut detail = GetOperatingSystemAssetRequest::new(id("os1"));
        assert_eq!(xml(&detail), "<get_assets asset_id=\"os1\" type=\"os\"/>");
        detail.details = Some(false);
        assert_eq!(
            xml(&detail),
            "<get_assets asset_id=\"os1\" details=\"0\" type=\"os\"/>"
        );
        response::<_, GetOperatingSystemAssetsResponse>(&detail);

        let delete = DeleteOperatingSystemAssetRequest::new(id("os1"));
        assert_eq!(xml(&delete), "<delete_asset asset_id=\"os1\"/>");
        response::<_, DeleteAssetResponse>(&delete);
    }
}
