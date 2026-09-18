// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for host-asset operations.

use gvm_protocol::Request as _;

use crate::commands::assets::{
    create_host_asset_command, delete_asset_command, get_assets_command, modify_asset_command,
    validate_ip_name, AssetType,
};
use crate::responses::{
    CreateHostResponse, DeleteHostResponse, GetHostsResponse, ModifyHostResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing host assets.
#[derive(Debug, Clone, Default)]
pub struct GetHostsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether gvmd should ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetHostsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_assets", "get_hosts"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_assets_command(
            &AssetType::Host,
            None,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.ignore_pagination,
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetHostsRequest {
    type Response = GetHostsResponse;
}

/// Request for retrieving one detailed host asset.
#[derive(Debug, Clone)]
pub struct GetHostRequest {
    /// Host asset identifier to retrieve.
    pub host_id: EntityId,
}

impl GetHostRequest {
    /// Create a detailed single-host request.
    #[must_use]
    pub fn new(host_id: EntityId) -> Self {
        Self { host_id }
    }
}

impl GmpRequestCodec for GetHostRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_assets", "get_host"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_assets_command(
            &AssetType::Host,
            Some(&self.host_id),
            None,
            None,
            None,
            Some(true),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetHostRequest {
    type Response = GetHostsResponse;
}

/// Request for directly creating a host asset from one IP address.
#[derive(Debug, Clone)]
pub struct CreateHostRequest {
    /// Required IPv4 or IPv6 address, preserved exactly when encoded.
    pub name: String,
    /// Optional comment. Empty text is omitted on creation.
    pub comment: Option<String>,
}

impl CreateHostRequest {
    /// Create a host request for one IP address.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreateHostRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_ip_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_asset",
            "create_host",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_host_asset_command(&self.name, self.comment.as_deref()).to_bytes())
    }
}

impl GmpRequest for CreateHostRequest {
    type Response = CreateHostResponse;
}

/// Request for replacing a host asset's comment.
#[derive(Debug, Clone)]
pub struct ModifyHostRequest {
    /// Host asset identifier to modify.
    pub host_id: EntityId,
    /// Final comment. An empty string clears the comment.
    pub comment: String,
}

impl ModifyHostRequest {
    /// Create a complete host-comment replacement request.
    #[must_use]
    pub fn new(host_id: EntityId, comment: impl Into<String>) -> Self {
        Self {
            host_id,
            comment: comment.into(),
        }
    }
}

impl GmpRequestCodec for ModifyHostRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "modify_asset",
            "modify_host",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_asset_command(&self.host_id, &self.comment).to_bytes())
    }
}

impl GmpRequest for ModifyHostRequest {
    type Response = ModifyHostResponse;
}

/// Request for permanently deleting a host asset.
#[derive(Debug, Clone)]
pub struct DeleteHostRequest {
    /// Host asset identifier to delete.
    pub host_id: EntityId,
}

impl DeleteHostRequest {
    /// Create a host-deletion request.
    #[must_use]
    pub fn new(host_id: EntityId) -> Self {
        Self { host_id }
    }
}

impl GmpRequestCodec for DeleteHostRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "delete_asset",
            "delete_host",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_asset_command(&self.host_id).to_bytes())
    }
}

impl GmpRequest for DeleteHostRequest {
    type Response = DeleteHostResponse;
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
    fn host_requests_encode_exact_xml_and_associate_responses() {
        fn response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let list = GetHostsRequest {
            filter_string: Some("name=host".into()),
            filter_id: Some(id("f1")),
            ignore_pagination: Some(false),
            details: Some(true),
        };
        assert_eq!(
            xml(&list),
            "<get_assets details=\"1\" filt_id=\"f1\" filter=\"name=host\" ignore_pagination=\"0\" type=\"host\"/>"
        );
        response::<_, GetHostsResponse>(&list);

        let detail = GetHostRequest::new(id("h1"));
        assert_eq!(
            xml(&detail),
            "<get_assets asset_id=\"h1\" details=\"1\" type=\"host\"/>"
        );
        response::<_, GetHostsResponse>(&detail);

        let mut create = CreateHostRequest::new("192.0.2.10");
        create.comment = Some("host".into());
        assert_eq!(
            xml(&create),
            "<create_asset><asset><type>host</type><name>192.0.2.10</name><comment>host</comment></asset></create_asset>"
        );
        response::<_, CreateHostResponse>(&create);

        let modify = ModifyHostRequest::new(id("h1"), "updated");
        assert_eq!(
            xml(&modify),
            "<modify_asset asset_id=\"h1\"><comment>updated</comment></modify_asset>"
        );
        response::<_, ModifyHostResponse>(&modify);

        let delete = DeleteHostRequest::new(id("h1"));
        assert_eq!(xml(&delete), "<delete_asset asset_id=\"h1\"/>");
        response::<_, DeleteHostResponse>(&delete);
    }

    #[test]
    fn mutated_host_name_is_validated() {
        let mut request = CreateHostRequest::new("192.0.2.1");
        request.name = "192.0.2.1,192.0.2.2".into();
        assert!(matches!(
            request.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));
    }
}
