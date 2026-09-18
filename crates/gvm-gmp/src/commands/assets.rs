// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for generic asset operations.

use std::net::IpAddr;

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{
    CreateAssetResponse, DeleteAssetResponse, GetAssetsResponse, ModifyAssetResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Typed GMP asset type values.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AssetType {
    /// Host assets.
    Host,
    /// Operating-system assets.
    OperatingSystem,
    /// Forward-compatible custom asset type for reads.
    ///
    /// Current gvmd accepts only `host` and `os`; a nonempty unknown value is
    /// retained so a newer server can remain authoritative.
    Custom(String),
}

impl AssetType {
    /// Build a custom/unknown asset type value.
    #[must_use]
    pub fn custom(value: impl Into<String>) -> Self {
        Self::Custom(value.into())
    }

    /// Returns the GMP wire-format string for this value.
    #[must_use]
    pub fn as_gmp_str(&self) -> &str {
        match self {
            Self::Host => "host",
            Self::OperatingSystem => "os",
            Self::Custom(value) => value.as_str(),
        }
    }

    fn validate(&self) -> Result<(), GmpRequestError> {
        if matches!(self, Self::Custom(value) if value.is_empty()) {
            Err(GmpRequestError::invalid_field(
                "asset_type",
                "custom asset type must not be empty",
            ))
        } else {
            Ok(())
        }
    }
}

/// Request for listing generic assets of one required type.
#[derive(Debug, Clone)]
pub struct GetAssetsRequest {
    /// Required asset type. Current gvmd supports host and operating-system reads.
    pub asset_type: AssetType,
    /// Optional asset identifier selector.
    pub asset_id: Option<EntityId>,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether gvmd should ignore pagination terms from the selected filter.
    pub ignore_pagination: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GetAssetsRequest {
    /// Create a generic asset-list request for the required asset type.
    #[must_use]
    pub fn new(asset_type: AssetType) -> Self {
        Self {
            asset_type,
            asset_id: None,
            filter_string: None,
            filter_id: None,
            ignore_pagination: None,
            details: None,
        }
    }
}

impl GmpRequestCodec for GetAssetsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        self.asset_type.validate()
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_assets"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_assets_command(
            &self.asset_type,
            self.asset_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.ignore_pagination,
            self.details,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetAssetsRequest {
    type Response = GetAssetsResponse;
}

/// Request for retrieving one detailed generic asset.
#[derive(Debug, Clone)]
pub struct GetAssetRequest {
    /// Asset identifier to retrieve.
    pub asset_id: EntityId,
    /// Required asset type.
    pub asset_type: AssetType,
}

impl GetAssetRequest {
    /// Create a detailed single-asset request.
    #[must_use]
    pub fn new(asset_id: EntityId, asset_type: AssetType) -> Self {
        Self {
            asset_id,
            asset_type,
        }
    }
}

impl GmpRequestCodec for GetAssetRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        self.asset_type.validate()
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_assets", "get_asset"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_assets_command(
            &self.asset_type,
            Some(&self.asset_id),
            None,
            None,
            None,
            Some(true),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetAssetRequest {
    type Response = GetAssetsResponse;
}

/// Request for directly creating a host asset from one IP address.
#[derive(Debug, Clone)]
pub struct CreateAssetRequest {
    /// Required IPv4 or IPv6 address, preserved exactly when encoded.
    pub name: String,
    /// Optional comment. Empty text is omitted on creation.
    pub comment: Option<String>,
}

impl CreateAssetRequest {
    /// Create a direct host-asset request for one IP address.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreateAssetRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_ip_name(&self.name)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_asset"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_host_asset_command(&self.name, self.comment.as_deref()).to_bytes())
    }
}

impl GmpRequest for CreateAssetRequest {
    type Response = CreateAssetResponse;
}

/// Request for replacing a host asset's comment.
#[derive(Debug, Clone)]
pub struct ModifyAssetRequest {
    /// Asset identifier. gvmd authoritatively requires this to identify a host.
    pub asset_id: EntityId,
    /// Final comment. An empty string clears the comment.
    pub comment: String,
}

impl ModifyAssetRequest {
    /// Create a complete asset-comment replacement request.
    #[must_use]
    pub fn new(asset_id: EntityId, comment: impl Into<String>) -> Self {
        Self {
            asset_id,
            comment: comment.into(),
        }
    }
}

impl GmpRequestCodec for ModifyAssetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_asset"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_asset_command(&self.asset_id, &self.comment).to_bytes())
    }
}

impl GmpRequest for ModifyAssetRequest {
    type Response = ModifyAssetResponse;
}

/// Request for permanently deleting an asset by identifier.
#[derive(Debug, Clone)]
pub struct DeleteAssetRequest {
    /// Asset identifier to delete.
    pub asset_id: EntityId,
}

impl DeleteAssetRequest {
    /// Create an asset-deletion request.
    #[must_use]
    pub fn new(asset_id: EntityId) -> Self {
        Self { asset_id }
    }
}

impl GmpRequestCodec for DeleteAssetRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_asset"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_asset_command(&self.asset_id).to_bytes())
    }
}

impl GmpRequest for DeleteAssetRequest {
    type Response = DeleteAssetResponse;
}

pub(crate) fn validate_ip_name(name: &str) -> Result<(), GmpRequestError> {
    if name.parse::<IpAddr>().is_err() {
        Err(GmpRequestError::invalid_field(
            "name",
            "must be one IPv4 or IPv6 address",
        ))
    } else {
        Ok(())
    }
}

pub(crate) fn get_assets_command(
    asset_type: &AssetType,
    asset_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    ignore_pagination: Option<bool>,
    details: Option<bool>,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_assets");
    if let Some(asset_id) = asset_id {
        cmd.set_attribute("asset_id", asset_id.as_str());
    }
    cmd.set_attribute("type", asset_type.as_gmp_str());
    add_filter_attrs(&mut cmd, filter_string, filter_id);
    set_optional_bool_attr(&mut cmd, "ignore_pagination", ignore_pagination);
    set_optional_bool_attr(&mut cmd, "details", details);
    cmd
}

pub(crate) fn create_host_asset_command(name: &str, comment: Option<&str>) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_asset");
    let asset = cmd.add_element("asset");
    asset.add_child_with_text("type", "host");
    asset.add_child_with_text("name", name);
    if let Some(comment) = comment.filter(|value| !value.is_empty()) {
        asset.add_child_with_text("comment", comment);
    }
    cmd
}

pub(crate) fn modify_asset_command(asset_id: &EntityId, comment: &str) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_asset").attribute("asset_id", asset_id.as_str());
    cmd.add_element_with_text("comment", comment);
    cmd
}

pub(crate) fn delete_asset_command(asset_id: &EntityId) -> XmlCommand {
    XmlCommand::new("delete_asset").attribute("asset_id", asset_id.as_str())
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
    fn all_asset_requests_encode_exact_xml_and_associate_responses() {
        fn response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let mut list = GetAssetsRequest::new(AssetType::custom("firmware"));
        list.asset_id = Some(id("a1"));
        list.filter_string = Some("name=foo & bar".into());
        list.filter_id = Some(id("f1"));
        list.ignore_pagination = Some(true);
        list.details = Some(false);
        assert_eq!(
            xml(&list),
            "<get_assets asset_id=\"a1\" details=\"0\" filt_id=\"f1\" filter=\"name=foo &amp; bar\" ignore_pagination=\"1\" type=\"firmware\"/>"
        );
        response::<_, GetAssetsResponse>(&list);

        let detail = GetAssetRequest::new(id("a1"), AssetType::OperatingSystem);
        assert_eq!(
            xml(&detail),
            "<get_assets asset_id=\"a1\" details=\"1\" type=\"os\"/>"
        );
        response::<_, GetAssetsResponse>(&detail);

        let mut create = CreateAssetRequest::new("2001:0db8:0:0:0:0:0:1");
        create.comment = Some("a < b".into());
        assert_eq!(
            xml(&create),
            "<create_asset><asset><type>host</type><name>2001:0db8:0:0:0:0:0:1</name><comment>a &lt; b</comment></asset></create_asset>"
        );
        response::<_, CreateAssetResponse>(&create);

        create.comment = Some(String::new());
        assert_eq!(
            xml(&create),
            "<create_asset><asset><type>host</type><name>2001:0db8:0:0:0:0:0:1</name></asset></create_asset>"
        );

        let modify = ModifyAssetRequest::new(id("a1"), "");
        assert_eq!(
            xml(&modify),
            "<modify_asset asset_id=\"a1\"><comment></comment></modify_asset>"
        );
        response::<_, ModifyAssetResponse>(&modify);

        let delete = DeleteAssetRequest::new(id("a1"));
        assert_eq!(xml(&delete), "<delete_asset asset_id=\"a1\"/>");
        response::<_, DeleteAssetResponse>(&delete);
    }

    #[test]
    fn final_values_are_validated() {
        let mut create = CreateAssetRequest::new("192.0.2.1");
        for invalid in ["", "example.test", "192.0.2.1/24", "192.0.2.1-2"] {
            create.name = invalid.into();
            assert!(matches!(
                create.validate(),
                Err(GmpRequestError::InvalidField { field: "name", .. })
            ));
            assert!(create.encode(GmpVersion(22, 4)).is_err());
        }

        let mut list = GetAssetsRequest::new(AssetType::Host);
        list.asset_type = AssetType::custom("");
        assert!(matches!(
            list.validate(),
            Err(GmpRequestError::InvalidField {
                field: "asset_type",
                ..
            })
        ));
    }

    #[test]
    fn metadata_is_available_without_encoding() {
        assert_eq!(
            GetAssetRequest::new(id("a1"), AssetType::Host)
                .command()
                .expect("metadata")
                .semantic_name(),
            Some("get_asset")
        );
        assert_eq!(
            CreateAssetRequest::new("invalid")
                .command()
                .expect("metadata")
                .wire_name(),
            "create_asset"
        );
    }
}
