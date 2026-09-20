// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical scan-configuration and policy lifecycle requests plus deferred
//! preference and selection mutation compatibility APIs.

use std::fmt;

use base64::Engine as _;
use gvm_protocol::{xml_command::XmlElement, Request, XmlCommand};
use quick_xml::events::{BytesRef, BytesStart, Event};
use quick_xml::{Reader, XmlVersion};

use crate::commands::configs::{
    config_copy_command, config_delete_command, config_modify_command, config_query_command,
    is_xml_1_0_character, validate_id, validate_metadata, validate_named_copy,
    validate_optional_xml_text, validate_query, ConfigUsageType,
};
use crate::common::bool_str;
use crate::responses::{
    CreateScanConfigResponse, DeleteScanConfigResponse, GetScanConfigPreferencesResponse,
    GetScanConfigsResponse, ModifyScanConfigResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// NVT family selection entry for deferred scan-config and policy mutation requests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NvtFamilySelection {
    /// NVT family name.
    pub name: String,
    /// Whether new NVTs should be added to this family automatically.
    pub growing: bool,
    /// Whether all NVTs from this family should be selected.
    pub all: bool,
}

/// Options for deferred scan-config `get_preferences` requests.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigPreferencesOpts {
    /// Optional NVT OID to restrict preference lookup.
    pub nvt_oid: Option<String>,
    /// Optional scan-config identifier to request configured values.
    pub config_id: Option<EntityId>,
}

/// Request for listing scan configurations.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigsRequest {
    /// Optional configuration identifier selector.
    pub config_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select trashed rather than active configurations.
    pub trash: Option<bool>,
    /// Request detailed output.
    pub details: Option<bool>,
    /// Request family expansion independently of details.
    pub families: Option<bool>,
    /// Request preference expansion independently of details.
    pub preferences: Option<bool>,
    /// Request associated tasks.
    pub tasks: Option<bool>,
}

impl GetScanConfigsRequest {
    /// Create an unfiltered scan-configuration list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            config_id: None,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            families: None,
            preferences: None,
            tasks: None,
        }
    }
}

impl GmpRequestCodec for GetScanConfigsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_configs",
            "get_scan_configs",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            self.config_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.tasks,
            Some(ConfigUsageType::Scan),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetScanConfigsRequest {
    type Response = GetScanConfigsResponse;
}

/// Request for one scan configuration through `get_configs`.
#[derive(Debug, Clone)]
pub struct GetScanConfigRequest {
    /// Required configuration identifier.
    pub config_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Select a trashed configuration.
    pub trash: Option<bool>,
    /// Request details; defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Request family expansion.
    pub families: Option<bool>,
    /// Request preference expansion.
    pub preferences: Option<bool>,
    /// Request associated tasks.
    pub tasks: Option<bool>,
}

impl GetScanConfigRequest {
    /// Create an ID-selected detail request.
    #[must_use]
    pub fn new(config_id: EntityId) -> Self {
        Self {
            config_id,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: Some(true),
            families: None,
            preferences: None,
            tasks: None,
        }
    }
}

impl GmpRequestCodec for GetScanConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_configs",
            "get_scan_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            Some(&self.config_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.tasks,
            Some(ConfigUsageType::Scan),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetScanConfigRequest {
    type Response = GetScanConfigsResponse;
}

/// Request for listing policies.
#[derive(Debug, Clone, Default)]
pub struct GetPoliciesRequest {
    /// Optional policy identifier selector, encoded as `config_id`.
    pub policy_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Select trashed rather than active configurations.
    pub trash: Option<bool>,
    /// Request detailed output.
    pub details: Option<bool>,
    /// Request family expansion independently of details.
    pub families: Option<bool>,
    /// Request preference expansion independently of details.
    pub preferences: Option<bool>,
    /// Request associated tasks, exposed as policy audits.
    pub audits: Option<bool>,
}

impl GetPoliciesRequest {
    /// Create an unfiltered policy list request.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            policy_id: None,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: None,
            families: None,
            preferences: None,
            audits: None,
        }
    }
}

impl GmpRequestCodec for GetPoliciesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            self.policy_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_configs",
            "get_policies",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            self.policy_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.audits,
            Some(ConfigUsageType::Policy),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetPoliciesRequest {
    type Response = GetScanConfigsResponse;
}

/// Request for one policy through `get_configs`.
#[derive(Debug, Clone)]
pub struct GetPolicyRequest {
    /// Required policy identifier, encoded as `config_id`.
    pub policy_id: EntityId,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier.
    pub filter_id: Option<EntityId>,
    /// Select a trashed configuration.
    pub trash: Option<bool>,
    /// Request details; defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Request family expansion.
    pub families: Option<bool>,
    /// Request preference expansion.
    pub preferences: Option<bool>,
    /// Request associated tasks, exposed as policy audits.
    pub audits: Option<bool>,
}

impl GetPolicyRequest {
    /// Create an ID-selected policy detail request.
    #[must_use]
    pub fn new(policy_id: EntityId) -> Self {
        Self {
            policy_id,
            filter_string: None,
            filter_id: None,
            trash: None,
            details: Some(true),
            families: None,
            preferences: None,
            audits: None,
        }
    }
}

impl GmpRequestCodec for GetPolicyRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_query(
            Some(&self.policy_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_configs", "get_policy"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_query_command(
            Some(&self.policy_id),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.trash,
            self.details,
            self.families,
            self.preferences,
            self.audits,
            Some(ConfigUsageType::Policy),
        )
        .to_bytes())
    }
}

impl GmpRequest for GetPolicyRequest {
    type Response = GetScanConfigsResponse;
}

/// Request for creating a named scan configuration from a required base.
#[derive(Debug, Clone)]
pub struct CreateScanConfigRequest {
    /// Required nonempty name.
    pub name: String,
    /// Required source configuration.
    pub base_id: EntityId,
    /// Optional comment override.
    pub comment: Option<String>,
    /// Optional usage override; omission inherits the source usage.
    pub usage_type: Option<ConfigUsageType>,
}

impl CreateScanConfigRequest {
    /// Create a named copy request.
    #[must_use]
    pub fn new(name: impl Into<String>, base_id: EntityId) -> Self {
        Self {
            name: name.into(),
            base_id,
            comment: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for CreateScanConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_named_copy(
            &self.name,
            &self.base_id,
            self.comment.as_deref(),
            "base_id",
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_config",
            "create_scan_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_copy_command(
            &self.base_id,
            Some(&self.name),
            self.comment.as_deref(),
            self.usage_type,
        )
        .to_bytes())
    }
}

impl GmpRequest for CreateScanConfigRequest {
    type Response = CreateScanConfigResponse;
}

/// Request for creating a named policy from a required base.
#[derive(Debug, Clone)]
pub struct CreatePolicyRequest {
    /// Required nonempty policy name.
    pub name: String,
    /// Required source configuration.
    pub base_id: EntityId,
    /// Optional comment override.
    pub comment: Option<String>,
}

impl CreatePolicyRequest {
    /// Create a named policy copy request.
    #[must_use]
    pub fn new(name: impl Into<String>, base_id: EntityId) -> Self {
        Self {
            name: name.into(),
            base_id,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CreatePolicyRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_named_copy(
            &self.name,
            &self.base_id,
            self.comment.as_deref(),
            "base_id",
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_config",
            "create_policy",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(config_copy_command(
            &self.base_id,
            Some(&self.name),
            self.comment.as_deref(),
            Some(ConfigUsageType::Policy),
        )
        .to_bytes())
    }
}

impl GmpRequest for CreatePolicyRequest {
    type Response = CreateScanConfigResponse;
}

macro_rules! clone_request {
    ($name:ident, $id:ident, $semantic:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            /// Required source configuration identifier.
            pub $id: EntityId,
            /// Optional name override; an empty value requests generated naming.
            pub name: Option<String>,
            /// Optional comment override; an empty value inherits the source comment.
            pub comment: Option<String>,
            /// Optional typed usage override; omission inherits source usage.
            pub usage_type: Option<ConfigUsageType>,
        }

        impl $name {
            /// Create a clone request with all overrides omitted.
            #[must_use]
            pub fn new($id: EntityId) -> Self {
                Self {
                    $id,
                    name: None,
                    comment: None,
                    usage_type: None,
                }
            }
        }

        impl GmpRequestCodec for $name {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_id(&self.$id, stringify!($id))?;
                validate_optional_xml_text(self.name.as_deref(), "name")?;
                validate_optional_xml_text(self.comment.as_deref(), "comment")
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("create_config", $semantic))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(config_copy_command(
                    &self.$id,
                    self.name.as_deref(),
                    self.comment.as_deref(),
                    self.usage_type,
                )
                .to_bytes())
            }
        }

        impl GmpRequest for $name {
            type Response = CreateScanConfigResponse;
        }
    };
}

clone_request!(
    CloneScanConfigRequest,
    config_id,
    "clone_scan_config",
    "Request for cloning a scan configuration while inheriting source usage by default."
);
clone_request!(
    ClonePolicyRequest,
    policy_id,
    "clone_policy",
    "Request for cloning through the policy alias without forcing usage conversion."
);

/// Request for importing exactly one scan-configuration export.
#[derive(Clone)]
pub struct ImportScanConfigRequest {
    /// Original exported XML document.
    pub xml: String,
    /// Optional outer usage override.
    pub usage_type: Option<ConfigUsageType>,
}

impl ImportScanConfigRequest {
    /// Store import XML for validation at encode and execute time.
    #[must_use]
    pub fn new(xml: impl Into<String>) -> Self {
        Self {
            xml: xml.into(),
            usage_type: None,
        }
    }
}

impl fmt::Debug for ImportScanConfigRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportScanConfigRequest")
            .field("xml_bytes", &self.xml.len())
            .field("usage_type", &self.usage_type)
            .finish()
    }
}

impl GmpRequestCodec for ImportScanConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_import(&self.xml, "xml").map(|_| ())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_config",
            "import_scan_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        encode_import(&self.xml, self.usage_type, "xml")
    }
}

impl GmpRequest for ImportScanConfigRequest {
    type Response = CreateScanConfigResponse;
}

/// Request for importing exactly one configuration as a policy.
#[derive(Clone)]
pub struct ImportPolicyRequest {
    /// Original exported XML document.
    pub xml: String,
}

impl ImportPolicyRequest {
    /// Store import XML for validation at encode and execute time.
    #[must_use]
    pub fn new(xml: impl Into<String>) -> Self {
        Self { xml: xml.into() }
    }
}

impl fmt::Debug for ImportPolicyRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ImportPolicyRequest")
            .field("xml_bytes", &self.xml.len())
            .finish()
    }
}

impl GmpRequestCodec for ImportPolicyRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_import(&self.xml, "xml").map(|_| ())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_config",
            "import_policy",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        encode_import(&self.xml, Some(ConfigUsageType::Policy), "xml")
    }
}

impl GmpRequest for ImportPolicyRequest {
    type Response = CreateScanConfigResponse;
}

macro_rules! modify_request {
    ($name:ident, $id:ident, $semantic:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            /// Required configuration identifier.
            pub $id: EntityId,
            /// Optional name update; an empty value is a server-side no-op.
            pub name: Option<String>,
            /// Optional comment update; an empty value is a server-side no-op.
            pub comment: Option<String>,
        }

        impl $name {
            /// Create a metadata no-op request.
            #[must_use]
            pub fn new($id: EntityId) -> Self {
                Self {
                    $id,
                    name: None,
                    comment: None,
                }
            }
        }

        impl GmpRequestCodec for $name {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_metadata(
                    &self.$id,
                    self.name.as_deref(),
                    self.comment.as_deref(),
                    stringify!($id),
                )
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("modify_config", $semantic))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(
                    config_modify_command(&self.$id, self.name.as_deref(), self.comment.as_deref())
                        .to_bytes(),
                )
            }
        }

        impl GmpRequest for $name {
            type Response = ModifyScanConfigResponse;
        }
    };
}

modify_request!(
    ModifyScanConfigRequest,
    config_id,
    "modify_scan_config",
    "Request for modifying scan-configuration metadata."
);
modify_request!(
    ModifyPolicyRequest,
    policy_id,
    "modify_policy",
    "Request for modifying policy metadata without changing usage."
);

macro_rules! delete_request {
    ($name:ident, $id:ident, $semantic:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            /// Required configuration identifier.
            pub $id: EntityId,
            /// Optional permanent-deletion flag. Omission uses trash semantics.
            pub ultimate: Option<bool>,
        }

        impl $name {
            /// Create a trash-by-default deletion request.
            #[must_use]
            pub fn new($id: EntityId) -> Self {
                Self {
                    $id,
                    ultimate: None,
                }
            }
        }

        impl GmpRequestCodec for $name {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_id(&self.$id, stringify!($id))
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("delete_config", $semantic))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(config_delete_command(&self.$id, self.ultimate).to_bytes())
            }
        }

        impl GmpRequest for $name {
            type Response = DeleteScanConfigResponse;
        }
    };
}

delete_request!(
    DeleteScanConfigRequest,
    config_id,
    "delete_scan_config",
    "Request for trashing or permanently deleting a scan configuration."
);
delete_request!(
    DeletePolicyRequest,
    policy_id,
    "delete_policy",
    "Request for trashing or permanently deleting a policy."
);

macro_rules! metadata_setter_request {
    ($name:ident, $id:ident, $field:ident, $semantic:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            /// Required configuration identifier.
            pub $id: EntityId,
            /// Exact metadata value. Empty text is emitted and is a gvmd no-op.
            pub $field: String,
        }

        impl $name {
            /// Create a metadata setter request.
            #[must_use]
            pub fn new($id: EntityId, $field: impl Into<String>) -> Self {
                Self {
                    $id,
                    $field: $field.into(),
                }
            }
        }

        impl GmpRequestCodec for $name {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_id(&self.$id, stringify!($id))?;
                validate_optional_xml_text(Some(&self.$field), stringify!($field))
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("modify_config", $semantic))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                let (name, comment) = if stringify!($field) == "name" {
                    (Some(self.$field.as_str()), None)
                } else {
                    (None, Some(self.$field.as_str()))
                };
                Ok(config_modify_command(&self.$id, name, comment).to_bytes())
            }
        }

        impl GmpRequest for $name {
            type Response = ModifyScanConfigResponse;
        }
    };
}

metadata_setter_request!(
    ModifyScanConfigSetNameRequest,
    config_id,
    name,
    "modify_scan_config_set_name",
    "Request for setting a scan-configuration name; empty text is a no-op."
);
metadata_setter_request!(
    ModifyPolicySetNameRequest,
    policy_id,
    name,
    "modify_policy_set_name",
    "Request for setting a policy name; empty text is a no-op."
);

macro_rules! comment_setter_request {
    ($name:ident, $id:ident, $semantic:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone)]
        pub struct $name {
            /// Required configuration identifier.
            pub $id: EntityId,
            /// Optional comment. `None` omits it; `Some("")` emits a no-op element.
            pub comment: Option<String>,
        }

        impl $name {
            /// Create a comment setter request.
            #[must_use]
            pub fn new($id: EntityId, comment: Option<String>) -> Self {
                Self { $id, comment }
            }
        }

        impl GmpRequestCodec for $name {
            fn validate(&self) -> Result<(), GmpRequestError> {
                validate_id(&self.$id, stringify!($id))?;
                validate_optional_xml_text(self.comment.as_deref(), "comment")
            }

            fn command(&self) -> Option<GmpCommand> {
                Some(GmpCommand::with_semantic_name("modify_config", $semantic))
            }

            fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
                self.validate()?;
                Ok(config_modify_command(&self.$id, None, self.comment.as_deref()).to_bytes())
            }
        }

        impl GmpRequest for $name {
            type Response = ModifyScanConfigResponse;
        }
    };
}

comment_setter_request!(
    ModifyScanConfigSetCommentRequest,
    config_id,
    "modify_scan_config_set_comment",
    "Request for setting a scan-configuration comment; empty text is a no-op."
);
comment_setter_request!(
    ModifyPolicySetCommentRequest,
    policy_id,
    "modify_policy_set_comment",
    "Request for setting a policy comment; empty text is a no-op."
);

fn encode_import(
    xml: &str,
    usage_type: Option<ConfigUsageType>,
    field: &'static str,
) -> Result<Vec<u8>, GmpRequestError> {
    let carrier = validate_import(xml, field)?;
    let usage_capacity = usage_type.map_or(0, |_| "<usage_type>policy</usage_type>".len());
    let mut bytes = Vec::with_capacity(
        "<create_config></create_config>".len() + carrier.len() + usage_capacity,
    );
    bytes.extend_from_slice(b"<create_config>");
    bytes.extend_from_slice(carrier.as_bytes());
    if let Some(usage_type) = usage_type {
        bytes.extend_from_slice(b"<usage_type>");
        bytes.extend_from_slice(usage_type.as_gmp_str().as_bytes());
        bytes.extend_from_slice(b"</usage_type>");
    }
    bytes.extend_from_slice(b"</create_config>");
    Ok(bytes)
}

fn validate_import<'a>(xml: &'a str, field: &'static str) -> Result<&'a str, GmpRequestError> {
    let carrier = strip_import_prolog(xml, field)?;
    let mut reader = Reader::from_str(carrier);
    reader.config_mut().trim_text(false);
    reader.config_mut().check_comments = true;
    let mut state = ConfigImportState::new(field);

    loop {
        let event = reader
            .read_event()
            .map_err(|_| import_error(field, "must be well-formed XML"))?;
        match event {
            Event::Start(element) => state.start(&element)?,
            Event::Empty(element) => state.empty(&element)?,
            Event::End(_) => state.end()?,
            Event::Text(text) => state.text(&text.xml_content(XmlVersion::Implicit1_0))?,
            Event::CData(text) => state.text(text.as_ref())?,
            Event::GeneralRef(reference) => {
                let resolved = resolve_reference(&reference).ok_or_else(|| {
                    import_error(field, "contains an unsupported entity reference")
                })?;
                state.text(&resolved)?;
            }
            Event::Decl(_) => {
                return Err(import_error(
                    field,
                    "XML declaration must appear once at the beginning",
                ));
            }
            Event::DocType(_) => return Err(import_error(field, "DOCTYPE is not allowed")),
            Event::PI(_) | Event::Comment(_) => {}
            Event::Eof => break,
        }
    }
    state.finish()?;
    Ok(carrier)
}

fn strip_import_prolog<'a>(xml: &'a str, field: &'static str) -> Result<&'a str, GmpRequestError> {
    let without_bom = xml.strip_prefix('\u{feff}').unwrap_or(xml);
    if !without_bom.starts_with("<?xml") {
        return Ok(without_bom);
    }
    let Some(end) = without_bom.find("?>") else {
        return Err(import_error(
            field,
            "contains an incomplete XML declaration",
        ));
    };
    let declaration = &without_bom[..end + 2];
    let mut reader = Reader::from_str(declaration);
    let Event::Decl(declaration) = reader
        .read_event()
        .map_err(|_| import_error(field, "contains an invalid XML declaration"))?
    else {
        return Err(import_error(field, "contains an invalid XML declaration"));
    };
    let version = declaration
        .version()
        .map_err(|_| import_error(field, "contains an invalid XML declaration"))?;
    if version.as_ref() != "1.0" {
        return Err(import_error(field, "XML declaration must use version 1.0"));
    }
    if let Some(encoding) = declaration.encoding() {
        let encoding =
            encoding.map_err(|_| import_error(field, "contains an invalid XML declaration"))?;
        if !encoding.as_ref().eq_ignore_ascii_case("UTF-8") {
            return Err(import_error(field, "XML declaration must use UTF-8"));
        }
    }
    if let Some(standalone) = declaration.standalone() {
        let standalone =
            standalone.map_err(|_| import_error(field, "contains an invalid XML declaration"))?;
        if !matches!(standalone.as_ref(), "yes" | "no") {
            return Err(import_error(field, "contains an invalid XML declaration"));
        }
    }
    Ok(&without_bom[end + 2..])
}

#[derive(Default)]
struct ImportedPreferenceState {
    nvt_oid_nonempty: bool,
    saw_id: bool,
    id: String,
}

struct ConfigImportState {
    field: &'static str,
    stack: Vec<String>,
    saw_root: bool,
    completed_root: bool,
    invalid_outside_content: bool,
    config_count: usize,
    name_count: usize,
    usage_count: usize,
    selectors_count: usize,
    preferences_count: usize,
    name: String,
    current_preference: Option<ImportedPreferenceState>,
}

impl ConfigImportState {
    const fn new(field: &'static str) -> Self {
        Self {
            field,
            stack: Vec::new(),
            saw_root: false,
            completed_root: false,
            invalid_outside_content: false,
            config_count: 0,
            name_count: 0,
            usage_count: 0,
            selectors_count: 0,
            preferences_count: 0,
            name: String::new(),
            current_preference: None,
        }
    }

    fn start(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.stack.is_empty() {
            self.begin_root(element)?;
        } else if self.completed_root {
            return Err(import_error(
                self.field,
                "must contain exactly one root element",
            ));
        }
        validate_import_attributes(element, self.field)?;
        let name = element.name().as_ref().to_string();
        self.stack.push(name);
        self.record_open(element)
    }

    fn empty(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.stack.is_empty() {
            self.begin_root(element)?;
            validate_import_attributes(element, self.field)?;
            self.stack.push(element.name().as_ref().to_string());
            self.record_open(element)?;
            self.end()?;
            return Ok(());
        }
        if self.completed_root {
            return Err(import_error(
                self.field,
                "must contain exactly one root element",
            ));
        }
        validate_import_attributes(element, self.field)?;
        self.stack.push(element.name().as_ref().to_string());
        self.record_open(element)?;
        self.end()
    }

    fn begin_root(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        if self.saw_root || self.completed_root {
            return Err(import_error(
                self.field,
                "must contain exactly one root element",
            ));
        }
        if element.name().as_ref() != "get_configs_response" {
            return Err(import_error(
                self.field,
                "root must be an unqualified get_configs_response",
            ));
        }
        reject_namespace_attributes(element, self.field)?;
        self.saw_root = true;
        Ok(())
    }

    fn record_open(&mut self, element: &BytesStart<'_>) -> Result<(), GmpRequestError> {
        let depth = self.stack.len();
        let name = self.stack.last().map(String::as_str).unwrap_or_default();
        if depth == 2 && name == "config" {
            reject_namespace_attributes(element, self.field)?;
            self.config_count += 1;
            if self.config_count > 1 {
                return Err(import_error(
                    self.field,
                    "must contain exactly one direct config",
                ));
            }
        }
        if self.config_count == 1 && depth == 3 && self.stack[1] == "config" {
            match name {
                "name" => self.name_count += 1,
                "usage_type" => self.usage_count += 1,
                "nvt_selectors" => self.selectors_count += 1,
                "preferences" => self.preferences_count += 1,
                _ => {}
            }
            if self.name_count > 1
                || self.usage_count > 1
                || self.selectors_count > 1
                || self.preferences_count > 1
            {
                return Err(import_error(
                    self.field,
                    "config contains an ambiguous duplicate direct field",
                ));
            }
        }
        if self.is_preference_path() {
            self.current_preference = Some(ImportedPreferenceState::default());
        } else if self.is_preference_nvt_path() {
            if let Some(preference) = self.current_preference.as_mut() {
                preference.nvt_oid_nonempty = attribute_value(element, "oid", self.field)?
                    .is_some_and(|value| !value.is_empty());
            }
        } else if self.is_preference_id_path() {
            if let Some(preference) = self.current_preference.as_mut() {
                preference.saw_id = true;
            }
        }
        Ok(())
    }

    fn text(&mut self, value: &str) -> Result<(), GmpRequestError> {
        if !value.chars().all(is_xml_1_0_character) {
            return Err(import_error(
                self.field,
                "contains a forbidden XML 1.0 character",
            ));
        }
        if self.stack.is_empty() {
            if !value.chars().all(char::is_whitespace) {
                self.invalid_outside_content = true;
            }
        } else if self.stack.as_slice() == ["get_configs_response", "config", "name"] {
            self.name.push_str(value);
        } else if self.is_preference_id_path() {
            if let Some(preference) = self.current_preference.as_mut() {
                preference.id.push_str(value);
            }
        }
        Ok(())
    }

    fn end(&mut self) -> Result<(), GmpRequestError> {
        if self.is_preference_path() {
            let preference = self.current_preference.take().ok_or_else(|| {
                import_error(self.field, "contains an invalid preference structure")
            })?;
            if preference.nvt_oid_nonempty && (!preference.saw_id || preference.id.is_empty()) {
                return Err(import_error(
                    self.field,
                    "NVT preferences require a nonempty direct id",
                ));
            }
        }
        if self.stack.pop().is_none() {
            return Err(import_error(
                self.field,
                "contains an unmatched closing tag",
            ));
        }
        if self.stack.is_empty() {
            self.completed_root = true;
        }
        Ok(())
    }

    fn finish(self) -> Result<(), GmpRequestError> {
        if !self.saw_root
            || !self.completed_root
            || self.invalid_outside_content
            || !self.stack.is_empty()
        {
            return Err(import_error(
                self.field,
                "must contain one complete response envelope",
            ));
        }
        if self.config_count != 1 {
            return Err(import_error(
                self.field,
                "must contain exactly one direct config",
            ));
        }
        if self.name_count != 1 || self.name.is_empty() {
            return Err(import_error(
                self.field,
                "config must have one nonempty direct name",
            ));
        }
        if self.selectors_count != 1 {
            return Err(import_error(
                self.field,
                "config must have one direct nvt_selectors container",
            ));
        }
        if self.preferences_count != 1 {
            return Err(import_error(
                self.field,
                "config must have one direct preferences container",
            ));
        }
        Ok(())
    }

    fn is_preference_path(&self) -> bool {
        self.stack.len() == 4
            && self.stack[0] == "get_configs_response"
            && self.stack[1] == "config"
            && self.stack[2] == "preferences"
            && self.stack[3] == "preference"
    }

    fn is_preference_nvt_path(&self) -> bool {
        self.stack.len() == 5
            && self.stack[0] == "get_configs_response"
            && self.stack[1] == "config"
            && self.stack[2] == "preferences"
            && self.stack[3] == "preference"
            && self.stack[4] == "nvt"
    }

    fn is_preference_id_path(&self) -> bool {
        self.stack.len() == 5
            && self.stack[0] == "get_configs_response"
            && self.stack[1] == "config"
            && self.stack[2] == "preferences"
            && self.stack[3] == "preference"
            && self.stack[4] == "id"
    }
}

fn validate_import_attributes(
    element: &BytesStart<'_>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|_| import_error(field, "contains an invalid attribute"))?;
        let value = attribute
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|_| import_error(field, "contains an invalid attribute value"))?;
        if !value.chars().all(is_xml_1_0_character) {
            return Err(import_error(
                field,
                "contains a forbidden XML 1.0 character",
            ));
        }
    }
    Ok(())
}

fn reject_namespace_attributes(
    element: &BytesStart<'_>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|_| import_error(field, "contains an invalid attribute"))?;
        let key = attribute.key.as_ref();
        if key == "xmlns" || key.starts_with("xmlns:") {
            return Err(import_error(
                field,
                "required envelope elements must be unqualified",
            ));
        }
    }
    Ok(())
}

fn attribute_value(
    element: &BytesStart<'_>,
    expected: &str,
    field: &'static str,
) -> Result<Option<String>, GmpRequestError> {
    for attribute in element.attributes() {
        let attribute =
            attribute.map_err(|_| import_error(field, "contains an invalid attribute"))?;
        if attribute.key.as_ref() == expected {
            let value = attribute
                .normalized_value(XmlVersion::Implicit1_0)
                .map_err(|_| import_error(field, "contains an invalid attribute value"))?;
            if !value.chars().all(is_xml_1_0_character) {
                return Err(import_error(
                    field,
                    "contains a forbidden XML 1.0 character",
                ));
            }
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn resolve_reference(reference: &BytesRef<'_>) -> Option<String> {
    if let Some(character) = reference.resolve_char_ref().ok()? {
        return is_xml_1_0_character(character).then(|| character.to_string());
    }
    quick_xml::escape::resolve_xml_entity(reference.as_ref()).map(ToString::to_string)
}

fn import_error(field: &'static str, reason: &'static str) -> GmpRequestError {
    GmpRequestError::invalid_field(field, reason)
}

/// Transitional request for scan-configuration preferences.
#[derive(Debug, Clone, Default)]
pub struct GetScanConfigPreferencesRequest {
    opts: GetScanConfigPreferencesOpts,
}

impl GetScanConfigPreferencesRequest {
    /// Create a scan-configuration preference list request.
    #[must_use]
    pub fn new(opts: GetScanConfigPreferencesOpts) -> Self {
        Self { opts }
    }
}

impl Request for GetScanConfigPreferencesRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_config_preferences(self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanConfigPreferencesRequest {
    type Response = GetScanConfigPreferencesResponse;
}

/// Transitional request for one scan-configuration preference.
#[derive(Debug, Clone)]
pub struct GetScanConfigPreferenceRequest {
    name: String,
    opts: GetScanConfigPreferencesOpts,
}

impl GetScanConfigPreferenceRequest {
    /// Create a single scan-configuration preference request.
    #[must_use]
    pub fn new(name: impl Into<String>, opts: GetScanConfigPreferencesOpts) -> Self {
        Self {
            name: name.into(),
            opts,
        }
    }
}

impl Request for GetScanConfigPreferenceRequest {
    fn to_bytes(&self) -> Vec<u8> {
        get_scan_config_preference(&self.name, self.opts.clone()).to_bytes()
    }
}

impl GmpRequest for GetScanConfigPreferenceRequest {
    type Response = GetScanConfigPreferencesResponse;
}

macro_rules! define_nvt_preference_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            name: String,
            nvt_oid: String,
            value: Option<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                name: impl Into<String>,
                nvt_oid: impl Into<String>,
                value: Option<String>,
            ) -> Self {
                Self {
                    resource_id,
                    name: name.into(),
                    nvt_oid: nvt_oid.into(),
                    value,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(
                    &self.resource_id,
                    &self.name,
                    &self.nvt_oid,
                    self.value.as_deref(),
                )
                .to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_scanner_preference_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            name: String,
            value: Option<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                name: impl Into<String>,
                value: Option<String>,
            ) -> Self {
                Self {
                    resource_id,
                    name: name.into(),
                    value,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, &self.name, self.value.as_deref()).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_nvt_selection_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            family: String,
            nvt_oids: Vec<String>,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                family: impl Into<String>,
                nvt_oids: Vec<String>,
            ) -> Self {
                Self {
                    resource_id,
                    family: family.into(),
                    nvt_oids,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(&self.resource_id, &self.family, &self.nvt_oids).to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

macro_rules! define_family_selection_request {
    ($request:ident, $builder:ident, $request_doc:literal, $new_doc:literal) => {
        #[doc = $request_doc]
        #[derive(Debug, Clone)]
        pub struct $request {
            resource_id: EntityId,
            families: Vec<NvtFamilySelection>,
            auto_add_new_families: bool,
        }

        impl $request {
            #[doc = $new_doc]
            #[must_use]
            pub fn new(
                resource_id: EntityId,
                families: Vec<NvtFamilySelection>,
                auto_add_new_families: bool,
            ) -> Self {
                Self {
                    resource_id,
                    families,
                    auto_add_new_families,
                }
            }
        }

        impl Request for $request {
            fn to_bytes(&self) -> Vec<u8> {
                $builder(
                    &self.resource_id,
                    &self.families,
                    self.auto_add_new_families,
                )
                .to_bytes()
            }
        }

        impl GmpRequest for $request {
            type Response = ModifyScanConfigResponse;
        }
    };
}

define_nvt_preference_request!(
    ModifyScanConfigSetNvtPreferenceRequest,
    modify_scan_config_set_nvt_preference,
    "Semantic request for setting or deleting a scan-config NVT preference.",
    "Create a scan-config NVT-preference mutation request."
);
define_scanner_preference_request!(
    ModifyScanConfigSetScannerPreferenceRequest,
    modify_scan_config_set_scanner_preference,
    "Semantic request for setting or deleting a scan-config scanner preference.",
    "Create a scan-config scanner-preference mutation request."
);
define_nvt_selection_request!(
    ModifyScanConfigSetNvtSelectionRequest,
    modify_scan_config_set_nvt_selection,
    "Semantic request for replacing a scan-config NVT selection.",
    "Create a scan-config NVT-selection mutation request."
);
define_family_selection_request!(
    ModifyScanConfigSetFamilySelectionRequest,
    modify_scan_config_set_family_selection,
    "Semantic request for replacing a scan-config family selection.",
    "Create a scan-config family-selection mutation request."
);
define_nvt_preference_request!(
    ModifyPolicySetNvtPreferenceRequest,
    modify_policy_set_nvt_preference,
    "Semantic request for setting or deleting a policy NVT preference.",
    "Create a policy NVT-preference mutation request."
);
define_scanner_preference_request!(
    ModifyPolicySetScannerPreferenceRequest,
    modify_policy_set_scanner_preference,
    "Semantic request for setting or deleting a policy scanner preference.",
    "Create a policy scanner-preference mutation request."
);
define_nvt_selection_request!(
    ModifyPolicySetNvtSelectionRequest,
    modify_policy_set_nvt_selection,
    "Semantic request for replacing a policy NVT selection.",
    "Create a policy NVT-selection mutation request."
);
define_family_selection_request!(
    ModifyPolicySetFamilySelectionRequest,
    modify_policy_set_family_selection,
    "Semantic request for replacing a policy family selection.",
    "Create a policy family-selection mutation request."
);

/// Build a deferred `get_preferences` request for scan-config preferences.
#[must_use]
pub fn get_scan_config_preferences(opts: GetScanConfigPreferencesOpts) -> impl Request {
    get_preferences_with(
        None,
        opts.nvt_oid.as_deref(),
        opts.config_id.as_ref().map(EntityId::as_str),
    )
}

/// Build a deferred `get_preferences` request for one scan-config preference.
#[must_use]
pub fn get_scan_config_preference(name: &str, opts: GetScanConfigPreferencesOpts) -> impl Request {
    get_preferences_with(
        Some(name),
        opts.nvt_oid.as_deref(),
        opts.config_id.as_ref().map(EntityId::as_str),
    )
}

fn get_preferences_with(
    preference: Option<&str>,
    nvt_oid: Option<&str>,
    config_id: Option<&str>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_preferences");
    if let Some(preference) = preference {
        command.set_attribute("preference", preference);
    }
    if let Some(nvt_oid) = nvt_oid {
        command.set_attribute("nvt_oid", nvt_oid);
    }
    if let Some(config_id) = config_id {
        command.set_attribute("config_id", config_id);
    }
    command
}

/// Build a deferred `modify_config` request that sets an NVT preference.
#[must_use]
pub fn modify_scan_config_set_nvt_preference(
    config_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_nvt_preference(config_id, name, nvt_oid, value)
}

/// Build a deferred `modify_config` request that sets a scanner preference.
#[must_use]
pub fn modify_scan_config_set_scanner_preference(
    config_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_scanner_preference(config_id, name, value)
}

/// Build a deferred `modify_config` request that replaces an NVT selection.
#[must_use]
pub fn modify_scan_config_set_nvt_selection(
    config_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> impl Request {
    modify_config_set_nvt_selection(config_id, family, nvt_oids)
}

/// Build a deferred `modify_config` request that replaces family selection.
#[must_use]
pub fn modify_scan_config_set_family_selection(
    config_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> impl Request {
    modify_config_set_family_selection(config_id, families, auto_add_new_families)
}

/// Build a deferred policy NVT-preference mutation request.
#[must_use]
pub fn modify_policy_set_nvt_preference(
    policy_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_nvt_preference(policy_id, name, nvt_oid, value)
}

/// Build a deferred policy scanner-preference mutation request.
#[must_use]
pub fn modify_policy_set_scanner_preference(
    policy_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> impl Request {
    modify_config_set_scanner_preference(policy_id, name, value)
}

/// Build a deferred policy NVT-selection mutation request.
#[must_use]
pub fn modify_policy_set_nvt_selection(
    policy_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> impl Request {
    modify_config_set_nvt_selection(policy_id, family, nvt_oids)
}

/// Build a deferred policy family-selection mutation request.
#[must_use]
pub fn modify_policy_set_family_selection(
    policy_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> impl Request {
    modify_config_set_family_selection(policy_id, families, auto_add_new_families)
}

fn modify_config_set_nvt_preference(
    config_id: &EntityId,
    name: &str,
    nvt_oid: &str,
    value: Option<&str>,
) -> XmlCommand {
    let mut command = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let preference = command.add_element("preference");
    preference.add_child("nvt").set_attribute("oid", nvt_oid);
    preference.add_child_with_text("name", name);
    add_encoded_preference_value(preference, value);
    command
}

fn modify_config_set_scanner_preference(
    config_id: &EntityId,
    name: &str,
    value: Option<&str>,
) -> XmlCommand {
    let mut command = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let preference = command.add_element("preference");
    preference.add_child_with_text("name", name);
    add_encoded_preference_value(preference, value);
    command
}

fn modify_config_set_nvt_selection(
    config_id: &EntityId,
    family: &str,
    nvt_oids: &[String],
) -> XmlCommand {
    let mut command = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let selection = command.add_element("nvt_selection");
    selection.add_child_with_text("family", family);
    for nvt_oid in nvt_oids {
        selection.add_child("nvt").set_attribute("oid", nvt_oid);
    }
    command
}

fn modify_config_set_family_selection(
    config_id: &EntityId,
    families: &[NvtFamilySelection],
    auto_add_new_families: bool,
) -> XmlCommand {
    let mut command = XmlCommand::new("modify_config").attribute("config_id", config_id.as_str());
    let selection = command.add_element("family_selection");
    selection.add_child_with_text("growing", bool_str(auto_add_new_families));
    for family in families {
        let family_element = selection.add_child("family");
        family_element.add_child_with_text("name", &family.name);
        family_element.add_child_with_text("all", bool_str(family.all));
        family_element.add_child_with_text("growing", bool_str(family.growing));
    }
    command
}

fn add_encoded_preference_value(preference: &mut XmlElement, value: Option<&str>) {
    if let Some(value) = value.filter(|value| !value.is_empty()) {
        let encoded = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        preference.add_child_with_text("value", &encoded);
    }
}
