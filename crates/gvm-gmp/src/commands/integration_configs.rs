// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for integration-configuration operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::{GetIntegrationConfigsResponse, ModifyIntegrationConfigResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Semantic request for listing integration configurations.
#[derive(Debug, Clone, Default)]
pub struct GetIntegrationConfigsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
}

impl GmpRequestCodec for GetIntegrationConfigsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_integration_configs"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_integration_configs_command(self).to_bytes())
    }
}

impl GmpRequest for GetIntegrationConfigsRequest {
    type Response = GetIntegrationConfigsResponse;
}

/// Semantic request for one integration configuration.
#[derive(Debug, Clone)]
pub struct GetIntegrationConfigRequest {
    /// Integration-configuration identifier to retrieve.
    pub integration_config_id: EntityId,
    /// Whether to include service and OIDC details.
    pub details: Option<bool>,
}

impl GetIntegrationConfigRequest {
    /// Create a single integration-configuration request.
    #[must_use]
    pub fn new(integration_config_id: EntityId, details: Option<bool>) -> Self {
        Self {
            integration_config_id,
            details,
        }
    }
}

impl GmpRequestCodec for GetIntegrationConfigRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_integration_configs",
            "get_integration_config",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_integration_config_command(self).to_bytes())
    }
}

impl GmpRequest for GetIntegrationConfigRequest {
    type Response = GetIntegrationConfigsResponse;
}

/// Semantic request for replacing or clearing an integration configuration.
///
/// Leaving every configurable field unset clears the integration
/// configuration. A replacement requires non-empty service URL, OIDC provider
/// URL, client ID, and client secret values together. The service CA
/// certificate remains optional.
#[derive(Clone)]
pub struct ModifyIntegrationConfigRequest {
    /// Integration-configuration identifier to modify.
    pub integration_config_id: EntityId,
    /// Optional integration service URL.
    pub service_url: Option<String>,
    /// Optional integration service CA certificate.
    pub service_cacert: Option<String>,
    /// Optional OIDC provider URL.
    pub oidc_provider_url: Option<String>,
    /// Optional OIDC provider client ID.
    pub oidc_provider_client_id: Option<String>,
    /// Optional OIDC provider client secret.
    pub oidc_provider_client_secret: Option<String>,
}

impl std::fmt::Debug for ModifyIntegrationConfigRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ModifyIntegrationConfigRequest")
            .field("integration_config_id", &self.integration_config_id)
            .field("service_url", &self.service_url)
            .field(
                "service_cacert",
                &self.service_cacert.as_ref().map(|_| "<redacted>"),
            )
            .field("oidc_provider_url", &self.oidc_provider_url)
            .field("oidc_provider_client_id", &self.oidc_provider_client_id)
            .field(
                "oidc_provider_client_secret",
                &self
                    .oidc_provider_client_secret
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl ModifyIntegrationConfigRequest {
    /// Create an integration-configuration clear request.
    ///
    /// Populate all four required replacement fields to replace the
    /// configuration instead.
    #[must_use]
    pub fn new(integration_config_id: EntityId) -> Self {
        Self {
            integration_config_id,
            service_url: None,
            service_cacert: None,
            oidc_provider_url: None,
            oidc_provider_client_id: None,
            oidc_provider_client_secret: None,
        }
    }
}

impl GmpRequestCodec for ModifyIntegrationConfigRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_modify_integration_config(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_integration_config"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(modify_integration_config_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyIntegrationConfigRequest {
    type Response = ModifyIntegrationConfigResponse;
}

fn get_integration_configs_command(request: &GetIntegrationConfigsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_integration_configs");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    cmd
}

fn get_integration_config_command(request: &GetIntegrationConfigRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_integration_configs").attribute(
        "integration_config_id",
        request.integration_config_id.as_str(),
    );
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn modify_integration_config_command(request: &ModifyIntegrationConfigRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_integration_config")
        .attribute("uuid", request.integration_config_id.as_str());

    let service = cmd.add_element("service");
    service.add_child_with_text("url", request.service_url.as_deref().unwrap_or_default());
    service.add_child_with_text(
        "cacert",
        request.service_cacert.as_deref().unwrap_or_default(),
    );

    let oidc = cmd.add_element("oidc");
    oidc.add_child_with_text(
        "url",
        request.oidc_provider_url.as_deref().unwrap_or_default(),
    );

    let client = oidc.add_child("client");
    client.add_child_with_text(
        "id",
        request
            .oidc_provider_client_id
            .as_deref()
            .unwrap_or_default(),
    );
    client.add_child_with_text(
        "secret",
        request
            .oidc_provider_client_secret
            .as_deref()
            .unwrap_or_default(),
    );

    cmd
}

fn validate_modify_integration_config(
    request: &ModifyIntegrationConfigRequest,
) -> Result<(), GmpRequestError> {
    let any_field_is_set = request.service_url.is_some()
        || request.service_cacert.is_some()
        || request.oidc_provider_url.is_some()
        || request.oidc_provider_client_id.is_some()
        || request.oidc_provider_client_secret.is_some();
    if !any_field_is_set {
        return Ok(());
    }

    let required_fields_are_nonempty = [
        request.service_url.as_deref(),
        request.oidc_provider_url.as_deref(),
        request.oidc_provider_client_id.as_deref(),
        request.oidc_provider_client_secret.as_deref(),
    ]
    .into_iter()
    .all(|value| value.is_some_and(|value| !value.is_empty()));

    if required_fields_are_nonempty {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_combination(
            &[
                "service_url",
                "oidc_provider_url",
                "oidc_provider_client_id",
                "oidc_provider_client_secret",
            ],
            "a replacement requires every field to be present and non-empty; leave every configurable field unset to clear the configuration",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(
            request
                .encode(GmpVersion(22, 8))
                .expect("valid integration-configuration request"),
        )
        .expect("valid UTF-8")
    }

    fn replacement_request() -> ModifyIntegrationConfigRequest {
        let mut request = ModifyIntegrationConfigRequest::new(id("ic1"));
        request.service_url = Some("https://service.example".into());
        request.service_cacert = Some("CERT".into());
        request.oidc_provider_url = Some("https://oidc.example".into());
        request.oidc_provider_client_id = Some("client-id".into());
        request.oidc_provider_client_secret = Some("client-secret".into());
        request
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetIntegrationConfigsRequest {
                filter_string: Some("name=demo".into()),
                filter_id: Some(id("f1")),
            }),
            "<get_integration_configs filt_id=\"f1\" filter=\"name=demo\"/>"
        );
        assert_eq!(
            request_xml(&GetIntegrationConfigRequest::new(id("ic1"), Some(true))),
            "<get_integration_configs details=\"1\" integration_config_id=\"ic1\"/>"
        );
        assert_eq!(
            request_xml(&replacement_request()),
            "<modify_integration_config uuid=\"ic1\"><service><url>https://service.example</url><cacert>CERT</cacert></service><oidc><url>https://oidc.example</url><client><id>client-id</id><secret>client-secret</secret></client></oidc></modify_integration_config>"
        );
        assert_eq!(
            request_xml(&ModifyIntegrationConfigRequest::new(id("ic1"))),
            "<modify_integration_config uuid=\"ic1\"><service><url></url><cacert></cacert></service><oidc><url></url><client><id></id><secret></secret></client></oidc></modify_integration_config>"
        );
    }

    #[test]
    fn modify_validation_accepts_replacement_and_clear_but_rejects_partial_values() {
        assert_eq!(replacement_request().validate(), Ok(()));
        assert_eq!(
            ModifyIntegrationConfigRequest::new(id("ic1")).validate(),
            Ok(())
        );

        let mut partial = ModifyIntegrationConfigRequest::new(id("ic1"));
        partial.service_url = Some("https://service.example".into());
        assert!(matches!(
            partial.validate(),
            Err(GmpRequestError::InvalidCombination { fields, reason })
                if fields == [
                    "service_url",
                    "oidc_provider_url",
                    "oidc_provider_client_id",
                    "oidc_provider_client_secret",
                ] && !reason.contains("https://service.example")
        ));

        let mut empty_secret = replacement_request();
        empty_secret.oidc_provider_client_secret = Some(String::new());
        assert!(matches!(
            empty_secret.validate(),
            Err(GmpRequestError::InvalidCombination { .. })
        ));
    }

    #[test]
    fn requests_expose_semantic_capability_metadata() {
        assert_eq!(
            GetIntegrationConfigsRequest::default().command(),
            Some(GmpCommand::new("get_integration_configs"))
        );
        assert_eq!(
            GetIntegrationConfigRequest::new(id("ic1"), None).command(),
            Some(GmpCommand::with_semantic_name(
                "get_integration_configs",
                "get_integration_config"
            ))
        );
        assert_eq!(
            ModifyIntegrationConfigRequest::new(id("ic1")).command(),
            Some(GmpCommand::new("modify_integration_config"))
        );
    }

    #[test]
    fn requests_remain_statically_associated_with_responses_and_redact_secrets() {
        fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

        assert_response::<_, GetIntegrationConfigsResponse>(
            &GetIntegrationConfigsRequest::default(),
        );
        assert_response::<_, GetIntegrationConfigsResponse>(&GetIntegrationConfigRequest::new(
            id("ic1"),
            None,
        ));
        let modify = replacement_request();
        assert_response::<_, ModifyIntegrationConfigResponse>(&modify);

        let debug = format!("{modify:?}");
        assert!(!debug.contains("CERT"));
        assert!(!debug.contains("client-secret"));
        assert!(debug.contains("<redacted>"));
    }
}
