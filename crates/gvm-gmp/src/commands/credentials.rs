// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for credential and credential-store operations.

use std::fmt;

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, add_text_element, bool_str, set_optional_bool_attr};
use crate::enums::{
    CredentialFormat, CredentialStoreCredentialType, CredentialType, SnmpAuthAlgorithm,
    SnmpPrivacyAlgorithm,
};
use crate::responses::{
    CreateCredentialResponse, DeleteCredentialResponse, GetCredentialStoresResponse,
    GetCredentialsResponse, ModifyCredentialResponse, ModifyCredentialStoreResponse,
    VerifyCredentialStoreResponse,
};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

fn redacted(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<redacted>")
}

fn present(value: &Option<String>) -> Option<&'static str> {
    value.as_ref().map(|_| "<present>")
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn require_present(value: &Option<String>, field: &'static str) -> Result<(), GmpRequestError> {
    match value {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(GmpRequestError::invalid_field(
            field,
            "is required for the selected credential type",
        )),
    }
}

/// Semantic request for listing credentials.
#[derive(Debug, Clone, Default)]
pub struct GetCredentialsRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetCredentialsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_credentials"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_credentials_command(self).to_bytes())
    }
}

impl GmpRequest for GetCredentialsRequest {
    type Response = GetCredentialsResponse;
}

/// Semantic request for one detailed credential.
#[derive(Debug, Clone)]
pub struct GetCredentialRequest {
    /// Credential identifier to retrieve.
    pub credential_id: EntityId,
}

impl GetCredentialRequest {
    /// Create a detailed single-credential request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self { credential_id }
    }
}

impl GmpRequestCodec for GetCredentialRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_credentials",
            "get_credential",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_credential_command(&self.credential_id).to_bytes())
    }
}

impl GmpRequest for GetCredentialRequest {
    type Response = GetCredentialsResponse;
}

/// Semantic request for creating a credential.
#[derive(Clone, Default)]
pub struct CreateCredentialRequest {
    /// Resource name.
    pub name: String,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional explicit credential type.
    pub credential_type: Option<CredentialType>,
    /// Optional login or username value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
    /// Optional private-key passphrase.
    pub key_phrase: Option<String>,
    /// Optional public key material.
    pub public_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community value.
    pub community: Option<String>,
    /// Optional SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Whether the credential may be used over an insecure transport.
    pub allow_insecure: Option<bool>,
    /// Deprecated comma-separated Kerberos KDC value.
    pub kdc: Option<String>,
    /// Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional Kerberos realm.
    pub realm: Option<String>,
    /// Historical format field ignored by current gvmd.
    #[deprecated(note = "current gvmd ignores credential request format")]
    pub format: Option<CredentialFormat>,
}

impl CreateCredentialRequest {
    /// Create a credential creation request.
    #[must_use]
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ..Self::default()
        }
    }
}

#[allow(deprecated)]
impl fmt::Debug for CreateCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateCredentialRequest")
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("credential_type", &self.credential_type)
            .field("login", &self.login)
            .field("password", &redacted(&self.password))
            .field("private_key", &redacted(&self.private_key))
            .field("key_phrase", &redacted(&self.key_phrase))
            .field("public_key", &present(&self.public_key))
            .field("certificate", &present(&self.certificate))
            .field("community", &redacted(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_password", &redacted(&self.privacy_password))
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("allow_insecure", &self.allow_insecure)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .field("format", &"<ignored>")
            .finish()
    }
}

impl GmpRequestCodec for CreateCredentialRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_create_credential(self)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_credential"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_credential_command(self).to_bytes())
    }
}

impl GmpRequest for CreateCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for cloning a credential.
#[derive(Debug, Clone)]
pub struct CloneCredentialRequest {
    /// Existing credential identifier to copy.
    pub credential_id: EntityId,
}

impl CloneCredentialRequest {
    /// Create a credential clone request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self { credential_id }
    }
}

impl GmpRequestCodec for CloneCredentialRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_credential",
            "clone_credential",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(clone_credential_command(&self.credential_id).to_bytes())
    }
}

impl GmpRequest for CloneCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for modifying a credential.
#[derive(Clone)]
pub struct ModifyCredentialRequest {
    /// Credential identifier to modify.
    pub credential_id: EntityId,
    /// Optional replacement credential name.
    pub name: Option<String>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional login or username value.
    pub login: Option<String>,
    /// Optional password value.
    pub password: Option<String>,
    /// Optional private key material.
    pub private_key: Option<String>,
    /// Optional private-key passphrase.
    pub key_phrase: Option<String>,
    /// Optional public key material.
    pub public_key: Option<String>,
    /// Optional certificate data.
    pub certificate: Option<String>,
    /// Optional SNMP community value.
    pub community: Option<String>,
    /// Optional SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy password.
    pub privacy_password: Option<String>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Whether the credential may be used over an insecure transport.
    pub allow_insecure: Option<bool>,
    /// Deprecated comma-separated Kerberos KDC value.
    pub kdc: Option<String>,
    /// Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional Kerberos realm.
    pub realm: Option<String>,
}

impl ModifyCredentialRequest {
    /// Create a credential modification request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self {
            credential_id,
            name: None,
            comment: None,
            login: None,
            password: None,
            private_key: None,
            key_phrase: None,
            public_key: None,
            certificate: None,
            community: None,
            auth_algorithm: None,
            privacy_password: None,
            privacy_algorithm: None,
            allow_insecure: None,
            kdc: None,
            kdcs: Vec::new(),
            realm: None,
        }
    }
}

impl fmt::Debug for ModifyCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModifyCredentialRequest")
            .field("credential_id", &self.credential_id)
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("login", &self.login)
            .field("password", &redacted(&self.password))
            .field("private_key", &redacted(&self.private_key))
            .field("key_phrase", &redacted(&self.key_phrase))
            .field("public_key", &present(&self.public_key))
            .field("certificate", &present(&self.certificate))
            .field("community", &redacted(&self.community))
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_password", &redacted(&self.privacy_password))
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("allow_insecure", &self.allow_insecure)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .finish()
    }
}

impl GmpRequestCodec for ModifyCredentialRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if matches!(self.login.as_deref(), Some("")) {
            return Err(GmpRequestError::invalid_field("login", "must not be empty"));
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_credential"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_credential_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyCredentialRequest {
    type Response = ModifyCredentialResponse;
}

/// Semantic request for deleting a credential.
#[derive(Debug, Clone)]
pub struct DeleteCredentialRequest {
    /// Credential identifier to delete.
    pub credential_id: EntityId,
    /// Whether to delete permanently instead of moving to trash.
    pub ultimate: bool,
}

impl DeleteCredentialRequest {
    /// Create a credential deletion request.
    #[must_use]
    pub fn new(credential_id: EntityId, ultimate: bool) -> Self {
        Self {
            credential_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteCredentialRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_credential"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_credential_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteCredentialRequest {
    type Response = DeleteCredentialResponse;
}

/// Semantic request for listing or filtering credential stores.
#[derive(Debug, Clone, Default)]
pub struct GetCredentialStoresRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetCredentialStoresRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_credential_stores"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_credential_stores_command(self).to_bytes())
    }
}

impl GmpRequest for GetCredentialStoresRequest {
    type Response = GetCredentialStoresResponse;
}

/// Semantic request for one credential store.
#[derive(Debug, Clone)]
pub struct GetCredentialStoreRequest {
    /// Credential-store identifier to retrieve.
    pub credential_store_id: EntityId,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GetCredentialStoreRequest {
    /// Create a single credential-store request.
    #[must_use]
    pub fn new(credential_store_id: EntityId) -> Self {
        Self {
            credential_store_id,
            details: None,
        }
    }
}

impl GmpRequestCodec for GetCredentialStoreRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_credential_stores",
            "get_credential_store",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_credential_store_command(self).to_bytes())
    }
}

impl GmpRequest for GetCredentialStoreRequest {
    type Response = GetCredentialStoresResponse;
}

/// Semantic request for verifying a credential store.
#[derive(Debug, Clone)]
pub struct VerifyCredentialStoreRequest {
    /// Credential-store identifier to verify.
    pub credential_store_id: EntityId,
}

impl VerifyCredentialStoreRequest {
    /// Create a credential-store verification request.
    #[must_use]
    pub fn new(credential_store_id: EntityId) -> Self {
        Self {
            credential_store_id,
        }
    }
}

impl GmpRequestCodec for VerifyCredentialStoreRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("verify_credential_store"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(verify_credential_store_command(&self.credential_store_id).to_bytes())
    }
}

impl GmpRequest for VerifyCredentialStoreRequest {
    type Response = VerifyCredentialStoreResponse;
}

/// A credential-store preference update with redacted value formatting.
#[derive(Clone, Default)]
pub struct CredentialStorePreference {
    /// Preference name.
    pub name: String,
    /// Preference value.
    pub value: String,
}

impl fmt::Debug for CredentialStorePreference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CredentialStorePreference")
            .field("name", &self.name)
            .field("value", &"<redacted>")
            .finish()
    }
}

/// Semantic request for modifying a credential store.
#[derive(Clone)]
pub struct ModifyCredentialStoreRequest {
    /// Credential-store identifier to modify.
    pub credential_store_id: EntityId,
    /// Whether the credential store is active.
    pub active: Option<bool>,
    /// Credential-store host.
    pub host: Option<String>,
    /// Credential-store path.
    pub path: Option<String>,
    /// Credential-store port.
    pub port: Option<u16>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Preference values to update.
    pub preferences: Vec<CredentialStorePreference>,
}

impl ModifyCredentialStoreRequest {
    /// Create a credential-store modification request.
    #[must_use]
    pub fn new(credential_store_id: EntityId) -> Self {
        Self {
            credential_store_id,
            active: None,
            host: None,
            path: None,
            port: None,
            comment: None,
            preferences: Vec::new(),
        }
    }
}

impl fmt::Debug for ModifyCredentialStoreRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModifyCredentialStoreRequest")
            .field("credential_store_id", &self.credential_store_id)
            .field("active", &self.active)
            .field("host", &redacted(&self.host))
            .field("path", &redacted(&self.path))
            .field("port", &self.port)
            .field("comment", &self.comment)
            .field("preferences", &self.preferences)
            .finish()
    }
}

impl GmpRequestCodec for ModifyCredentialStoreRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        for preference in &self.preferences {
            require_non_empty(&preference.name, "preference.name")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_credential_store"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_credential_store_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyCredentialStoreRequest {
    type Response = ModifyCredentialStoreResponse;
}

/// Semantic request for creating a credential-store-backed credential.
#[derive(Clone)]
pub struct CreateCredentialStoreCredentialRequest {
    /// Resource name.
    pub name: String,
    /// Credential-store-backed credential type.
    pub credential_type: CredentialStoreCredentialType,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional credential-store identifier.
    pub credential_store_id: Option<EntityId>,
    /// Deprecated comma-separated Kerberos KDC value.
    pub kdc: Option<String>,
    /// Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional Kerberos realm.
    pub realm: Option<String>,
    /// SNMP authentication algorithm, required for stored SNMP credentials.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Credential-store vault identifier.
    pub vault_id: String,
    /// Credential-store host/item identifier.
    pub host_identifier: String,
    /// Optional credential-store host/item identifier for the SNMP privacy secret.
    pub privacy_host_identifier: Option<String>,
}

impl CreateCredentialStoreCredentialRequest {
    /// Create a credential-store-backed credential request.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        credential_type: CredentialStoreCredentialType,
        vault_id: impl Into<String>,
        host_identifier: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            credential_type,
            comment: None,
            credential_store_id: None,
            kdc: None,
            kdcs: Vec::new(),
            realm: None,
            auth_algorithm: None,
            privacy_algorithm: None,
            vault_id: vault_id.into(),
            host_identifier: host_identifier.into(),
            privacy_host_identifier: None,
        }
    }
}

impl fmt::Debug for CreateCredentialStoreCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CreateCredentialStoreCredentialRequest")
            .field("name", &self.name)
            .field("credential_type", &self.credential_type)
            .field("comment", &self.comment)
            .field("credential_store_id", &self.credential_store_id)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("vault_id", &"<redacted>")
            .field("host_identifier", &"<redacted>")
            .field(
                "privacy_host_identifier",
                &redacted(&self.privacy_host_identifier),
            )
            .finish()
    }
}

impl GmpRequestCodec for CreateCredentialStoreCredentialRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        require_non_empty(&self.vault_id, "vault_id")?;
        require_non_empty(&self.host_identifier, "host_identifier")?;
        if self.credential_type == CredentialStoreCredentialType::Kerberos5 {
            if self
                .kdc
                .as_deref()
                .filter(|value| !value.is_empty())
                .is_none()
                && !self.kdcs.iter().any(|value| !value.is_empty())
            {
                return Err(GmpRequestError::invalid_combination(
                    &["kdc", "kdcs"],
                    "a Kerberos credential requires at least one key distribution center",
                ));
            }
            require_present(&self.realm, "realm")?;
        }
        if self.credential_type == CredentialStoreCredentialType::Snmp
            && self.auth_algorithm.is_none()
        {
            return Err(GmpRequestError::invalid_field(
                "auth_algorithm",
                "is required for the selected credential type",
            ));
        }
        if self
            .privacy_host_identifier
            .as_deref()
            .is_some_and(|value| !value.is_empty())
            && self.privacy_algorithm.is_none()
        {
            return Err(GmpRequestError::invalid_combination(
                &["privacy_host_identifier", "privacy_algorithm"],
                "an SNMP privacy host identifier requires a privacy algorithm",
            ));
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_credential",
            "create_credential_store_credential",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_credential_store_credential_command(self).to_bytes())
    }
}

impl GmpRequest for CreateCredentialStoreCredentialRequest {
    type Response = CreateCredentialResponse;
}

/// Semantic request for modifying a credential-store-backed credential.
#[derive(Clone)]
pub struct ModifyCredentialStoreCredentialRequest {
    /// Credential identifier to modify.
    pub credential_id: EntityId,
    /// Optional credential name.
    pub name: Option<String>,
    /// Optional comment text.
    pub comment: Option<String>,
    /// Optional credential-store identifier.
    pub credential_store_id: Option<EntityId>,
    /// Optional replacement comma-separated Kerberos KDC value.
    pub kdc: Option<String>,
    /// Replacement Kerberos key distribution centers.
    pub kdcs: Vec<String>,
    /// Optional replacement Kerberos realm.
    pub realm: Option<String>,
    /// Optional replacement SNMP authentication algorithm.
    pub auth_algorithm: Option<SnmpAuthAlgorithm>,
    /// Optional replacement SNMP privacy algorithm.
    pub privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    /// Optional replacement vault identifier.
    pub vault_id: Option<String>,
    /// Optional replacement host/item identifier.
    pub host_identifier: Option<String>,
    /// Optional replacement credential-store identifier for the SNMP privacy secret.
    pub privacy_host_identifier: Option<String>,
}

impl ModifyCredentialStoreCredentialRequest {
    /// Create a credential-store-backed credential modification request.
    #[must_use]
    pub fn new(credential_id: EntityId) -> Self {
        Self {
            credential_id,
            name: None,
            comment: None,
            credential_store_id: None,
            kdc: None,
            kdcs: Vec::new(),
            realm: None,
            auth_algorithm: None,
            privacy_algorithm: None,
            vault_id: None,
            host_identifier: None,
            privacy_host_identifier: None,
        }
    }
}

impl fmt::Debug for ModifyCredentialStoreCredentialRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ModifyCredentialStoreCredentialRequest")
            .field("credential_id", &self.credential_id)
            .field("name", &self.name)
            .field("comment", &self.comment)
            .field("credential_store_id", &self.credential_store_id)
            .field("kdc", &self.kdc)
            .field("kdcs", &self.kdcs)
            .field("realm", &self.realm)
            .field("auth_algorithm", &self.auth_algorithm)
            .field("privacy_algorithm", &self.privacy_algorithm)
            .field("vault_id", &redacted(&self.vault_id))
            .field("host_identifier", &redacted(&self.host_identifier))
            .field(
                "privacy_host_identifier",
                &redacted(&self.privacy_host_identifier),
            )
            .finish()
    }
}

impl GmpRequestCodec for ModifyCredentialStoreCredentialRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        if let Some(vault_id) = &self.vault_id {
            require_non_empty(vault_id, "vault_id")?;
        }
        if let Some(host_identifier) = &self.host_identifier {
            require_non_empty(host_identifier, "host_identifier")?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "modify_credential",
            "modify_credential_store_credential",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_credential_store_credential_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyCredentialStoreCredentialRequest {
    type Response = ModifyCredentialResponse;
}

#[allow(deprecated)]
fn validate_create_credential(request: &CreateCredentialRequest) -> Result<(), GmpRequestError> {
    require_non_empty(&request.name, "name")?;
    if matches!(request.login.as_deref(), Some("")) {
        return Err(GmpRequestError::invalid_field("login", "must not be empty"));
    }
    if request.key_phrase.is_some()
        && request
            .private_key
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none()
        && request
            .public_key
            .as_deref()
            .filter(|value| !value.is_empty())
            .is_none()
    {
        return Err(GmpRequestError::invalid_combination(
            &["key_phrase", "private_key", "public_key"],
            "a key passphrase requires private or public key material",
        ));
    }
    if request
        .privacy_password
        .as_deref()
        .is_some_and(|value| !value.is_empty())
        && request.privacy_algorithm.is_none()
    {
        return Err(GmpRequestError::invalid_combination(
            &["privacy_password", "privacy_algorithm"],
            "an SNMP privacy password requires a privacy algorithm",
        ));
    }

    match request.credential_type {
        Some(CredentialType::ClientCertificate) => {
            require_present(&request.private_key, "private_key")?;
            require_present(&request.certificate, "certificate")?;
        }
        Some(CredentialType::Kerberos5) => {
            require_present(&request.login, "login")?;
            require_present(&request.password, "password")?;
            if request
                .kdc
                .as_deref()
                .filter(|value| !value.is_empty())
                .is_none()
                && request.kdcs.is_empty()
            {
                return Err(GmpRequestError::invalid_combination(
                    &["kdc", "kdcs"],
                    "a Kerberos credential requires at least one key distribution center",
                ));
            }
            require_present(&request.realm, "realm")?;
        }
        // gvmd autogenerates passwords for explicit `pw` credentials.
        Some(CredentialType::PasswordOnly) => {}
        Some(CredentialType::PgpEncryptionKey) => {
            require_present(&request.public_key, "public_key")?;
        }
        Some(CredentialType::SmimeCertificate) => {
            require_present(&request.certificate, "certificate")?;
        }
        Some(CredentialType::SnmpV1Or2c) => require_present(&request.community, "community")?,
        Some(CredentialType::SnmpV3) => {
            require_present(&request.login, "login")?;
            require_present(&request.password, "password")?;
            if request.auth_algorithm.is_none() {
                return Err(GmpRequestError::invalid_field(
                    "auth_algorithm",
                    "is required for the selected credential type",
                ));
            }
        }
        // gvmd requires the username but can autogenerate the password.
        Some(CredentialType::UsernamePassword) => require_present(&request.login, "login")?,
        Some(CredentialType::UsernameSshKey) => require_present(&request.login, "login")?,
        None => {}
    }
    Ok(())
}

fn get_credentials_command(request: &GetCredentialsRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_credentials");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "trash", request.trash);
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_credential_command(credential_id: &EntityId) -> XmlCommand {
    XmlCommand::new("get_credentials")
        .attribute("credential_id", credential_id.as_str())
        .attribute("details", "1")
}

fn create_credential_command(request: &CreateCredentialRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_credential");
    cmd.add_element_with_text("name", &request.name);
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(credential_type) = request.credential_type {
        cmd.add_element_with_text("type", credential_type.as_gmp_str());
    }
    add_credential_values(&mut cmd, CredentialValues::from(request));
    cmd
}

fn clone_credential_command(credential_id: &EntityId) -> XmlCommand {
    XmlCommand::new("create_credential").child_with_text("copy", credential_id.as_str())
}

fn modify_credential_command(request: &ModifyCredentialRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_credential")
        .attribute("credential_id", request.credential_id.as_str());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    add_credential_values(&mut cmd, CredentialValues::from(request));
    cmd
}

fn delete_credential_command(request: &DeleteCredentialRequest) -> XmlCommand {
    XmlCommand::new("delete_credential")
        .attribute("credential_id", request.credential_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn get_credential_stores_command(request: &GetCredentialStoresRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_credential_stores");
    add_filter_attrs(
        &mut cmd,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn get_credential_store_command(request: &GetCredentialStoreRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("get_credential_stores");
    cmd.set_attribute("credential_store_id", request.credential_store_id.as_str());
    set_optional_bool_attr(&mut cmd, "details", request.details);
    cmd
}

fn verify_credential_store_command(credential_store_id: &EntityId) -> XmlCommand {
    XmlCommand::new("verify_credential_store")
        .attribute("credential_store_id", credential_store_id.as_str())
}

fn modify_credential_store_command(request: &ModifyCredentialStoreRequest) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_credential_store")
        .attribute("credential_store_id", request.credential_store_id.as_str());
    if let Some(active) = request.active {
        cmd.add_element_with_text("active", bool_str(active));
    }
    add_text_element(&mut cmd, "host", request.host.as_deref());
    add_text_element(&mut cmd, "path", request.path.as_deref());
    if let Some(port) = request.port {
        cmd.add_element_with_text("port", &port.to_string());
    }
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if !request.preferences.is_empty() {
        let preferences = cmd.add_element("preferences");
        for preference in &request.preferences {
            let preference_element = preferences.add_child("preference");
            preference_element.add_child_with_text("name", &preference.name);
            preference_element.add_child_with_text("value", &preference.value);
        }
    }
    cmd
}

fn create_credential_store_credential_command(
    request: &CreateCredentialStoreCredentialRequest,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("create_credential");
    cmd.add_element_with_text("name", &request.name);
    cmd.add_element_with_text("type", request.credential_type.as_gmp_str());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(credential_store_id) = &request.credential_store_id {
        cmd.add_element_with_text("credential_store_id", credential_store_id.as_str());
    }
    add_kerberos_values(
        &mut cmd,
        request.kdc.as_deref(),
        &request.kdcs,
        request.realm.as_deref(),
    );
    if let Some(auth_algorithm) = request.auth_algorithm {
        cmd.add_element_with_text("auth_algorithm", auth_algorithm.as_gmp_str());
    }
    if let Some(privacy_algorithm) = request.privacy_algorithm {
        let privacy = cmd.add_element("privacy");
        privacy.add_child_with_text("algorithm", privacy_algorithm.as_gmp_str());
    }
    cmd.add_element_with_text("vault_id", &request.vault_id);
    cmd.add_element_with_text("host_identifier", &request.host_identifier);
    add_text_element(
        &mut cmd,
        "privacy_host_identifier",
        request.privacy_host_identifier.as_deref(),
    );
    cmd
}

fn modify_credential_store_credential_command(
    request: &ModifyCredentialStoreCredentialRequest,
) -> XmlCommand {
    let mut cmd = XmlCommand::new("modify_credential")
        .attribute("credential_id", request.credential_id.as_str());
    add_text_element(&mut cmd, "name", request.name.as_deref());
    add_text_element(&mut cmd, "comment", request.comment.as_deref());
    if let Some(credential_store_id) = &request.credential_store_id {
        cmd.add_element_with_text("credential_store_id", credential_store_id.as_str());
    }
    add_kerberos_values(
        &mut cmd,
        request.kdc.as_deref(),
        &request.kdcs,
        request.realm.as_deref(),
    );
    if let Some(auth_algorithm) = request.auth_algorithm {
        cmd.add_element_with_text("auth_algorithm", auth_algorithm.as_gmp_str());
    }
    if let Some(privacy_algorithm) = request.privacy_algorithm {
        let privacy = cmd.add_element("privacy");
        privacy.add_child_with_text("algorithm", privacy_algorithm.as_gmp_str());
    }
    add_text_element(&mut cmd, "vault_id", request.vault_id.as_deref());
    add_text_element(
        &mut cmd,
        "host_identifier",
        request.host_identifier.as_deref(),
    );
    add_text_element(
        &mut cmd,
        "privacy_host_identifier",
        request.privacy_host_identifier.as_deref(),
    );
    cmd
}

struct CredentialValues<'a> {
    login: Option<&'a str>,
    password: Option<&'a str>,
    private_key: Option<&'a str>,
    key_phrase: Option<&'a str>,
    public_key: Option<&'a str>,
    certificate: Option<&'a str>,
    community: Option<&'a str>,
    auth_algorithm: Option<SnmpAuthAlgorithm>,
    privacy_password: Option<&'a str>,
    privacy_algorithm: Option<SnmpPrivacyAlgorithm>,
    allow_insecure: Option<bool>,
    kdc: Option<&'a str>,
    kdcs: &'a [String],
    realm: Option<&'a str>,
}

impl<'a> From<&'a CreateCredentialRequest> for CredentialValues<'a> {
    fn from(request: &'a CreateCredentialRequest) -> Self {
        Self {
            login: request.login.as_deref(),
            password: request.password.as_deref(),
            private_key: request.private_key.as_deref(),
            key_phrase: request.key_phrase.as_deref(),
            public_key: request.public_key.as_deref(),
            certificate: request.certificate.as_deref(),
            community: request.community.as_deref(),
            auth_algorithm: request.auth_algorithm,
            privacy_password: request.privacy_password.as_deref(),
            privacy_algorithm: request.privacy_algorithm,
            allow_insecure: request.allow_insecure,
            kdc: request.kdc.as_deref(),
            kdcs: &request.kdcs,
            realm: request.realm.as_deref(),
        }
    }
}

impl<'a> From<&'a ModifyCredentialRequest> for CredentialValues<'a> {
    fn from(request: &'a ModifyCredentialRequest) -> Self {
        Self {
            login: request.login.as_deref(),
            password: request.password.as_deref(),
            private_key: request.private_key.as_deref(),
            key_phrase: request.key_phrase.as_deref(),
            public_key: request.public_key.as_deref(),
            certificate: request.certificate.as_deref(),
            community: request.community.as_deref(),
            auth_algorithm: request.auth_algorithm,
            privacy_password: request.privacy_password.as_deref(),
            privacy_algorithm: request.privacy_algorithm,
            allow_insecure: request.allow_insecure,
            kdc: request.kdc.as_deref(),
            kdcs: &request.kdcs,
            realm: request.realm.as_deref(),
        }
    }
}

fn add_credential_values(cmd: &mut XmlCommand, values: CredentialValues<'_>) {
    if let Some(allow_insecure) = values.allow_insecure {
        cmd.add_element_with_text("allow_insecure", bool_str(allow_insecure));
    }
    add_text_element(cmd, "certificate", values.certificate);
    add_text_element(cmd, "kdc", values.kdc);
    if !values.kdcs.is_empty() {
        let kdcs = cmd.add_element("kdcs");
        for kdc in values.kdcs {
            kdcs.add_child_with_text("kdc", kdc);
        }
    }
    if values.private_key.is_some() || values.key_phrase.is_some() || values.public_key.is_some() {
        let key = cmd.add_element("key");
        if let Some(phrase) = values.key_phrase {
            key.add_child_with_text("phrase", phrase);
        }
        if let Some(private_key) = values.private_key {
            key.add_child_with_text("private", private_key);
        }
        if let Some(public_key) = values.public_key {
            key.add_child_with_text("public", public_key);
        }
    }
    add_text_element(cmd, "login", values.login);
    add_text_element(cmd, "password", values.password);
    if let Some(auth_algorithm) = values.auth_algorithm {
        cmd.add_element_with_text("auth_algorithm", auth_algorithm.as_gmp_str());
    }
    add_text_element(cmd, "community", values.community);
    if values.privacy_algorithm.is_some() || values.privacy_password.is_some() {
        let privacy = cmd.add_element("privacy");
        if let Some(privacy_algorithm) = values.privacy_algorithm {
            privacy.add_child_with_text("algorithm", privacy_algorithm.as_gmp_str());
        }
        if let Some(privacy_password) = values.privacy_password {
            privacy.add_child_with_text("password", privacy_password);
        }
    }
    add_text_element(cmd, "realm", values.realm);
}

fn add_kerberos_values(
    cmd: &mut XmlCommand,
    kdc: Option<&str>,
    kdcs: &[String],
    realm: Option<&str>,
) {
    add_text_element(cmd, "kdc", kdc);
    if !kdcs.is_empty() {
        let kdcs_element = cmd.add_element("kdcs");
        for kdc in kdcs {
            kdcs_element.add_child_with_text("kdc", kdc);
        }
    }
    add_text_element(cmd, "realm", realm);
}
