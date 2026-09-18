// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for scanner operations.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{
    add_filter_attrs, add_optional_id_element, add_scalar_id_update, bool_str,
    set_optional_bool_attr,
};
use crate::enums::ScannerType;
use crate::responses::{
    CreateScannerResponse, DeleteScannerResponse, GetScannersResponse, ModifyScannerResponse,
    VerifyScannerResponse,
};
use crate::types::{EntityId, ScalarUpdate};
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing scanners.
#[derive(Debug, Clone, Default)]
pub struct GetScannersRequest {
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Whether to query trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed output.
    pub details: Option<bool>,
}

impl GmpRequestCodec for GetScannersRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_scanners"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_scanners_command(self).to_bytes())
    }
}

impl GmpRequest for GetScannersRequest {
    type Response = GetScannersResponse;
}

/// Request for one detailed scanner.
#[derive(Debug, Clone)]
pub struct GetScannerRequest {
    /// Scanner identifier to retrieve.
    pub scanner_id: EntityId,
}

impl GetScannerRequest {
    /// Create a detailed single-scanner request.
    #[must_use]
    pub fn new(scanner_id: EntityId) -> Self {
        Self { scanner_id }
    }
}

impl GmpRequestCodec for GetScannerRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_scanners",
            "get_scanner",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(get_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for GetScannerRequest {
    type Response = GetScannersResponse;
}

/// Request for creating a scanner.
#[derive(Debug, Clone)]
pub struct CreateScannerRequest {
    /// Scanner name.
    pub name: String,
    /// Optional resource comment.
    pub comment: Option<String>,
    /// Scanner hostname or IP address.
    pub host: String,
    /// Scanner service port.
    pub port: u16,
    /// Scanner protocol type.
    pub scanner_type: ScannerType,
    /// Optional CA certificate used to verify the scanner certificate.
    pub ca_pub: Option<String>,
    /// Optional client-certificate credential relationship.
    pub credential_id: Option<EntityId>,
    /// Optional relay hostname, IP address, or supported Unix-socket path.
    pub relay_host: Option<String>,
    /// Optional relay service port.
    pub relay_port: Option<u16>,
}

impl CreateScannerRequest {
    /// Create a scanner request with the values required by gvmd.
    #[must_use]
    pub fn new(
        name: impl Into<String>,
        host: impl Into<String>,
        port: u16,
        scanner_type: ScannerType,
    ) -> Self {
        Self {
            name: name.into(),
            comment: None,
            host: host.into(),
            port,
            scanner_type,
            ca_pub: None,
            credential_id: None,
            relay_host: None,
            relay_port: None,
        }
    }
}

impl GmpRequestCodec for CreateScannerRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        require_non_empty(&self.name, "name")?;
        validate_host(&self.host, "host")?;
        validate_port(self.port, "port")?;
        validate_create_relay(self.relay_host.as_deref(), self.relay_port)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("create_scanner"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(create_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for CreateScannerRequest {
    type Response = CreateScannerResponse;
}

/// Request for cloning a scanner through `create_scanner`.
#[derive(Debug, Clone)]
pub struct CloneScannerRequest {
    /// Existing scanner identifier to copy.
    pub scanner_id: EntityId,
    /// Optional name override. Omission copies the existing name.
    pub name: Option<String>,
    /// Optional comment override. Omission copies the existing comment.
    pub comment: Option<String>,
}

impl CloneScannerRequest {
    /// Create a scanner-clone request.
    #[must_use]
    pub fn new(scanner_id: EntityId) -> Self {
        Self {
            scanner_id,
            name: None,
            comment: None,
        }
    }
}

impl GmpRequestCodec for CloneScannerRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_non_empty(self.name.as_deref(), "name")
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "create_scanner",
            "clone_scanner",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(clone_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for CloneScannerRequest {
    type Response = CreateScannerResponse;
}

/// Request for modifying a scanner.
#[derive(Debug, Clone)]
pub struct ModifyScannerRequest {
    /// Scanner identifier to modify.
    pub scanner_id: EntityId,
    /// Optional replacement name.
    pub name: Option<String>,
    /// Optional replacement comment. An empty string clears the comment.
    pub comment: Option<String>,
    /// Optional replacement hostname or IP address.
    pub host: Option<String>,
    /// Optional replacement service port.
    pub port: Option<u16>,
    /// Optional replacement scanner type.
    pub scanner_type: Option<ScannerType>,
    /// Optional replacement CA certificate. An empty string restores gvmd's default.
    pub ca_pub: Option<String>,
    /// Client-certificate credential update: preserve, set, or detach.
    pub credential_id: ScalarUpdate<EntityId>,
    /// Optional relay-host update. An empty string clears the relay.
    pub relay_host: Option<String>,
    /// Optional replacement relay service port.
    pub relay_port: Option<u16>,
}

impl ModifyScannerRequest {
    /// Create a scanner-modification request with no field updates.
    #[must_use]
    pub fn new(scanner_id: EntityId) -> Self {
        Self {
            scanner_id,
            name: None,
            comment: None,
            host: None,
            port: None,
            scanner_type: None,
            ca_pub: None,
            credential_id: ScalarUpdate::Omitted,
            relay_host: None,
            relay_port: None,
        }
    }
}

impl GmpRequestCodec for ModifyScannerRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_optional_non_empty(self.name.as_deref(), "name")?;
        if let Some(host) = self.host.as_deref() {
            validate_host(host, "host")?;
        }
        if let Some(port) = self.port {
            validate_port(port, "port")?;
        }
        validate_modify_relay(self.relay_host.as_deref(), self.relay_port)
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("modify_scanner"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(modify_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for ModifyScannerRequest {
    type Response = ModifyScannerResponse;
}

/// Request for deleting a scanner.
#[derive(Debug, Clone)]
pub struct DeleteScannerRequest {
    /// Scanner identifier to delete.
    pub scanner_id: EntityId,
    /// Whether to delete permanently instead of moving to the trashcan.
    pub ultimate: bool,
}

impl DeleteScannerRequest {
    /// Create a scanner-deletion request.
    #[must_use]
    pub fn new(scanner_id: EntityId, ultimate: bool) -> Self {
        Self {
            scanner_id,
            ultimate,
        }
    }
}

impl GmpRequestCodec for DeleteScannerRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("delete_scanner"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(delete_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for DeleteScannerRequest {
    type Response = DeleteScannerResponse;
}

/// Request for verifying a scanner connection.
#[derive(Debug, Clone)]
pub struct VerifyScannerRequest {
    /// Scanner identifier to verify.
    pub scanner_id: EntityId,
}

impl VerifyScannerRequest {
    /// Create a scanner-verification request.
    #[must_use]
    pub fn new(scanner_id: EntityId) -> Self {
        Self { scanner_id }
    }
}

impl GmpRequestCodec for VerifyScannerRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("verify_scanner"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(verify_scanner_command(self).to_bytes())
    }
}

impl GmpRequest for VerifyScannerRequest {
    type Response = VerifyScannerResponse;
}

fn require_non_empty(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.is_empty() {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_optional_non_empty(
    value: Option<&str>,
    field: &'static str,
) -> Result<(), GmpRequestError> {
    if value.is_some_and(str::is_empty) {
        Err(GmpRequestError::invalid_field(field, "must not be empty"))
    } else {
        Ok(())
    }
}

fn validate_host(host: &str, field: &'static str) -> Result<(), GmpRequestError> {
    require_non_empty(host, field)?;
    if host.starts_with('/') {
        Err(GmpRequestError::invalid_field(
            field,
            "Unix socket paths are not accepted over GMP",
        ))
    } else {
        Ok(())
    }
}

fn validate_port(port: u16, field: &'static str) -> Result<(), GmpRequestError> {
    if port == 0 {
        Err(GmpRequestError::invalid_field(field, "must be non-zero"))
    } else {
        Ok(())
    }
}

fn validate_create_relay(
    relay_host: Option<&str>,
    relay_port: Option<u16>,
) -> Result<(), GmpRequestError> {
    match (relay_host, relay_port) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(GmpRequestError::invalid_field(
            "relay_port",
            "requires relay_host",
        )),
        (Some(""), _) => Err(GmpRequestError::invalid_field(
            "relay_host",
            "must not be empty on create",
        )),
        (Some(host), Some(_)) if host.starts_with('/') => Err(GmpRequestError::invalid_field(
            "relay_port",
            "must be omitted for a Unix-socket relay",
        )),
        (Some(host), None) if !host.starts_with('/') => Err(GmpRequestError::invalid_field(
            "relay_port",
            "is required for a network relay",
        )),
        (Some(_), Some(port)) => validate_port(port, "relay_port"),
        (Some(_), None) => Ok(()),
    }
}

fn validate_modify_relay(
    relay_host: Option<&str>,
    relay_port: Option<u16>,
) -> Result<(), GmpRequestError> {
    if let Some(port) = relay_port {
        validate_port(port, "relay_port")?;
    }
    if relay_host == Some("") && relay_port.is_some() {
        return Err(GmpRequestError::invalid_field(
            "relay_port",
            "must be omitted when clearing relay_host",
        ));
    }
    if relay_host.is_some_and(|host| host.starts_with('/')) && relay_port.is_some() {
        return Err(GmpRequestError::invalid_field(
            "relay_port",
            "must be omitted for a Unix-socket relay",
        ));
    }
    Ok(())
}

fn add_optional_text_element(command: &mut XmlCommand, name: &str, value: Option<&str>) {
    if let Some(value) = value {
        command.add_element_with_text(name, value);
    }
}

fn get_scanners_command(request: &GetScannersRequest) -> XmlCommand {
    let mut command = XmlCommand::new("get_scanners");
    add_filter_attrs(
        &mut command,
        request.filter_string.as_deref(),
        request.filter_id.as_ref(),
    );
    set_optional_bool_attr(&mut command, "trash", request.trash);
    set_optional_bool_attr(&mut command, "details", request.details);
    command
}

fn get_scanner_command(request: &GetScannerRequest) -> XmlCommand {
    XmlCommand::new("get_scanners")
        .attribute("scanner_id", request.scanner_id.as_str())
        .attribute("details", "1")
}

fn create_scanner_command(request: &CreateScannerRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_scanner");
    command.add_element_with_text("name", &request.name);
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("host", &request.host);
    command.add_element_with_text("port", &request.port.to_string());
    command.add_element_with_text("type", request.scanner_type.as_scanner_type());
    add_optional_text_element(&mut command, "ca_pub", request.ca_pub.as_deref());
    add_optional_id_element(&mut command, "credential", request.credential_id.as_ref());
    add_optional_text_element(&mut command, "relay_host", request.relay_host.as_deref());
    if let Some(port) = request.relay_port {
        command.add_element_with_text("relay_port", &port.to_string());
    }
    command
}

fn clone_scanner_command(request: &CloneScannerRequest) -> XmlCommand {
    let mut command = XmlCommand::new("create_scanner");
    add_optional_text_element(&mut command, "name", request.name.as_deref());
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    command.add_element_with_text("copy", request.scanner_id.as_str());
    command
}

fn modify_scanner_command(request: &ModifyScannerRequest) -> XmlCommand {
    let mut command =
        XmlCommand::new("modify_scanner").attribute("scanner_id", request.scanner_id.as_str());
    add_optional_text_element(&mut command, "name", request.name.as_deref());
    add_optional_text_element(&mut command, "comment", request.comment.as_deref());
    add_optional_text_element(&mut command, "host", request.host.as_deref());
    if let Some(port) = request.port {
        command.add_element_with_text("port", &port.to_string());
    }
    if let Some(scanner_type) = request.scanner_type {
        command.add_element_with_text("type", scanner_type.as_scanner_type());
    }
    add_optional_text_element(&mut command, "ca_pub", request.ca_pub.as_deref());
    add_scalar_id_update(&mut command, "credential", &request.credential_id);
    add_optional_text_element(&mut command, "relay_host", request.relay_host.as_deref());
    if let Some(port) = request.relay_port {
        command.add_element_with_text("relay_port", &port.to_string());
    }
    command
}

fn delete_scanner_command(request: &DeleteScannerRequest) -> XmlCommand {
    XmlCommand::new("delete_scanner")
        .attribute("scanner_id", request.scanner_id.as_str())
        .attribute("ultimate", bool_str(request.ultimate))
}

fn verify_scanner_command(request: &VerifyScannerRequest) -> XmlCommand {
    XmlCommand::new("verify_scanner").attribute("scanner_id", request.scanner_id.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::GmpResponse;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn request_xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 8)).expect("valid request"))
            .expect("valid UTF-8")
    }

    fn create_request() -> CreateScannerRequest {
        CreateScannerRequest::new(
            "scanner",
            "scanner.example",
            9390,
            ScannerType::OpenVasScanner,
        )
    }

    #[test]
    fn requests_have_independent_exact_wire_shapes() {
        assert_eq!(
            request_xml(&GetScannersRequest {
                filter_string: Some("name=scanner".into()),
                filter_id: Some(id("filter-1")),
                trash: Some(false),
                details: Some(true),
            }),
            "<get_scanners details=\"1\" filt_id=\"filter-1\" filter=\"name=scanner\" trash=\"0\"/>"
        );
        assert_eq!(
            request_xml(&GetScannerRequest::new(id("scanner-1"))),
            "<get_scanners details=\"1\" scanner_id=\"scanner-1\"/>"
        );

        let mut create = create_request();
        create.comment = Some("comment".into());
        create.ca_pub = Some("CA certificate".into());
        create.credential_id = Some(id("credential-1"));
        create.relay_host = Some("relay.example".into());
        create.relay_port = Some(9391);
        assert_eq!(
            request_xml(&create),
            "<create_scanner><name>scanner</name><comment>comment</comment><host>scanner.example</host><port>9390</port><type>2</type><ca_pub>CA certificate</ca_pub><credential id=\"credential-1\"/><relay_host>relay.example</relay_host><relay_port>9391</relay_port></create_scanner>"
        );

        let mut clone = CloneScannerRequest::new(id("scanner-1"));
        clone.name = Some("copy".into());
        clone.comment = Some(String::new());
        assert_eq!(
            request_xml(&clone),
            "<create_scanner><name>copy</name><comment></comment><copy>scanner-1</copy></create_scanner>"
        );

        let mut modify = ModifyScannerRequest::new(id("scanner-1"));
        modify.name = Some("renamed".into());
        modify.comment = Some(String::new());
        modify.host = Some("127.0.0.1".into());
        modify.port = Some(9392);
        modify.scanner_type = Some(ScannerType::GreenBoneSensorType);
        modify.ca_pub = Some(String::new());
        modify.credential_id = ScalarUpdate::Clear;
        modify.relay_host = Some(String::new());
        assert_eq!(
            request_xml(&modify),
            "<modify_scanner scanner_id=\"scanner-1\"><name>renamed</name><comment></comment><host>127.0.0.1</host><port>9392</port><type>5</type><ca_pub></ca_pub><credential id=\"0\"/><relay_host></relay_host></modify_scanner>"
        );

        assert_eq!(
            request_xml(&DeleteScannerRequest::new(id("scanner-1"), true)),
            "<delete_scanner scanner_id=\"scanner-1\" ultimate=\"1\"/>"
        );
        assert_eq!(
            request_xml(&VerifyScannerRequest::new(id("scanner-1"))),
            "<verify_scanner scanner_id=\"scanner-1\"/>"
        );
    }

    #[test]
    fn invalid_final_values_are_rejected() {
        let mut create = create_request();
        create.name.clear();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));

        let mut create = create_request();
        create.host = "/run/scanner.sock".into();
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "host", .. })
        ));

        let mut create = create_request();
        create.port = 0;
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField { field: "port", .. })
        ));

        let mut create = create_request();
        create.relay_host = Some("relay.example".into());
        assert!(matches!(
            create.validate(),
            Err(GmpRequestError::InvalidField {
                field: "relay_port",
                ..
            })
        ));

        let mut modify = ModifyScannerRequest::new(id("scanner-1"));
        modify.relay_host = Some(String::new());
        modify.relay_port = Some(9391);
        assert!(matches!(
            modify.validate(),
            Err(GmpRequestError::InvalidField {
                field: "relay_port",
                ..
            })
        ));
    }

    #[test]
    fn requests_keep_static_response_associations() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: GmpResponse,
        {
        }

        associated::<_, GetScannersResponse>(&GetScannersRequest::default());
        associated::<_, GetScannersResponse>(&GetScannerRequest::new(id("scanner-1")));
        associated::<_, CreateScannerResponse>(&create_request());
        associated::<_, CreateScannerResponse>(&CloneScannerRequest::new(id("scanner-1")));
        associated::<_, ModifyScannerResponse>(&ModifyScannerRequest::new(id("scanner-1")));
        associated::<_, DeleteScannerResponse>(&DeleteScannerRequest::new(id("scanner-1"), false));
        associated::<_, VerifyScannerResponse>(&VerifyScannerRequest::new(id("scanner-1")));
    }

    #[test]
    fn semantic_aliases_keep_wire_and_capability_names() {
        let detail = GetScannerRequest::new(id("scanner-1"));
        let detail_command = detail.command().expect("typed command");
        assert_eq!(detail_command.wire_name(), "get_scanners");
        assert_eq!(detail_command.semantic_name(), Some("get_scanner"));

        let clone = CloneScannerRequest::new(id("scanner-1"));
        let clone_command = clone.command().expect("typed command");
        assert_eq!(clone_command.wire_name(), "create_scanner");
        assert_eq!(clone_command.semantic_name(), Some("clone_scanner"));
    }
}
