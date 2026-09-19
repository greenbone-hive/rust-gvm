// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful semantics for TLS-certificate lifecycle commands.

use base64::Engine as _;
use quick_xml::events::{BytesRef, Event};
use quick_xml::{Reader, XmlVersion};
use uuid::Uuid;

use crate::command_parser::{ParsedCommand, ParsedElement};
use crate::response_gen::error_response;
use crate::store::{Resource, ResourceStore, StoreError};
use crate::util::{now_iso, xml_escape, xml_escape_attr};

const CERT_A_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nMOCK-A\n-----END CERTIFICATE-----\n";
const CERT_A_DER: &[u8] = b"\x30\x82MOCK-A-DER\0\xff";
const CERT_B_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\r\nMOCK-B\r\n-----END CERTIFICATE-----\r\n";
const INVALID_CERTIFICATE: &[u8] = b"mock-invalid-certificate";

#[derive(Clone, Copy)]
struct CertificateFixture {
    sha256: &'static str,
    md5: &'static str,
    subject: &'static str,
    issuer: &'static str,
    activates: &'static str,
    expires: &'static str,
    serial: &'static str,
    format: &'static str,
    valid: bool,
}

const CERT_A_PEM_FIXTURE: CertificateFixture = CertificateFixture {
    sha256: "AA:AA:AA:AA:AA:AA:AA:AA",
    md5: "AA:AA:AA:AA",
    subject: "CN=mock-a.example",
    issuer: "CN=Mock Test CA",
    activates: "2026-01-01T00:00:00Z",
    expires: "2036-01-01T00:00:00Z",
    serial: "01",
    format: "PEM",
    valid: true,
};

const CERT_A_DER_FIXTURE: CertificateFixture = CertificateFixture {
    format: "DER",
    ..CERT_A_PEM_FIXTURE
};

const CERT_B_PEM_FIXTURE: CertificateFixture = CertificateFixture {
    sha256: "BB:BB:BB:BB:BB:BB:BB:BB",
    md5: "BB:BB:BB:BB",
    subject: "CN=mock-b.example",
    issuer: "CN=Mock Test CA",
    activates: "2020-01-01T00:00:00Z",
    expires: "2021-01-01T00:00:00Z",
    serial: "02",
    format: "PEM",
    valid: false,
};

pub(crate) fn handle_create(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    principal: &str,
) -> Vec<u8> {
    if let Some(copy) = direct_child(cmd, "copy") {
        let Some(id) = copy
            .text
            .as_deref()
            .and_then(|value| Uuid::parse_str(value).ok())
        else {
            return error_response(&cmd.name, 404, "TLS certificate to clone not found");
        };
        let name = paired_text_at_path(&cmd.raw_xml, &["name"]);
        let comment = paired_text_at_path(&cmd.raw_xml, &["comment"]);
        return match store.clone_tls_certificate(
            &id,
            principal,
            name.as_deref(),
            comment.as_deref(),
        ) {
            Ok(id) => created_response(&cmd.name, id),
            Err(error) => store_error(&cmd.name, error),
        };
    }

    let Some(certificate) = direct_child(cmd, "certificate") else {
        return error_response(
            &cmd.name,
            400,
            "Certificate is required and must not be empty",
        );
    };
    let encoded = certificate.text.as_deref().unwrap_or_default();
    if encoded.is_empty() {
        return error_response(
            &cmd.name,
            400,
            "Certificate is required and must not be empty",
        );
    }
    let compact = encoded
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect::<String>();
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(compact) else {
        return error_response(&cmd.name, 400, "Certificate is not valid standard base64");
    };
    if decoded.is_empty() {
        return error_response(
            &cmd.name,
            400,
            "Certificate is required and must not be empty",
        );
    }
    if decoded == INVALID_CERTIFICATE {
        return error_response(&cmd.name, 400, "Invalid certificate content");
    }
    let Some(fixture) = certificate_fixture(&decoded) else {
        return error_response(&cmd.name, 400, "Unsupported mock TLS certificate fixture");
    };

    let requested_name = paired_text_at_path(&cmd.raw_xml, &["name"]);
    let name = requested_name
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or(fixture.sha256);
    let comment = paired_text_at_path(&cmd.raw_xml, &["comment"]).unwrap_or_default();
    let trust = permissive_child_bool(cmd, "trust").unwrap_or(false);
    let mut resource = Resource::new("tls_certificate", name);
    resource.comment = comment;
    apply_fixture(&mut resource, encoded, fixture, trust);
    resource.set_attr("source_id", &Uuid::new_v4().to_string());
    resource.set_attr("source_timestamp", &now_iso());
    resource.set_attr("source_origin_type", "Import");
    resource.set_attr("last_seen", &now_iso());

    match store.create_tls_certificate(resource, principal) {
        Ok(id) => created_response(&cmd.name, id),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_modify(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    principal: &str,
) -> Vec<u8> {
    let Some(id) = cmd
        .attr("tls_certificate_id")
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid tls_certificate_id");
    };
    let name = paired_text_at_path(&cmd.raw_xml, &["name"]);
    let comment = paired_text_at_path(&cmd.raw_xml, &["comment"]);
    let trust = permissive_child_bool(cmd, "trust");
    match store.modify_tls_certificate(&id, principal, name.as_deref(), comment.as_deref(), trust) {
        Ok(()) => b"<modify_tls_certificate_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_delete(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    principal: &str,
) -> Vec<u8> {
    let Some(id) = cmd
        .attr("tls_certificate_id")
        .and_then(|value| Uuid::parse_str(value).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid tls_certificate_id");
    };
    match store.delete_tls_certificate(&id, principal) {
        Ok(()) => b"<delete_tls_certificate_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_get(cmd: &ParsedCommand, store: &ResourceStore, principal: &str) -> Vec<u8> {
    if attribute_bool(cmd.attr("trash")) {
        return error_response(&cmd.name, 400, "TLS certificates do not use the trashcan");
    }
    let details = attribute_bool(cmd.attr("details"));
    let include_certificate_data = attribute_bool(cmd.attr("include_certificate_data"));
    let visible = store
        .list("tls_certificate")
        .into_iter()
        .filter(|resource| tls_visible_to(resource, principal))
        .collect::<Vec<_>>();
    let total = visible.len();

    if let Some(id) = cmd.attr("tls_certificate_id") {
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid tls_certificate_id");
        };
        let Some(resource) = visible.into_iter().find(|resource| resource.id == id) else {
            return error_response(&cmd.name, 404, "TLS certificate not found");
        };
        let item = render_certificate(&resource, details, include_certificate_data);
        return list_response(&item, total, 1, 1, 1, 1);
    }

    let filter = resolve_filter(cmd, store);
    let mut filtered = visible;
    let mut first = 1_usize;
    let mut rows = None;
    let mut sort = "name";
    let mut reverse = false;
    if let Some(filter) = filter.as_deref() {
        for term in filter.split_ascii_whitespace() {
            let relation = if let Some((key, value)) = term.split_once('=') {
                Some((key, value, false))
            } else {
                term.split_once('~').map(|(key, value)| (key, value, true))
            };
            let Some((key, value, contains)) = relation else {
                return error_response(&cmd.name, 400, "Unsupported mock TLS filter term");
            };
            match key {
                "first" if !contains => {
                    let Ok(value) = value.parse::<usize>() else {
                        return error_response(&cmd.name, 400, "Invalid first filter value");
                    };
                    first = value.max(1);
                }
                "rows" if !contains => {
                    let Ok(value) = value.parse::<isize>() else {
                        return error_response(&cmd.name, 400, "Invalid rows filter value");
                    };
                    rows = (value >= 0).then_some(value as usize);
                }
                "sort" if !contains => {
                    sort = value;
                    reverse = false;
                }
                "sort-reverse" if !contains => {
                    sort = value;
                    reverse = true;
                }
                "name" => retain_text(&mut filtered, |resource| &resource.name, value, contains),
                "uuid" | "id" if !contains => {
                    filtered.retain(|resource| resource.id.to_string() == value);
                }
                "owner" => retain_text(
                    &mut filtered,
                    |resource| resource.attr("owner").unwrap_or_default(),
                    value,
                    contains,
                ),
                "sha256_fingerprint" | "md5_fingerprint" | "subject_dn" | "issuer_dn" => {
                    retain_text(
                        &mut filtered,
                        |resource| resource.attr(key).unwrap_or_default(),
                        value,
                        contains,
                    );
                }
                "trust" | "valid" if !contains => {
                    filtered.retain(|resource| resource.attr(key) == Some(value));
                }
                "host_id" | "report_id" if !contains => {
                    let attr = if key == "host_id" {
                        "host_ids"
                    } else {
                        "report_ids"
                    };
                    filtered
                        .retain(|resource| comma_values(resource.attr(attr)).any(|id| id == value));
                }
                _ => return error_response(&cmd.name, 400, "Unsupported mock TLS filter field"),
            }
        }
    }
    filtered.sort_by(|left, right| {
        let ordering = match sort {
            "uuid" | "id" => left.id.cmp(&right.id),
            "owner" => left.attr("owner").cmp(&right.attr("owner")),
            "sha256_fingerprint" | "md5_fingerprint" | "subject_dn" | "issuer_dn" => {
                left.attr(sort).cmp(&right.attr(sort))
            }
            _ => left.name.cmp(&right.name),
        };
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
    let filtered_count = filtered.len();
    let start = first.saturating_sub(1);
    // gvmd parses ignore_pagination for this family but does not apply it.
    let page = if start >= filtered.len() {
        Vec::new()
    } else {
        let end = rows.map_or(filtered.len(), |rows| {
            start.saturating_add(rows).min(filtered.len())
        });
        filtered[start..end].to_vec()
    };
    let page_count = page.len();
    let items = page
        .iter()
        .map(|resource| render_certificate(resource, details, include_certificate_data))
        .collect::<String>();
    list_response(
        &items,
        total,
        filtered_count,
        page_count,
        first,
        rows.unwrap_or(page_count),
    )
}

fn certificate_fixture(bytes: &[u8]) -> Option<&'static CertificateFixture> {
    if bytes == CERT_A_PEM {
        Some(&CERT_A_PEM_FIXTURE)
    } else if bytes == CERT_A_DER {
        Some(&CERT_A_DER_FIXTURE)
    } else if bytes == CERT_B_PEM {
        Some(&CERT_B_PEM_FIXTURE)
    } else {
        None
    }
}

fn apply_fixture(
    resource: &mut Resource,
    certificate: &str,
    fixture: &CertificateFixture,
    trust: bool,
) {
    resource.set_attr("certificate", certificate);
    resource.set_attr("certificate_format", fixture.format);
    resource.set_attr("sha256_fingerprint", fixture.sha256);
    resource.set_attr("md5_fingerprint", fixture.md5);
    resource.set_attr("subject_dn", fixture.subject);
    resource.set_attr("issuer_dn", fixture.issuer);
    resource.set_attr("activation_time", fixture.activates);
    resource.set_attr("expiration_time", fixture.expires);
    resource.set_attr("serial", fixture.serial);
    resource.set_attr("valid", if fixture.valid { "1" } else { "0" });
    resource.set_attr(
        "time_status",
        if fixture.valid { "valid" } else { "expired" },
    );
    resource.set_attr("trust", if trust { "1" } else { "0" });
}

fn render_certificate(resource: &Resource, details: bool, include_data: bool) -> String {
    let certificate = if details || include_data {
        resource.attr("certificate").unwrap_or_default()
    } else {
        ""
    };
    let mut xml = format!(
        "<tls_certificate id=\"{}\"><owner><name>{}</name></owner><name>{}</name>\
         <comment>{}</comment><creation_time>{}</creation_time><modification_time>{}</modification_time>\
         <writable>1</writable><in_use>0</in_use>\
         <certificate format=\"{}\">{}</certificate>\
         <sha256_fingerprint>{}</sha256_fingerprint><md5_fingerprint>{}</md5_fingerprint>\
         <trust>{}</trust><valid>{}</valid><time_status>{}</time_status>\
         <activation_time>{}</activation_time><expiration_time>{}</expiration_time>\
         <subject_dn>{}</subject_dn><issuer_dn>{}</issuer_dn><serial>{}</serial><last_seen>{}</last_seen>",
        xml_escape_attr(&resource.id.to_string()),
        xml_escape(resource.attr("owner").unwrap_or_default()),
        xml_escape(&resource.name),
        xml_escape(&resource.comment),
        xml_escape(&resource.creation_time),
        xml_escape(&resource.modification_time),
        xml_escape_attr(resource.attr("certificate_format").unwrap_or("unknown")),
        xml_escape(certificate),
        xml_escape(resource.attr("sha256_fingerprint").unwrap_or_default()),
        xml_escape(resource.attr("md5_fingerprint").unwrap_or_default()),
        xml_escape(resource.attr("trust").unwrap_or("0")),
        xml_escape(resource.attr("valid").unwrap_or("0")),
        xml_escape(resource.attr("time_status").unwrap_or("unknown")),
        xml_escape(resource.attr("activation_time").unwrap_or_default()),
        xml_escape(resource.attr("expiration_time").unwrap_or_default()),
        xml_escape(resource.attr("subject_dn").unwrap_or_default()),
        xml_escape(resource.attr("issuer_dn").unwrap_or_default()),
        xml_escape(resource.attr("serial").unwrap_or_default()),
        xml_escape(resource.attr("last_seen").unwrap_or_default()),
    );
    if let Some(tags) = resource.attr("tag_ids") {
        xml.push_str("<tags>");
        for id in comma_values(Some(tags)) {
            xml.push_str(&format!(
                "<tag id=\"{}\"><name></name></tag>",
                xml_escape_attr(id)
            ));
        }
        xml.push_str("</tags>");
    }
    if details {
        xml.push_str("<sources>");
        if let Some(source_id) = resource.attr("source_id") {
            xml.push_str(&format!(
                "<source id=\"{}\"><timestamp>{}</timestamp><tls_versions>{}</tls_versions>",
                xml_escape_attr(source_id),
                xml_escape(resource.attr("source_timestamp").unwrap_or_default()),
                xml_escape(resource.attr("source_tls_versions").unwrap_or_default()),
            ));
            if let Some(host) = resource.attr("source_location_host") {
                xml.push_str(&format!(
                    "<location id=\"{}\"><host><ip>{}</ip></host><port>{}</port></location>",
                    xml_escape_attr(resource.attr("source_location_id").unwrap_or_default()),
                    xml_escape(host),
                    xml_escape(resource.attr("source_location_port").unwrap_or_default()),
                ));
            }
            if let Some(origin_type) = resource.attr("source_origin_type") {
                xml.push_str(&format!(
                    "<origin id=\"{}\"><origin_type>{}</origin_type><origin_id>{}</origin_id><origin_data>{}</origin_data></origin>",
                    xml_escape_attr(resource.attr("source_origin_id").unwrap_or_default()),
                    xml_escape(origin_type),
                    xml_escape(resource.attr("source_origin_resource_id").unwrap_or_default()),
                    xml_escape(resource.attr("source_origin_data").unwrap_or_default()),
                ));
            }
            xml.push_str("</source>");
        }
        xml.push_str("</sources>");
    }
    xml.push_str("</tls_certificate>");
    xml
}

fn resolve_filter(cmd: &ParsedCommand, store: &ResourceStore) -> Option<String> {
    match cmd.attr("filt_id") {
        None | Some("0" | "-2") => cmd.attr("filter").map(str::to_string),
        Some(id) => Uuid::parse_str(id)
            .ok()
            .and_then(|id| store.get_typed(&id, "filter"))
            .and_then(|filter| filter.attr("term").map(str::to_string))
            .or_else(|| cmd.attr("filter").map(str::to_string)),
    }
}

fn list_response(
    items: &str,
    total: usize,
    filtered: usize,
    page: usize,
    start: usize,
    max: usize,
) -> Vec<u8> {
    format!(
        "<get_tls_certificates_response status=\"200\" status_text=\"OK\">{items}\
         <tls_certificates start=\"{start}\" max=\"{max}\"/>\
         <tls_certificate_count>{total}<filtered>{filtered}</filtered><page>{page}</page></tls_certificate_count>\
         </get_tls_certificates_response>"
    )
    .into_bytes()
}

fn retain_text<F>(resources: &mut Vec<Resource>, value: F, expected: &str, contains: bool)
where
    F: Fn(&Resource) -> &str,
{
    if contains {
        let expected = expected.to_ascii_lowercase();
        resources.retain(|resource| value(resource).to_ascii_lowercase().contains(&expected));
    } else {
        resources.retain(|resource| value(resource) == expected);
    }
}

fn comma_values(value: Option<&str>) -> impl Iterator<Item = &str> {
    value
        .into_iter()
        .flat_map(|value| value.split(','))
        .filter(|value| !value.is_empty())
}

fn tls_visible_to(resource: &Resource, principal: &str) -> bool {
    resource.attr("owner") == Some(principal)
        || comma_values(resource.attr("visible_to")).any(|value| value == principal)
}

fn attribute_bool(value: Option<&str>) -> bool {
    value.is_some_and(|value| !value.is_empty() && value != "0")
}

fn permissive_child_bool(cmd: &ParsedCommand, name: &str) -> Option<bool> {
    direct_child(cmd, name).map(|element| {
        let value = element.text.as_deref().unwrap_or_default();
        !value.is_empty() && value != "0"
    })
}

fn direct_child<'a>(cmd: &'a ParsedCommand, name: &str) -> Option<&'a ParsedElement> {
    cmd.children.iter().find(|child| child.name == name)
}

fn paired_text_at_path(xml: &[u8], path: &[&str]) -> Option<String> {
    let text = std::str::from_utf8(xml).ok()?;
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<String>::new();
    let mut current = None;
    loop {
        match reader.read_event().ok()? {
            Event::Start(element) => {
                stack.push(element.name().as_ref().to_string());
                if path_matches(&stack, path) {
                    current = Some(String::new());
                }
            }
            Event::Empty(element) => {
                let mut candidate = stack.clone();
                candidate.push(element.name().as_ref().to_string());
                if path_matches(&candidate, path) {
                    return Some(String::new());
                }
            }
            Event::Text(text) if path_matches(&stack, path) => {
                current
                    .as_mut()?
                    .push_str(&text.xml_content(XmlVersion::Implicit1_0));
            }
            Event::CData(text) if path_matches(&stack, path) => {
                current.as_mut()?.push_str(text.as_ref());
            }
            Event::GeneralRef(reference) if path_matches(&stack, path) => {
                current.as_mut()?.push_str(&resolve_reference(&reference)?);
            }
            Event::End(_) => {
                if path_matches(&stack, path) {
                    return current;
                }
                stack.pop();
            }
            Event::Eof => return None,
            _ => {}
        }
    }
}

fn path_matches(stack: &[String], path: &[&str]) -> bool {
    stack.len() == path.len() + 1
        && stack
            .iter()
            .skip(1)
            .zip(path)
            .all(|(actual, expected)| actual == expected)
}

fn resolve_reference(reference: &BytesRef<'_>) -> Option<String> {
    if let Some(character) = reference.resolve_char_ref().ok()? {
        return Some(character.to_string());
    }
    quick_xml::escape::resolve_xml_entity(reference.as_ref()).map(ToString::to_string)
}

fn created_response(command: &str, id: Uuid) -> Vec<u8> {
    format!("<{command}_response status=\"201\" status_text=\"OK, resource created\" id=\"{id}\"/>")
        .into_bytes()
}

fn store_error(command: &str, error: StoreError) -> Vec<u8> {
    match error {
        StoreError::NotFound(resource) => {
            error_response(command, 404, &format!("{resource} not found"))
        }
        StoreError::InvalidArgument(message) => error_response(command, 400, message),
        StoreError::InUse(resource) => {
            error_response(command, 409, &format!("{resource} is in use"))
        }
        StoreError::InvalidState(message) => error_response(command, 409, message),
        StoreError::Inconsistent(resource) => {
            error_response(command, 409, &format!("Inconsistent {resource}"))
        }
    }
}
