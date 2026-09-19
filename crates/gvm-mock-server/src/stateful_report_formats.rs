// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful semantics for report-format lifecycle commands.

use std::collections::BTreeSet;

use base64::Engine as _;
use quick_xml::events::{BytesRef, Event};
use quick_xml::{Reader, XmlVersion};
use uuid::Uuid;

use crate::command_parser::{ParsedCommand, ParsedElement};
use crate::response_gen::error_response;
use crate::store::{validate_seeded_report_format_value, Resource, ResourceStore, StoreError};
use crate::util::{xml_escape, xml_escape_attr};

pub(crate) fn handle_create(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    if let Some(copy) = direct_child(cmd, "copy") {
        let Some(id) = copy.text.as_deref().and_then(|id| Uuid::parse_str(id).ok()) else {
            return error_response(&cmd.name, 404, "Report format to clone not found");
        };
        let requested_name =
            direct_child(cmd, "name").map(|name| name.text.clone().unwrap_or_default());
        return match store.clone_report_format(&id, requested_name.as_deref()) {
            Ok(id) => created_response(&cmd.name, id),
            Err(error) => store_error(&cmd.name, error),
        };
    }

    let Some(envelope) = direct_child(cmd, "get_report_formats_response") else {
        return error_response(
            &cmd.name,
            400,
            "A get_report_formats_response import envelope is required",
        );
    };
    let Some(format) = envelope
        .children
        .iter()
        .find(|child| child.name == "report_format")
    else {
        return error_response(&cmd.name, 400, "Import envelope contains no report format");
    };
    let (resource, exported_id) = match imported_resource(format) {
        Ok(imported) => imported,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    match store.import_report_format(resource, exported_id) {
        Ok(id) => created_response(&cmd.name, id),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_modify(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd
        .attr("report_format_id")
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid report_format_id");
    };
    let name = paired_text_at_path(&cmd.raw_xml, &["name"]);
    let summary = paired_text_at_path(&cmd.raw_xml, &["summary"]);
    let active = match direct_child(cmd, "active").and_then(|active| active.text.as_deref()) {
        None => None,
        Some("0" | "false") => Some(false),
        Some("1" | "true") => Some(true),
        Some(_) => return error_response(&cmd.name, 400, "Invalid active value"),
    };

    let parameter = match direct_child(cmd, "param") {
        None => None,
        Some(param) => {
            let Some(name) = paired_text_at_path(&cmd.raw_xml, &["param", "name"]) else {
                return error_response(&cmd.name, 400, "Missing report format parameter name");
            };
            let encoded = param
                .children
                .iter()
                .find(|child| child.name == "value")
                .map(|value| value.text.as_deref().unwrap_or_default());
            let value = match encoded {
                None | Some("") => String::new(),
                Some(encoded) => {
                    let encoded = encoded
                        .chars()
                        .filter(|character| !character.is_ascii_whitespace())
                        .collect::<String>();
                    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(encoded)
                    else {
                        return error_response(&cmd.name, 400, "Invalid parameter base64 value");
                    };
                    let Ok(decoded) = String::from_utf8(decoded) else {
                        return error_response(&cmd.name, 400, "Parameter value is not UTF-8");
                    };
                    decoded
                }
            };
            Some((name, value))
        }
    };

    match store.modify_report_format(
        &id,
        name.as_deref(),
        summary.as_deref(),
        active,
        parameter
            .as_ref()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    ) {
        Ok(()) => b"<modify_report_format_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_get(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let trash = parse_bool(cmd.attr("trash"));
    let params = parse_bool(cmd.attr("params"));
    if trash && params {
        return error_response(&cmd.name, 400, "params and trash cannot both be true");
    }
    let details = parse_bool(cmd.attr("details"));
    let alerts = parse_bool(cmd.attr("alerts"));
    let report_configs = parse_bool(cmd.attr("report_configs"));
    let resources = if trash {
        store.list_trashed("report_format")
    } else {
        store.list("report_format")
    };
    let total = resources.len();

    if let Some(id) = cmd.attr("report_format_id") {
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid report_format_id");
        };
        let Some(resource) = resources.into_iter().find(|resource| resource.id == id) else {
            return error_response(&cmd.name, 404, "Report format not found");
        };
        let item = render_report_format(
            &resource,
            store,
            trash,
            details,
            params,
            alerts,
            report_configs,
        );
        return list_response(&item, total, 1, 1, 1, 1);
    }

    let (filter, concrete_saved_filter) = resolve_filter(cmd, store);
    let mut filtered = resources;
    let mut first = 1_usize;
    let mut rows = None;
    let mut sort = "name";
    let mut reverse = false;
    if let Some(filter) = filter.as_deref() {
        for term in filter.split_ascii_whitespace() {
            let Some((key, value)) = term.split_once('=') else {
                if let Some(("name", value)) = term.split_once('~') {
                    let value = value.to_ascii_lowercase();
                    filtered.retain(|resource| resource.name.to_ascii_lowercase().contains(&value));
                }
                continue;
            };
            match key {
                "name" => filtered.retain(|resource| resource.name == value),
                "uuid" | "id" => {
                    filtered.retain(|resource| resource.id.to_string() == value);
                }
                "first" => first = value.parse::<usize>().unwrap_or(1).max(1),
                "rows" => {
                    rows = value
                        .parse::<isize>()
                        .ok()
                        .filter(|rows| *rows >= 0)
                        .map(|rows| rows as usize);
                }
                "sort" => {
                    sort = value;
                    reverse = false;
                }
                "sort-reverse" => {
                    sort = value;
                    reverse = true;
                }
                _ => {}
            }
        }
    }
    filtered.sort_by(|left, right| {
        let ordering = match sort {
            "uuid" | "id" => left.id.cmp(&right.id),
            "summary" => left.attr("summary").cmp(&right.attr("summary")),
            _ => left.name.cmp(&right.name),
        };
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
    let filtered_count = filtered.len();
    let ignore_pagination = parse_bool(cmd.attr("ignore_pagination"));
    let mut start = first.saturating_sub(1);
    if start >= filtered.len() && !filtered.is_empty() && !concrete_saved_filter {
        start = 0;
    }
    let page = if ignore_pagination {
        filtered
    } else if start >= filtered.len() {
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
        .map(|resource| {
            render_report_format(
                resource,
                store,
                trash,
                details,
                params,
                alerts,
                report_configs,
            )
        })
        .collect::<String>();
    list_response(
        &items,
        total,
        filtered_count,
        page_count,
        start.saturating_add(1),
        page_count,
    )
}

pub(crate) fn handle_delete(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd
        .attr("report_format_id")
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid report_format_id");
    };
    let ultimate = parse_bool(cmd.attr("ultimate"));
    match store.delete_report_format(&id, ultimate) {
        Ok(()) => b"<delete_report_format_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_verify(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd
        .attr("report_format_id")
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid report_format_id");
    };
    match store.verify_report_format(&id) {
        Ok(()) => b"<verify_report_format_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

fn imported_resource(format: &ParsedElement) -> Result<(Resource, Uuid), &'static str> {
    let exported_id = format
        .attributes
        .get("id")
        .and_then(|id| Uuid::parse_str(id).ok())
        .ok_or("Imported report format ID must be a UUID")?;
    let name = child_text(format, "name").ok_or("Imported report format name is required")?;
    if name.is_empty() {
        return Err("Imported report format name must not be empty");
    }

    let mut resource = Resource::with_id("report_format", name, exported_id);
    for field in [
        "content_type",
        "extension",
        "summary",
        "description",
        "signature",
    ] {
        if let Some(value) = child_text(format, field) {
            resource.set_attr(field, value);
        }
    }
    let report_type = child_text(format, "report_type")
        .filter(|value| matches!(*value, "scan" | "audit" | "all"))
        .unwrap_or("all");
    resource.set_attr("report_type", report_type);

    let mut parameter_names = BTreeSet::new();
    for parameter in format.children.iter().filter(|child| child.name == "param") {
        let name = child_text(parameter, "name")
            .unwrap_or_default()
            .to_string();
        if !parameter_names.insert(name.clone()) {
            return Err("Duplicate report format parameter name");
        }
        let parameter_type = child_text(parameter, "type")
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or("Report format parameter type is required")?;
        if !matches!(
            parameter_type,
            "string"
                | "integer"
                | "selection"
                | "multi_selection"
                | "report_format_list"
                | "boolean"
        ) {
            return Err("Unsupported report format parameter type");
        }
        let Some(default_element) = child(parameter, "default") else {
            return Err("Report format parameter default is required");
        };
        let value = child_text(parameter, "value").unwrap_or_default();
        let default = default_element.text.as_deref().unwrap_or_default();
        resource.set_attr(&format!("report_format_param_type:{name}"), parameter_type);
        resource.set_attr(&format!("report_format_param_value:{name}"), value);
        resource.set_attr(&format!("report_format_param_default:{name}"), default);
        for bound in ["min", "max"] {
            if let Some(value) = child_text(parameter, bound) {
                if value.parse::<i64>().is_err() {
                    return Err("Invalid report format parameter bound");
                }
                resource.set_attr(&format!("report_format_param_{bound}:{name}"), value);
            }
        }
        if let Some(options) = child(parameter, "options") {
            for (index, option) in options
                .children
                .iter()
                .filter(|child| child.name == "option")
                .enumerate()
            {
                resource.set_attr(
                    &format!("report_format_param_option:{name}\u{1f}{index}"),
                    option.text.as_deref().unwrap_or_default(),
                );
            }
        }
        let config_definition = match parameter_type {
            "selection" => {
                let choices = resource
                    .attrs
                    .iter()
                    .filter_map(|(key, option)| {
                        key.starts_with(&format!("report_format_param_option:{name}\u{1f}"))
                            .then_some(option.as_str())
                    })
                    .collect::<Vec<_>>()
                    .join(",");
                format!("selection:{choices}")
            }
            _ => format!(
                "string:{}",
                resource
                    .attr(&format!("report_format_param_max:{name}"))
                    .unwrap_or("18446744073709551615")
            ),
        };
        resource.set_attr(&format!("report_config_param:{name}"), &config_definition);
        resource.set_attr(&format!("report_config_default:{name}"), default);
    }
    resource.set_attr(
        "configurable",
        if parameter_names.is_empty() { "0" } else { "1" },
    );
    for name in &parameter_names {
        let value = resource
            .attr(&format!("report_format_param_value:{name}"))
            .unwrap_or_default();
        let default = resource
            .attr(&format!("report_format_param_default:{name}"))
            .unwrap_or_default();
        validate_seeded_report_format_value(&resource, name, value)
            .map_err(|_| "Invalid current report format parameter value")?;
        validate_seeded_report_format_value(&resource, name, default)
            .map_err(|_| "Invalid default report format parameter value")?;
    }

    for file in format.children.iter().filter(|child| child.name == "file") {
        let Some(filename) = file.attributes.get("name") else {
            continue;
        };
        if filename.is_empty() {
            return Err("Report format filename must not be empty");
        }
        let payload = file.text.as_deref().unwrap_or_default();
        let compact = payload
            .chars()
            .filter(|character| !character.is_ascii_whitespace())
            .collect::<String>();
        base64::engine::general_purpose::STANDARD
            .decode(compact)
            .map_err(|_| "Invalid report format file base64")?;
        resource.set_attr(&format!("report_format_file:{filename}"), payload);
    }

    Ok((resource, exported_id))
}

#[allow(clippy::too_many_arguments)]
fn render_report_format(
    resource: &Resource,
    store: &ResourceStore,
    trash: bool,
    details: bool,
    params: bool,
    alerts: bool,
    report_configs: bool,
) -> String {
    let id = resource.id.to_string();
    let alert_references = store
        .list("alert")
        .into_iter()
        .filter(|alert| report_format_reference(alert, &id))
        .collect::<Vec<_>>();
    let configs = store
        .list("report_config")
        .into_iter()
        .filter(|config| config.attr("report_format_id") == Some(id.as_str()))
        .collect::<Vec<_>>();
    let trust = if !trash
        && resource.attr("predefined") == Some("1")
        && resource.attr("active") == Some("1")
    {
        "yes"
    } else {
        resource.attr("trust").unwrap_or("unknown")
    };
    let mut xml = format!(
        "<report_format id=\"{}\"><owner><name>admin</name></owner><name>{}</name>\
         <comment>{}</comment><creation_time>{}</creation_time><modification_time>{}</modification_time>\
         <writable>{}</writable><in_use>{}</in_use>",
        xml_escape_attr(&id),
        xml_escape(&resource.name),
        xml_escape(&resource.comment),
        resource.creation_time,
        resource.modification_time,
        if resource.attr("predefined") == Some("1") { "0" } else { "1" },
        if alert_references.is_empty() { "0" } else { "1" },
    );
    for field in ["content_type", "extension", "summary"] {
        if let Some(value) = resource.attr(field) {
            xml.push_str(&format!("<{field}>{}</{field}>", xml_escape(value)));
        }
    }
    xml.push_str(&format!(
        "<trust>{}<time>{}</time></trust><active>{}</active><predefined>{}</predefined>",
        xml_escape(trust),
        xml_escape(resource.attr("trust_time").unwrap_or_default()),
        xml_escape(resource.attr("active").unwrap_or("0")),
        xml_escape(resource.attr("predefined").unwrap_or("0")),
    ));

    if details || params {
        let names = resource
            .attrs
            .keys()
            .filter_map(|key| key.strip_prefix("report_format_param_type:"))
            .collect::<Vec<_>>();
        for name in names {
            xml.push_str(&format!(
                "<param><name>{}</name><type>{}</type><value>{}</value><default>{}</default>",
                xml_escape(name),
                xml_escape(
                    resource
                        .attr(&format!("report_format_param_type:{name}"))
                        .unwrap_or_default()
                ),
                xml_escape(
                    resource
                        .attr(&format!("report_format_param_value:{name}"))
                        .unwrap_or_default()
                ),
                xml_escape(
                    resource
                        .attr(&format!("report_format_param_default:{name}"))
                        .unwrap_or_default()
                ),
            ));
            if !trash {
                let options = resource
                    .attrs
                    .iter()
                    .filter_map(|(key, option)| {
                        key.starts_with(&format!("report_format_param_option:{name}\u{1f}"))
                            .then_some(option)
                    })
                    .collect::<Vec<_>>();
                if !options.is_empty() {
                    xml.push_str("<options>");
                    for option in options {
                        xml.push_str(&format!("<option>{}</option>", xml_escape(option)));
                    }
                    xml.push_str("</options>");
                }
            }
            xml.push_str("</param>");
        }
    }
    if details && !trash {
        for (filename, payload) in resource.attrs.iter().filter_map(|(key, value)| {
            key.strip_prefix("report_format_file:")
                .map(|filename| (filename, value))
        }) {
            xml.push_str(&format!(
                "<file name=\"{}\">{}</file>",
                xml_escape_attr(filename),
                xml_escape(payload),
            ));
        }
        if let Some(signature) = resource.attr("signature") {
            xml.push_str(&format!("<signature>{}</signature>", xml_escape(signature)));
        }
    }
    if alerts {
        render_associations(&mut xml, "alerts", "alert", &alert_references);
    }
    if report_configs {
        render_associations(&mut xml, "report_configs", "report_config", &configs);
    }
    xml.push_str("</report_format>");
    xml
}

fn render_associations(xml: &mut String, container: &str, item: &str, resources: &[Resource]) {
    let invisible = resources
        .iter()
        .filter(|resource| resource.attr("visible") == Some("0"))
        .count();
    xml.push_str(&format!("<{container}>"));
    for resource in resources
        .iter()
        .filter(|resource| resource.attr("visible") != Some("0"))
    {
        xml.push_str(&format!(
            "<{item} id=\"{}\"><name>{}</name></{item}>",
            xml_escape_attr(&resource.id.to_string()),
            xml_escape(&resource.name),
        ));
    }
    xml.push_str(&format!(
        "<count>{}<filtered>{invisible}</filtered></count></{container}>",
        resources.len()
    ));
}

fn report_format_reference(alert: &Resource, id: &str) -> bool {
    [
        "notice_attach_format",
        "notice_report_format",
        "scp_report_format",
        "send_report_format",
        "smb_report_format",
        "verinice_server_report_format",
    ]
    .iter()
    .any(|field| alert.attr(field) == Some(id))
}

fn resolve_filter(cmd: &ParsedCommand, store: &ResourceStore) -> (Option<String>, bool) {
    match cmd.attr("filt_id") {
        None | Some("0" | "-2") => (cmd.attr("filter").map(str::to_string), false),
        Some(id) => {
            let saved = Uuid::parse_str(id)
                .ok()
                .and_then(|id| store.get_typed(&id, "filter"))
                .and_then(|filter| filter.attr("term").map(str::to_string));
            saved.map_or_else(
                || (cmd.attr("filter").map(str::to_string), false),
                |saved| (Some(saved), true),
            )
        }
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
        "<get_report_formats_response status=\"200\" status_text=\"OK\">{items}\
         <report_formats start=\"{start}\" max=\"{max}\"/>\
         <report_format_count>{total}<filtered>{filtered}</filtered><page>{page}</page></report_format_count>\
         </get_report_formats_response>"
    )
    .into_bytes()
}

fn direct_child<'a>(cmd: &'a ParsedCommand, name: &str) -> Option<&'a ParsedElement> {
    cmd.children.iter().find(|child| child.name == name)
}

fn child<'a>(element: &'a ParsedElement, name: &str) -> Option<&'a ParsedElement> {
    element.children.iter().find(|child| child.name == name)
}

fn child_text<'a>(element: &'a ParsedElement, name: &str) -> Option<&'a str> {
    child(element, name).and_then(|child| child.text.as_deref())
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
            Event::Empty(_) => {}
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

fn parse_bool(value: Option<&str>) -> bool {
    matches!(value, Some("1" | "true"))
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
