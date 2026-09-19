// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful semantics for report-configuration lifecycle commands.

use quick_xml::events::{BytesRef, Event};
use quick_xml::{Reader, XmlVersion};
use uuid::Uuid;

use crate::command_parser::{ParsedCommand, ParsedElement};
use crate::response_gen::error_response;
use crate::store::{ReportConfigParamUpdate, Resource, ResourceStore, StoreError};
use crate::util::{xml_escape, xml_escape_attr};

pub(crate) fn handle_create(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    if direct_child(cmd, "copy").is_some() {
        let Some(copy_id) =
            direct_child_raw_text(cmd, "copy").and_then(|id| Uuid::parse_str(&id).ok())
        else {
            return error_response(&cmd.name, 404, "Report configuration to clone not found");
        };
        let requested_name = direct_child(cmd, "name")
            .is_some()
            .then(|| direct_child_raw_text(cmd, "name").unwrap_or_default());
        return match store.clone_report_config(&copy_id, requested_name.as_deref()) {
            Ok(id) => created_response(&cmd.name, id),
            Err(error) => store_error(&cmd.name, error),
        };
    }

    let Some(name) = direct_child_raw_text(cmd, "name") else {
        return error_response(&cmd.name, 400, "Missing required element: name");
    };
    if name.is_empty() {
        return error_response(&cmd.name, 400, "Name must not be empty");
    }
    let Some(report_format_id) = direct_child(cmd, "report_format")
        .and_then(|element| element.attributes.get("id"))
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return error_response(&cmd.name, 400, "Missing report format reference");
    };
    let comment = direct_child_raw_text(cmd, "comment").unwrap_or_default();
    let params = parse_params(cmd);
    match store.create_report_config(&name, &comment, report_format_id, &params) {
        Ok(id) => created_response(&cmd.name, id),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_modify(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd
        .attr("report_config_id")
        .and_then(|id| Uuid::parse_str(id).ok())
    else {
        return error_response(&cmd.name, 400, "Missing or invalid report_config_id");
    };
    let name = direct_child(cmd, "name")
        .is_some()
        .then(|| direct_child_raw_text(cmd, "name").unwrap_or_default());
    let comment = direct_child(cmd, "comment")
        .is_some()
        .then(|| direct_child_raw_text(cmd, "comment").unwrap_or_default());
    let params = parse_params(cmd);
    match store.modify_report_config(&id, name.as_deref(), comment.as_deref(), &params) {
        Ok(()) => b"<modify_report_config_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, error),
    }
}

pub(crate) fn handle_get(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let trash = parse_bool(cmd.attr("trash"));
    let resources = if trash {
        store.list_trashed("report_config")
    } else {
        store.list("report_config")
    };
    let total = resources.len();

    if let Some(id) = cmd.attr("report_config_id") {
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid report_config_id");
        };
        let Some(resource) = resources.into_iter().find(|resource| resource.id == id) else {
            return error_response(&cmd.name, 404, "Report configuration not found");
        };
        let item = render_report_config(&resource, store, trash);
        return list_response(&cmd.name, &item, total, 1, 1, 1, 1);
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
                if let Some((key, value)) = term.split_once('~') {
                    if key == "name" {
                        let value = value.to_ascii_lowercase();
                        filtered
                            .retain(|resource| resource.name.to_ascii_lowercase().contains(&value));
                    }
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
            "comment" => left.comment.cmp(&right.comment),
            "uuid" | "id" => left.id.cmp(&right.id),
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
        .map(|resource| render_report_config(resource, store, trash))
        .collect::<String>();
    list_response(
        &cmd.name,
        &items,
        total,
        filtered_count,
        page_count,
        start.saturating_add(1),
        page_count,
    )
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

fn render_report_config(resource: &Resource, store: &ResourceStore, trash: bool) -> String {
    let mut xml = format!(
        "<report_config id=\"{}\"><owner><name>admin</name></owner><name>{}</name>\
         <comment>{}</comment><creation_time>{}</creation_time><modification_time>{}</modification_time>\
         <writable>1</writable><in_use>0</in_use>",
        xml_escape_attr(&resource.id.to_string()),
        xml_escape(&resource.name),
        xml_escape(&resource.comment),
        resource.creation_time,
        resource.modification_time,
    );
    if let Some(format_id) = resource.attr("report_format_id") {
        xml.push_str(&format!(
            "<report_format id=\"{}\">",
            xml_escape_attr(format_id)
        ));
        let format = Uuid::parse_str(format_id)
            .ok()
            .and_then(|id| store.get_typed(&id, "report_format"));
        if let Some(format) = &format {
            xml.push_str(&format!("<name>{}</name>", xml_escape(&format.name)));
        }
        xml.push_str("</report_format>");

        // The pinned upstream trash renderer has row-ID-dependent behavior.
        // The bounded mock therefore renders parameters only for active rows.
        if !trash {
            if let Some(format) = format {
                for (key, default) in format.attrs.iter().filter_map(|(key, value)| {
                    key.strip_prefix("report_config_default:")
                        .map(|name| (name, value))
                }) {
                    let override_value = resource.attr(&format!("report_config_value:{key}"));
                    let (value, using_default) =
                        override_value.map_or((default.as_str(), "1"), |value| (value, "0"));
                    xml.push_str(&format!(
                        "<param><name>{}</name><value using_default=\"{}\">{}</value><default>{}</default></param>",
                        xml_escape(key),
                        using_default,
                        xml_escape(value),
                        xml_escape(default),
                    ));
                }
            }
        }
    }
    xml.push_str("</report_config>");
    xml
}

fn list_response(
    command: &str,
    items: &str,
    total: usize,
    filtered: usize,
    page: usize,
    start: usize,
    max: usize,
) -> Vec<u8> {
    format!(
        "<{command}_response status=\"200\" status_text=\"OK\">{items}\
         <report_configs start=\"{start}\" max=\"{max}\"/>\
         <report_config_count>{total}<filtered>{filtered}</filtered><page>{page}</page></report_config_count>\
         </{command}_response>"
    )
    .into_bytes()
}

fn parse_params(cmd: &ParsedCommand) -> Vec<ReportConfigParamUpdate> {
    let mut raw_values = raw_param_values(&cmd.raw_xml).into_iter();
    cmd.children
        .iter()
        .filter(|child| child.name == "param")
        .filter_map(|param| {
            let raw_value = raw_values.next().flatten();
            let name = param.children.iter().find(|child| child.name == "name")?;
            let name = element_text(name)?;
            let name = name
                .trim_matches(|character: char| character.is_ascii_whitespace())
                .to_string();
            if name.is_empty() {
                return None;
            }
            let value = param.children.iter().find(|child| child.name == "value")?;
            if value.attributes.get("use_default").map(String::as_str) == Some("1") {
                Some(ReportConfigParamUpdate::UseDefault { name })
            } else {
                Some(ReportConfigParamUpdate::Value {
                    name,
                    value: raw_value.unwrap_or_default(),
                })
            }
        })
        .collect()
}

fn direct_child<'a>(cmd: &'a ParsedCommand, name: &str) -> Option<&'a ParsedElement> {
    cmd.children.iter().find(|child| child.name == name)
}

fn element_text(element: &ParsedElement) -> Option<&str> {
    element.text.as_deref()
}

fn direct_child_raw_text(cmd: &ParsedCommand, name: &str) -> Option<String> {
    raw_texts_at_path(&cmd.raw_xml, &[name]).into_iter().next()
}

fn raw_param_values(xml: &[u8]) -> Vec<Option<String>> {
    let Ok(text) = std::str::from_utf8(xml) else {
        return Vec::new();
    };
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<String>::new();
    let mut values = Vec::new();
    let mut current_value = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                stack.push(element.name().as_ref().to_string());
                if path_matches(&stack, &["param", "value"]) {
                    current_value = Some(String::new());
                }
            }
            Ok(Event::Empty(element)) => {
                stack.push(element.name().as_ref().to_string());
                if path_matches(&stack, &["param", "value"]) {
                    current_value = Some(String::new());
                } else if path_matches(&stack, &["param"]) {
                    values.push(None);
                }
                stack.pop();
            }
            Ok(Event::Text(text)) if path_matches(&stack, &["param", "value"]) => {
                if let Some(value) = &mut current_value {
                    value.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::CData(text)) if path_matches(&stack, &["param", "value"]) => {
                if let Some(value) = &mut current_value {
                    value.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::GeneralRef(reference)) if path_matches(&stack, &["param", "value"]) => {
                let Some(text) = resolve_reference(&reference) else {
                    return Vec::new();
                };
                if let Some(value) = &mut current_value {
                    value.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                if path_matches(&stack, &["param"]) {
                    values.push(current_value.take());
                }
                stack.pop();
            }
            Ok(Event::Eof) => return values,
            Err(_) => return Vec::new(),
            _ => {}
        }
    }
}

fn raw_texts_at_path(xml: &[u8], path: &[&str]) -> Vec<String> {
    let Ok(text) = std::str::from_utf8(xml) else {
        return Vec::new();
    };
    let mut reader = Reader::from_str(text);
    reader.config_mut().trim_text(false);
    let mut stack = Vec::<String>::new();
    let mut values = Vec::new();
    let mut current_value = None;

    loop {
        match reader.read_event() {
            Ok(Event::Start(element)) => {
                stack.push(element.name().as_ref().to_string());
                if path_matches(&stack, path) {
                    current_value = Some(String::new());
                }
            }
            Ok(Event::Empty(element)) => {
                stack.push(element.name().as_ref().to_string());
                if path_matches(&stack, path) {
                    values.push(String::new());
                }
                stack.pop();
            }
            Ok(Event::Text(text)) if path_matches(&stack, path) => {
                if let Some(value) = &mut current_value {
                    value.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::CData(text)) if path_matches(&stack, path) => {
                if let Some(value) = &mut current_value {
                    value.push_str(&text.xml_content(XmlVersion::Implicit1_0));
                }
            }
            Ok(Event::GeneralRef(reference)) if path_matches(&stack, path) => {
                let Some(text) = resolve_reference(&reference) else {
                    return Vec::new();
                };
                if let Some(value) = &mut current_value {
                    value.push_str(&text);
                }
            }
            Ok(Event::End(_)) => {
                if path_matches(&stack, path) {
                    values.push(current_value.take().unwrap_or_default());
                }
                stack.pop();
            }
            Ok(Event::Eof) => return values,
            Err(_) => return Vec::new(),
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
