// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Source-shaped stateful behavior for report import, queries, and deletion.

use std::collections::BTreeSet;

use uuid::Uuid;

use crate::command_parser::{ParsedCommand, ParsedElement};
use crate::response_gen::{error_response, generate_large_report, LargeReportConfig};
use crate::store::{Resource, ResourceStore, StoreError};
use crate::util::{xml_escape, xml_escape_attr};

pub(crate) fn handle_create(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let mut envelopes = cmd.children.iter().filter(|child| child.name == "report");
    let Some(envelope) = envelopes.next() else {
        return error_response(&cmd.name, 400, "Missing required report envelope");
    };
    if envelopes.next().is_some() {
        return error_response(&cmd.name, 400, "Expected exactly one report envelope");
    }

    let Some(task_id) = cmd.child_attr("task", "id") else {
        return error_response(&cmd.name, 400, "Missing required task id");
    };
    let Ok(task_id) = Uuid::parse_str(task_id) else {
        return error_response(&cmd.name, 400, "Invalid task UUID");
    };
    let in_assets = match cmd.child_text("in_assets") {
        None | Some("0") => false,
        Some("1") => true,
        Some(_) => return error_response(&cmd.name, 400, "Invalid in_assets value"),
    };

    let body = report_body(envelope);
    let name = child_text(body, "name").unwrap_or("Imported report");
    let mut report = Resource::new("report", name);
    report.comment = child_text(body, "comment").unwrap_or_default().to_string();

    let mut results = Vec::new();
    collect_elements(body, "result", &mut |element| {
        results.push(imported_result(element));
    });
    let hosts = imported_hosts(body);

    match store.import_report(report, task_id, in_assets, &hosts, results) {
        Ok(id) => format!(
            "<create_report_response status=\"201\" status_text=\"OK, resource created\" id=\"{id}\"/>"
        )
        .into_bytes(),
        Err(error) => store_error_response(&cmd.name, error),
    }
}

pub(crate) fn handle_get(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    large_report: Option<&LargeReportConfig>,
) -> Vec<u8> {
    if let Some(id) = cmd.attr("report_id") {
        return handle_get_one(cmd, store, large_report, id);
    }

    let filter = match report_list_filter(cmd, store) {
        Ok(filter) => filter,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    let mut reports = store.list("report");
    if let Some(usage_type) = cmd.attr("usage_type") {
        reports.retain(|report| report.attr("usage_type") == Some(usage_type));
    }
    let full = reports.len();
    apply_report_filter(&mut reports, &filter);
    let filtered = reports.len();
    if cmd.attr("ignore_pagination") != Some("1") {
        paginate(&mut reports, &filter);
    }

    let details = cmd.attr("details") == Some("1");
    let items = reports
        .iter()
        .map(|report| render_report(report, store, details, "", false))
        .collect::<String>();
    format!(
        "<get_reports_response status=\"200\" status_text=\"OK\">{items}\
         <report_count>{full}<filtered>{filtered}</filtered></report_count>\
         </get_reports_response>"
    )
    .into_bytes()
}

pub(crate) fn handle_delete(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd.attr("report_id") else {
        return error_response(&cmd.name, 400, "Missing required attribute: report_id");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return error_response(&cmd.name, 400, "Invalid UUID");
    };

    // Pinned gvmd ignores no `ultimate` selector here: report deletion is
    // always permanent for both scan and audit semantic surfaces.
    match store.delete_typed(&id, "report", true) {
        Ok(()) => b"<delete_report_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error_response(&cmd.name, error),
    }
}

fn handle_get_one(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    large_report: Option<&LargeReportConfig>,
    id: &str,
) -> Vec<u8> {
    let Ok(id) = Uuid::parse_str(id) else {
        return error_response(&cmd.name, 400, "Invalid UUID");
    };
    let Some(report) = store.get_typed(&id, "report") else {
        return error_response(&cmd.name, 404, "Resource not found");
    };
    if cmd
        .attr("usage_type")
        .is_some_and(|usage_type| report.attr("usage_type") != Some(usage_type))
    {
        return error_response(&cmd.name, 404, "Resource not found");
    }
    if let Some(config) = large_report.filter(|_| report.attr("task_id").is_some()) {
        return generate_large_report(report.id, config).into_bytes();
    }

    let result_filter = match result_filter(cmd, store) {
        Ok(filter) => filter,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    let details = cmd.attr("details") != Some("0");
    let report_xml = render_report(
        &report,
        store,
        details,
        &result_filter,
        cmd.attr("ignore_pagination") == Some("1"),
    );
    format!(
        "<get_reports_response status=\"200\" status_text=\"OK\">{report_xml}\
         <report_count>1<filtered>1</filtered></report_count>\
         </get_reports_response>"
    )
    .into_bytes()
}

fn report_body(envelope: &ParsedElement) -> &ParsedElement {
    let mut nested = envelope
        .children
        .iter()
        .filter(|child| child.name == "report");
    match (nested.next(), nested.next()) {
        (Some(body), None) => body,
        _ => envelope,
    }
}

fn child_text<'a>(element: &'a ParsedElement, name: &str) -> Option<&'a str> {
    element
        .children
        .iter()
        .find(|child| child.name == name)
        .and_then(|child| child.text.as_deref())
}

fn collect_elements(element: &ParsedElement, name: &str, visit: &mut impl FnMut(&ParsedElement)) {
    for child in &element.children {
        if child.name == name {
            visit(child);
        }
        collect_elements(child, name, visit);
    }
}

fn imported_result(element: &ParsedElement) -> Resource {
    let name = child_text(element, "name")
        .or_else(|| {
            element
                .children
                .iter()
                .find(|child| child.name == "nvt")
                .and_then(|nvt| child_text(nvt, "name"))
        })
        .unwrap_or("Imported result");
    let mut result = Resource::new("result", name);
    for field in ["host", "port", "threat", "severity", "compliance"] {
        if let Some(value) = child_text(element, field) {
            result.set_attr(field, value);
        }
    }
    result
}

fn imported_hosts(body: &ParsedElement) -> Vec<String> {
    let mut hosts = BTreeSet::new();
    collect_elements(body, "result", &mut |result| {
        if let Some(host) = child_text(result, "host").filter(|host| !host.is_empty()) {
            hosts.insert(host.to_string());
        }
    });
    collect_elements(body, "host", &mut |host| {
        if let Some(ip) = child_text(host, "ip").filter(|ip| !ip.is_empty()) {
            hosts.insert(ip.to_string());
        }
    });
    hosts.into_iter().collect()
}

fn report_list_filter(cmd: &ParsedCommand, store: &ResourceStore) -> Result<String, &'static str> {
    if let Some(filter_id) = cmd.attr("report_filt_id") {
        let filter_id = Uuid::parse_str(filter_id).map_err(|_| "Invalid report filter UUID")?;
        let filter = store
            .get_typed(&filter_id, "filter")
            .ok_or("Report filter not found")?;
        Ok(filter.attr("term").unwrap_or_default().to_string())
    } else {
        Ok(cmd.attr("report_filter").unwrap_or_default().to_string())
    }
}

fn result_filter(cmd: &ParsedCommand, store: &ResourceStore) -> Result<String, &'static str> {
    if let Some(filter_id) = cmd.attr("filt_id") {
        let filter_id = Uuid::parse_str(filter_id).map_err(|_| "Invalid result filter UUID")?;
        let filter = store
            .get_typed(&filter_id, "filter")
            .ok_or("Result filter not found")?;
        Ok(filter.attr("term").unwrap_or_default().to_string())
    } else {
        Ok(cmd.attr("filter").unwrap_or_default().to_string())
    }
}

fn apply_report_filter(reports: &mut Vec<Resource>, filter: &str) {
    for term in filter.split_whitespace() {
        let Some((key, value)) = term.split_once(['=', '~']) else {
            continue;
        };
        match key {
            "first" | "rows" | "sort" | "sort-reverse" => {}
            "name" if term.contains('~') => reports.retain(|report| report.name.contains(value)),
            "name" => reports.retain(|report| report.name == value),
            "task_id" => reports.retain(|report| report.attr("task_id") == Some(value)),
            "usage_type" => reports.retain(|report| report.attr("usage_type") == Some(value)),
            _ => {}
        }
    }
    let (field, reverse) = sort_term(filter);
    reports.sort_by(|left, right| {
        let ordering = report_sort_value(left, field).cmp(report_sort_value(right, field));
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
}

fn paginate(resources: &mut Vec<Resource>, filter: &str) {
    let first = numeric_term(filter, "first").unwrap_or(1).max(1) - 1;
    let rows = numeric_term(filter, "rows").filter(|rows| *rows > 0);
    let start = first.min(resources.len());
    let end = rows.map_or(resources.len(), |rows| {
        start.saturating_add(rows).min(resources.len())
    });
    *resources = resources[start..end].to_vec();
}

fn numeric_term(filter: &str, name: &str) -> Option<usize> {
    filter.split_whitespace().find_map(|term| {
        let (key, value) = term.split_once('=')?;
        (key == name).then(|| value.parse().ok()).flatten()
    })
}

fn sort_term(filter: &str) -> (&str, bool) {
    for term in filter.split_whitespace() {
        if let Some(value) = term.strip_prefix("sort-reverse=") {
            return (value, true);
        }
        if let Some(value) = term.strip_prefix("sort=") {
            return (value, false);
        }
    }
    ("name", false)
}

fn report_sort_value<'a>(report: &'a Resource, field: &str) -> &'a str {
    match field {
        "name" => &report.name,
        "created" | "creation_time" => &report.creation_time,
        "modified" | "modification_time" => &report.modification_time,
        _ => report.attr(field).unwrap_or_default(),
    }
}

fn render_report(
    report: &Resource,
    store: &ResourceStore,
    details: bool,
    filter: &str,
    ignore_pagination: bool,
) -> String {
    let task = report
        .attr("task_id")
        .and_then(|id| Uuid::parse_str(id).ok())
        .and_then(|id| store.get_typed(&id, "task"));
    let task_xml = task.map_or_else(String::new, |task| {
        format!(
            "<task id=\"{}\"><name>{}</name></task>",
            task.id,
            xml_escape(&task.name)
        )
    });
    let metadata = ["status", "usage_type", "in_assets"]
        .into_iter()
        .filter_map(|key| report.attr(key).map(|value| (key, value)))
        .map(|(key, value)| format!("<{key}>{}</{key}>", xml_escape(value)))
        .collect::<String>();
    let detail_xml =
        details.then(|| render_report_details(report, store, filter, ignore_pagination));
    format!(
        "<report id=\"{id}\"><name>{name}</name><comment>{comment}</comment>\
         <creation_time>{created}</creation_time><modification_time>{modified}</modification_time>\
         {task_xml}{metadata}{detail_xml}</report>",
        id = xml_escape_attr(&report.id.to_string()),
        name = xml_escape(&report.name),
        comment = xml_escape(&report.comment),
        created = xml_escape(&report.creation_time),
        modified = xml_escape(&report.modification_time),
        detail_xml = detail_xml.unwrap_or_default(),
    )
}

fn render_report_details(
    report: &Resource,
    store: &ResourceStore,
    filter: &str,
    ignore_pagination: bool,
) -> String {
    let report_id = report.id.to_string();
    let all = store
        .list("result")
        .into_iter()
        .filter(|result| result.attr("report_id") == Some(report_id.as_str()))
        .collect::<Vec<_>>();
    let mut filtered = all
        .iter()
        .filter(|result| result_matches(result, filter))
        .cloned()
        .collect::<Vec<_>>();
    let filtered_count = filtered.len();
    let (sort_field, reverse) = sort_term(filter);
    filtered.sort_by(|left, right| {
        let ordering = result_sort_value(left, sort_field)
            .cmp(result_sort_value(right, sort_field))
            .then_with(|| left.id.cmp(&right.id));
        if reverse {
            ordering.reverse()
        } else {
            ordering
        }
    });
    if !ignore_pagination {
        paginate(&mut filtered, filter);
    }
    let results = filtered.iter().map(render_result).collect::<String>();
    let max_severity = all
        .iter()
        .filter_map(|result| result.attr("severity")?.parse::<f64>().ok())
        .fold(0.0_f64, f64::max);
    let filtered_severity = filtered
        .iter()
        .filter_map(|result| result.attr("severity")?.parse::<f64>().ok())
        .fold(0.0_f64, f64::max);
    let hosts = all
        .iter()
        .filter_map(|result| result.attr("host"))
        .collect::<BTreeSet<_>>()
        .len();
    format!(
        "<report id=\"{}\"><scan_start>{}</scan_start><scan_end>{}</scan_end>\
         <hosts><count>{hosts}</count></hosts>\
         <results max=\"100\" start=\"1\">{results}</results>\
         <result_count><full>{}</full><filtered>{filtered_count}</filtered></result_count>\
         <severity><full>{max_severity:.1}</full><filtered>{filtered_severity:.1}</filtered></severity>\
         </report>",
        report.id,
        xml_escape(&report.creation_time),
        xml_escape(&report.modification_time),
        all.len(),
    )
}

fn result_matches(result: &Resource, filter: &str) -> bool {
    filter.split_whitespace().all(|term| {
        let Some((key, value)) = term.split_once('=') else {
            return true;
        };
        match key {
            "first" | "rows" | "sort" | "sort-reverse" => true,
            "host" => result.attr("host") == Some(value),
            "port" => result.attr("port") == Some(value),
            "severity" => result.attr("severity") == Some(value),
            _ => true,
        }
    })
}

fn result_sort_value<'a>(result: &'a Resource, field: &str) -> &'a str {
    match field {
        "name" => &result.name,
        _ => result.attr(field).unwrap_or_default(),
    }
}

fn render_result(result: &Resource) -> String {
    let fields = ["host", "port", "threat", "severity", "compliance"]
        .into_iter()
        .filter_map(|key| result.attr(key).map(|value| (key, value)))
        .map(|(key, value)| format!("<{key}>{}</{key}>", xml_escape(value)))
        .collect::<String>();
    format!(
        "<result id=\"{}\"><name>{}</name>{fields}</result>",
        result.id,
        xml_escape(&result.name),
    )
}

fn store_error_response(command: &str, error: StoreError) -> Vec<u8> {
    match error {
        StoreError::NotFound(resource) => {
            error_response(command, 404, &format!("{resource} not found"))
        }
        StoreError::InUse(resource) => {
            error_response(command, 409, &format!("{resource} is in use"))
        }
        StoreError::InvalidArgument(message) => error_response(command, 400, message),
        StoreError::InvalidState(message) => error_response(command, 409, message),
        StoreError::Inconsistent(resource) => error_response(
            command,
            409,
            &format!("Task graph is inconsistent: {resource}"),
        ),
    }
}
