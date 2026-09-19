// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful conformance behavior for get-results.

use std::cmp::Ordering;

use uuid::Uuid;

use crate::command_parser::ParsedCommand;
use crate::response_gen::error_response;
use crate::store::{Resource, ResourceStore};
use crate::util::{xml_escape, xml_escape_attr};

const DEFAULT_MAX_ROWS: usize = 100;

#[derive(Debug, Clone, Copy)]
enum Relation {
    Equal,
    Greater,
    Less,
}

#[derive(Debug)]
struct Predicate {
    field: String,
    relation: Relation,
    value: String,
}

#[derive(Debug)]
struct ResultQuery {
    predicates: Vec<Predicate>,
    first: usize,
    max: usize,
    sort: String,
    reverse: bool,
    min_qod: u32,
    notes: bool,
    overrides: bool,
    apply_overrides: bool,
}

impl Default for ResultQuery {
    fn default() -> Self {
        Self {
            predicates: Vec::new(),
            first: 1,
            max: DEFAULT_MAX_ROWS,
            sort: "id".to_string(),
            reverse: false,
            min_qod: 70,
            notes: false,
            overrides: false,
            apply_overrides: false,
        }
    }
}

struct SelectedResults {
    total: usize,
    filtered: usize,
    first: usize,
    max: usize,
    resources: Vec<EvaluatedResult>,
}

#[derive(Debug, Clone)]
struct EvaluatedResult {
    resource: Resource,
    severity: f64,
    severity_text: String,
    threat: String,
}

pub(crate) fn handle_get_results(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    if cmd.attr("trash") == Some("1") {
        return error_response(&cmd.name, 400, "Result trash retrieval is not supported");
    }
    let requested_context = match requested_context_task(cmd, store) {
        Ok(context) => context,
        Err(response) => return response,
    };
    let filter = match effective_filter(cmd, store) {
        Ok(filter) => filter,
        Err(response) => return response,
    };
    let query = match parse_result_filter(&filter) {
        Ok(query) => query,
        Err(message) => return error_response(&cmd.name, 400, &message),
    };
    let selected = match select_results(cmd, store, &query) {
        Ok(selected) => selected,
        Err(response) => return response,
    };
    render_response(cmd, store, &query, &selected, requested_context)
}

fn requested_context_task(
    cmd: &ParsedCommand,
    store: &ResourceStore,
) -> Result<Option<Uuid>, Vec<u8>> {
    let Some(task_id) = cmd.attr("task_id") else {
        return Ok(None);
    };
    let Ok(task_id) = Uuid::parse_str(task_id) else {
        return Err(error_response(&cmd.name, 400, "Invalid task UUID"));
    };
    if store.get_typed(&task_id, "task").is_none() {
        return Err(error_response(
            &cmd.name,
            404,
            "Failed to find context task",
        ));
    }
    Ok(Some(task_id))
}

fn effective_filter(cmd: &ParsedCommand, store: &ResourceStore) -> Result<String, Vec<u8>> {
    match cmd.attr("filt_id") {
        None | Some("0") => Ok(cmd.attr("filter").unwrap_or_default().to_string()),
        Some("-2") => Err(error_response(
            &cmd.name,
            400,
            "User-setting result filter resolution is not modeled",
        )),
        Some(filter_id) => {
            let Ok(filter_id) = Uuid::parse_str(filter_id) else {
                return Err(error_response(&cmd.name, 400, "Invalid filter UUID"));
            };
            let Some(filter) = store.get_typed(&filter_id, "filter") else {
                return Err(error_response(
                    &cmd.name,
                    404,
                    "Saved-filter fallback is not modeled",
                ));
            };
            Ok(filter.attr("term").unwrap_or_default().to_string())
        }
    }
}

fn parse_result_filter(filter: &str) -> Result<ResultQuery, String> {
    let mut query = ResultQuery::default();
    for token in filter.split_whitespace() {
        let (field, relation, value) = split_predicate(token)?;
        match field {
            "first" => {
                require_equal(relation, field)?;
                query.first = value
                    .parse::<usize>()
                    .map_err(|_| "Invalid result filter value for 'first'".to_string())?
                    .max(1);
            }
            "rows" => {
                require_equal(relation, field)?;
                let rows = value
                    .parse::<isize>()
                    .map_err(|_| "Invalid result filter value for 'rows'".to_string())?;
                query.max = if rows < 0 {
                    DEFAULT_MAX_ROWS
                } else {
                    (rows as usize).min(DEFAULT_MAX_ROWS)
                };
            }
            "sort" | "sort-reverse" => {
                require_equal(relation, field)?;
                if !matches!(value, "id" | "name" | "host" | "port" | "severity" | "qod") {
                    return Err("Unsupported result filter sort field".to_string());
                }
                query.sort = value.to_string();
                query.reverse = field == "sort-reverse";
            }
            "min_qod" => {
                require_equal(relation, field)?;
                query.min_qod = value
                    .parse()
                    .map_err(|_| "Invalid result filter value for 'min_qod'".to_string())?;
            }
            "notes" => {
                require_equal(relation, field)?;
                query.notes = parse_bool(value, field)?;
            }
            "overrides" => {
                require_equal(relation, field)?;
                query.overrides = parse_bool(value, field)?;
            }
            "apply_overrides" => {
                require_equal(relation, field)?;
                query.apply_overrides = parse_bool(value, field)?;
            }
            "severity" | "qod" => {
                validate_finite_number(value, field)?;
                query.predicates.push(Predicate {
                    field: field.to_string(),
                    relation,
                    value: value.to_string(),
                });
            }
            "id" | "uuid" | "name" | "host" | "port" | "threat" | "task_id" | "report_id" => {
                require_equal(relation, field)?;
                query.predicates.push(Predicate {
                    field: field.to_string(),
                    relation,
                    value: value.to_string(),
                });
            }
            _ => return Err(format!("Unsupported result filter field '{field}'")),
        }
    }
    Ok(query)
}

fn split_predicate(token: &str) -> Result<(&str, Relation, &str), String> {
    let Some((index, operator)) = token
        .char_indices()
        .find(|(_, character)| matches!(character, '=' | '>' | '<'))
    else {
        return Err("Malformed result filter predicate".to_string());
    };
    let field = &token[..index];
    let value = &token[index + operator.len_utf8()..];
    if field.is_empty() || value.is_empty() {
        return Err("Malformed result filter predicate".to_string());
    }
    if value
        .chars()
        .any(|character| matches!(character, '=' | '>' | '<'))
    {
        return Err(format!(
            "Unsupported result filter operator for field '{field}'"
        ));
    }
    let relation = match operator {
        '=' => Relation::Equal,
        '>' => Relation::Greater,
        '<' => Relation::Less,
        _ => unreachable!("matched relation"),
    };
    Ok((field, relation, value))
}

fn validate_finite_number(value: &str, field: &str) -> Result<(), String> {
    if value.parse::<f64>().is_ok_and(|number| number.is_finite()) {
        Ok(())
    } else {
        Err(format!(
            "Invalid numeric value for result filter field '{field}'"
        ))
    }
}

fn require_equal(relation: Relation, field: &str) -> Result<(), String> {
    if matches!(relation, Relation::Equal) {
        Ok(())
    } else {
        Err(format!(
            "Invalid relation for result filter field '{field}'"
        ))
    }
}

fn parse_bool(value: &str, field: &str) -> Result<bool, String> {
    match value {
        "1" | "true" => Ok(true),
        "0" | "false" => Ok(false),
        _ => Err(format!("Invalid result filter value for '{field}'")),
    }
}

fn select_results(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    query: &ResultQuery,
) -> Result<SelectedResults, Vec<u8>> {
    let all = store.list("result");
    let total = all.len();
    if let Some(result_id) = cmd.attr("result_id") {
        let Ok(result_id) = Uuid::parse_str(result_id) else {
            return Err(error_response(&cmd.name, 400, "Invalid result UUID"));
        };
        let Some(result) = store.get_typed(&result_id, "result") else {
            return Err(error_response(&cmd.name, 404, "Failed to find result"));
        };
        return Ok(SelectedResults {
            total,
            filtered: 1,
            first: query.first,
            max: query.max,
            resources: vec![evaluate_result(result, store, query.apply_overrides)],
        });
    }

    let mut resources = all
        .into_iter()
        .map(|result| evaluate_result(result, store, query.apply_overrides))
        .filter(|result| result_qod(&result.resource) >= query.min_qod)
        .filter(|result| {
            query
                .predicates
                .iter()
                .all(|predicate| result_matches(result, predicate, store))
        })
        .collect::<Vec<_>>();
    sort_results(&mut resources, query);
    let filtered = resources.len();
    let start = query.first.saturating_sub(1).min(resources.len());
    let end = start.saturating_add(query.max).min(resources.len());
    resources = resources[start..end].to_vec();
    Ok(SelectedResults {
        total,
        filtered,
        first: query.first,
        max: query.max,
        resources,
    })
}

fn evaluate_result(
    resource: Resource,
    store: &ResourceStore,
    apply_overrides: bool,
) -> EvaluatedResult {
    let original_severity = resource.attr("severity").unwrap_or_default();
    let mut severity_text = original_severity.to_string();
    if apply_overrides {
        if let Some(new_severity) = applicable_overrides(&resource, store)
            .first()
            .and_then(|override_| override_.attr("new_severity"))
            .filter(|value| {
                value
                    .parse::<f64>()
                    .is_ok_and(|severity| severity.is_finite())
            })
        {
            severity_text = new_severity.to_string();
        }
    }
    let severity = severity_text.parse::<f64>().unwrap_or_default();
    let threat = if apply_overrides {
        threat_for_severity(severity).to_string()
    } else {
        resource.attr("threat").unwrap_or_default().to_string()
    };
    EvaluatedResult {
        resource,
        severity,
        severity_text,
        threat,
    }
}

fn result_matches(result: &EvaluatedResult, predicate: &Predicate, store: &ResourceStore) -> bool {
    let candidate = match predicate.field.as_str() {
        "id" | "uuid" => result.resource.id.to_string(),
        "name" => result.resource.name.clone(),
        "task_id" => result_task_id(&result.resource, store).unwrap_or_default(),
        "report_id" => result
            .resource
            .attr("report_id")
            .unwrap_or_default()
            .to_string(),
        "severity" => result.severity_text.clone(),
        "threat" => result.threat.clone(),
        "qod" => result_qod(&result.resource).to_string(),
        field => result.resource.attr(field).unwrap_or_default().to_string(),
    };
    if matches!(predicate.field.as_str(), "severity" | "qod") {
        return numeric_matches(&candidate, predicate.relation, &predicate.value);
    }
    matches!(predicate.relation, Relation::Equal) && candidate == predicate.value
}

fn numeric_matches(candidate: &str, relation: Relation, expected: &str) -> bool {
    let (Ok(candidate), Ok(expected)) = (candidate.parse::<f64>(), expected.parse::<f64>()) else {
        return false;
    };
    match relation {
        Relation::Equal => candidate == expected,
        Relation::Greater => candidate > expected,
        Relation::Less => candidate < expected,
    }
}

fn sort_results(resources: &mut [EvaluatedResult], query: &ResultQuery) {
    resources.sort_by(|left, right| {
        let primary = match query.sort.as_str() {
            "severity" => left
                .severity
                .partial_cmp(&right.severity)
                .unwrap_or(Ordering::Equal),
            "qod" => result_qod(&left.resource).cmp(&result_qod(&right.resource)),
            "name" => left.resource.name.cmp(&right.resource.name),
            "host" | "port" => left
                .resource
                .attr(&query.sort)
                .unwrap_or_default()
                .cmp(right.resource.attr(&query.sort).unwrap_or_default()),
            _ => left.resource.id.cmp(&right.resource.id),
        };
        let requested_order = if query.reverse {
            primary.reverse()
        } else {
            primary
        };
        if requested_order == Ordering::Equal {
            left.resource.id.cmp(&right.resource.id)
        } else {
            requested_order
        }
    });
}

fn result_qod(result: &Resource) -> u32 {
    result
        .attr("qod")
        .and_then(|value| value.parse().ok())
        .unwrap_or(100)
}

fn threat_for_severity(severity: f64) -> &'static str {
    if severity >= 9.0 {
        "Critical"
    } else if severity >= 7.0 {
        "High"
    } else if severity >= 4.0 {
        "Medium"
    } else if severity > 0.0 {
        "Low"
    } else {
        "Log"
    }
}

fn result_task_id(result: &Resource, store: &ResourceStore) -> Option<String> {
    result.attr("task_id").map(str::to_string).or_else(|| {
        let report_id = Uuid::parse_str(result.attr("report_id")?).ok()?;
        store
            .get_typed(&report_id, "report")
            .and_then(|report| report.attr("task_id").map(str::to_string))
    })
}

fn result_task_uuid(result: &Resource, store: &ResourceStore) -> Option<Uuid> {
    Uuid::parse_str(&result_task_id(result, store)?).ok()
}

fn applicable_overrides(result: &Resource, store: &ResourceStore) -> Vec<Resource> {
    let Some(task_id) = result_task_uuid(result, store) else {
        return Vec::new();
    };
    related_resources_for_context(store, "override", &result.id.to_string(), Some(task_id))
}

fn render_response(
    cmd: &ParsedCommand,
    store: &ResourceStore,
    query: &ResultQuery,
    selected: &SelectedResults,
    requested_context: Option<Uuid>,
) -> Vec<u8> {
    let details = cmd.attr("details") == Some("1");
    let notes_details = cmd.attr("notes_details") == Some("1");
    let overrides_details = cmd.attr("overrides_details") == Some("1");
    let items = selected
        .resources
        .iter()
        .map(|result| {
            let inferred_context = if cmd.attr("result_id").is_some() || details {
                result_task_uuid(&result.resource, store)
            } else {
                None
            };
            render_result(
                result,
                store,
                query,
                requested_context.or(inferred_context),
                details,
                notes_details,
                overrides_details,
            )
        })
        .collect::<String>();
    let counts = if cmd.attr("get_counts") == Some("0") {
        String::new()
    } else {
        format!(
            "<result_count>{}<filtered>{}</filtered><page>{}</page></result_count>",
            selected.total,
            selected.filtered,
            selected.resources.len()
        )
    };
    format!(
        "<get_results_response status=\"200\" status_text=\"OK\">{items}<results start=\"{}\" max=\"{}\"/>{counts}</get_results_response>",
        selected.first, selected.max
    )
    .into_bytes()
}

fn render_result(
    result: &EvaluatedResult,
    store: &ResourceStore,
    query: &ResultQuery,
    context_task: Option<Uuid>,
    details: bool,
    notes_details: bool,
    overrides_details: bool,
) -> String {
    let resource = &result.resource;
    let result_id = resource.id.to_string();
    let overrides = related_resources_for_context(store, "override", &result_id, context_task);
    let mut xml = format!(
        "<result id=\"{}\"><name>{}</name>",
        resource.id,
        xml_escape(&resource.name)
    );
    render_basic_fields(&mut xml, result);
    if details {
        render_result_references(&mut xml, resource, store, context_task);
    }
    if query.notes {
        render_expansion(
            &mut xml,
            "notes",
            "note",
            &related_resources_for_context(store, "note", &result_id, context_task),
            notes_details,
        );
    }
    if query.overrides {
        render_expansion(
            &mut xml,
            "overrides",
            "override",
            &overrides,
            overrides_details,
        );
    }
    if query.overrides {
        if let Some(severity) = resource.attr("severity") {
            xml.push_str(&format!(
                "<original_severity>{}</original_severity>",
                xml_escape(severity)
            ));
        }
        if let Some(threat) = resource.attr("threat") {
            xml.push_str(&format!(
                "<original_threat>{}</original_threat>",
                xml_escape(threat)
            ));
        }
    }
    xml.push_str("</result>");
    xml
}

fn render_basic_fields(xml: &mut String, result: &EvaluatedResult) {
    for field in ["host", "port"] {
        if let Some(value) = result.resource.attr(field) {
            xml.push_str(&format!("<{field}>{}</{field}>", xml_escape(value)));
        }
    }
    if !result.threat.is_empty() {
        xml.push_str(&format!("<threat>{}</threat>", xml_escape(&result.threat)));
    }
    if !result.severity_text.is_empty() {
        xml.push_str(&format!(
            "<severity>{}</severity>",
            xml_escape(&result.severity_text)
        ));
    }
    if let Some(qod) = result.resource.attr("qod") {
        xml.push_str(&format!(
            "<qod><value>{}</value><type>{}</type></qod>",
            xml_escape(qod),
            xml_escape(result.resource.attr("qod_type").unwrap_or("remote_vul"))
        ));
    }
    if let Some(description) = result.resource.attr("description") {
        xml.push_str(&format!(
            "<description>{}</description>",
            xml_escape(description)
        ));
    }
    if let Some(oid) = result.resource.attr("nvt_oid") {
        xml.push_str(&format!(
            "<nvt oid=\"{}\"><name>{}</name><family>{}</family>",
            xml_escape_attr(oid),
            xml_escape(result.resource.attr("nvt_name").unwrap_or_default()),
            xml_escape(result.resource.attr("nvt_family").unwrap_or_default())
        ));
        if let Some(cvss) = result.resource.attr("cvss_base") {
            xml.push_str(&format!("<cvss_base>{}</cvss_base>", xml_escape(cvss)));
        }
        for cve in result.resource.attr("cves").unwrap_or_default().split(',') {
            if !cve.is_empty() {
                xml.push_str(&format!("<cve>{}</cve>", xml_escape(cve)));
            }
        }
        xml.push_str("</nvt>");
    }
}

fn render_result_references(
    xml: &mut String,
    result: &Resource,
    store: &ResourceStore,
    context_task: Option<Uuid>,
) {
    if let Some(task_id) = context_task {
        let name = store
            .get_typed(&task_id, "task")
            .map(|task| task.name)
            .unwrap_or_default();
        xml.push_str(&format!(
            "<task id=\"{}\"><name>{}</name></task>",
            task_id,
            xml_escape(&name)
        ));
    }
    if let Some(report_id) = result.attr("report_id") {
        let name = Uuid::parse_str(report_id)
            .ok()
            .and_then(|id| store.get_typed(&id, "report"))
            .map(|report| report.name)
            .unwrap_or_default();
        xml.push_str(&format!(
            "<report id=\"{}\"><name>{}</name></report>",
            xml_escape_attr(report_id),
            xml_escape(&name)
        ));
    }
}

fn related_resources_for_context(
    store: &ResourceStore,
    resource_type: &str,
    result_id: &str,
    context_task: Option<Uuid>,
) -> Vec<Resource> {
    let Some(context_task) = context_task else {
        return Vec::new();
    };
    let context_task = context_task.to_string();
    let mut resources = store
        .list(resource_type)
        .into_iter()
        .filter(|resource| {
            resource.attr("result_id") == Some(result_id)
                && resource.attr("task_id") == Some(context_task.as_str())
        })
        .collect::<Vec<_>>();
    resources.sort_by_key(|resource| resource.id);
    resources
}

fn render_expansion(
    xml: &mut String,
    collection: &str,
    item: &str,
    resources: &[Resource],
    detailed: bool,
) {
    xml.push_str(&format!("<{collection}>"));
    for resource in resources {
        xml.push_str(&format!(
            "<{item} id=\"{}\"><name>{}</name>",
            resource.id,
            xml_escape(&resource.name)
        ));
        if detailed {
            if let Some(text) = resource.attr("text") {
                xml.push_str(&format!("<text>{}</text>", xml_escape(text)));
            }
            if let Some(severity) = resource.attr("new_severity") {
                xml.push_str(&format!(
                    "<new_severity>{}</new_severity>",
                    xml_escape(severity)
                ));
            }
        }
        xml.push_str(&format!("</{item}>"));
    }
    xml.push_str(&format!("</{collection}>"));
}
