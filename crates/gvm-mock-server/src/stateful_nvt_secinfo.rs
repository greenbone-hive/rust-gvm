// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful conformance behavior for NVT and SecInfo discovery.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use crate::command_parser::ParsedCommand;
use crate::response_gen::error_response;
use crate::store::{
    DiscoveryNvt, DiscoveryPreference, DiscoverySecInfo, DiscoverySnapshot, DiscoveryVulnerability,
    ResourceStore,
};
use crate::util::{xml_escape, xml_escape_attr};

const MAX_ROWS: usize = 100;
const INFO_TYPES: &[&str] = &["CERT_BUND_ADV", "CPE", "CVE", "DFN_CERT_ADV", "NVT"];

pub(crate) fn handle(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    handle_snapshot(cmd, &store.discovery_snapshot())
}

pub(crate) fn handle_fixture(cmd: &ParsedCommand) -> Vec<u8> {
    handle(cmd, &ResourceStore::new())
}

fn handle_snapshot(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    match cmd.name.as_str() {
        "get_nvts" => get_nvts(cmd, state),
        "get_nvt_families" => get_nvt_families(cmd, state),
        "get_preferences" => get_preferences(cmd, state),
        "get_info" => get_info(cmd, state),
        "get_vulns" => get_vulns(cmd, state),
        _ => error_response(&cmd.name, 400, "Unsupported discovery command"),
    }
}

fn get_nvts(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    if !state.nvt_feed_available {
        return error_response(&cmd.name, 503, "NVT feed is unavailable");
    }
    if let Err(message) = validate_nvt_attributes(cmd) {
        return error_response(&cmd.name, 400, &message);
    }
    let oid = cmd.attr("nvt_oid");
    let family = cmd.attr("family");
    let config_id = cmd.attr("config_id");
    let preference_config = cmd.attr("preferences_config_id");
    if config_id.is_some() && preference_config.is_some() {
        return error_response(
            &cmd.name,
            400,
            "config_id and preferences_config_id are mutually exclusive",
        );
    }
    if oid.is_some() && family.is_some() {
        return error_response(&cmd.name, 400, "nvt_oid and family are mutually exclusive");
    }
    if oid.is_none() && config_id.is_some() && family.is_none() {
        return error_response(&cmd.name, 400, "A config-scoped NVT list requires family");
    }
    let selected_config = config_id.or(preference_config);
    if let Some(config_id) = selected_config {
        if !state.config_nvts.contains_key(config_id)
            && !state.config_preferences.contains_key(config_id)
        {
            return error_response(&cmd.name, 404, "Scan configuration not found");
        }
    }

    let mut nvts: Vec<_> = state.nvts.values().cloned().collect();
    if let Some(oid) = oid {
        let Some(nvt) = state.nvts.get(oid) else {
            return error_response(&cmd.name, 404, "NVT not found");
        };
        // Detail selectors intentionally do not enforce config membership.
        nvts = vec![nvt.clone()];
    } else {
        if let Some(family) = family {
            nvts.retain(|nvt| nvt.family == family);
        }
        if let Some(config_id) = config_id {
            if let Some(members) = state.config_nvts.get(config_id) {
                nvts.retain(|nvt| members.contains(&nvt.oid));
            } else {
                nvts.clear();
            }
        }
    }

    let sort_field = cmd.attr("sort_field").unwrap_or("oid");
    nvts.sort_by(|left, right| {
        nvt_sort_value(left, sort_field).cmp(nvt_sort_value(right, sort_field))
    });
    if cmd.attr("sort_order") == Some("descending") {
        nvts.reverse();
    }
    let details = flag(cmd, "details");
    let lean = flag(cmd, "lean");
    let include_preferences = flag(cmd, "preferences");
    let include_preference_count = flag(cmd, "preference_count");
    let include_timeout = flag(cmd, "timeout");
    let config_values = selected_config.and_then(|id| state.config_preferences.get(id));
    let items: String = nvts
        .iter()
        .map(|nvt| {
            render_nvt(
                nvt,
                details,
                lean,
                !flag(cmd, "skip_tags"),
                !flag(cmd, "skip_cert_refs"),
                include_preferences,
                include_preference_count,
                include_timeout,
                config_values,
            )
        })
        .collect();
    let count = nvts.len();
    format!(
        "<get_nvts_response status=\"200\" status_text=\"OK\">{items}<nvt_count>{count}<filtered>{count}</filtered><page>{count}</page></nvt_count></get_nvts_response>"
    )
    .into_bytes()
}

fn validate_nvt_attributes(cmd: &ParsedCommand) -> Result<(), String> {
    for name in [
        "details",
        "preferences",
        "preference_count",
        "timeout",
        "lean",
        "skip_cert_refs",
        "skip_tags",
    ] {
        if cmd
            .attr(name)
            .is_some_and(|value| !matches!(value, "0" | "1"))
        {
            return Err(format!("Invalid boolean value for '{name}'"));
        }
    }
    let details = flag(cmd, "details");
    for name in [
        "preferences",
        "preference_count",
        "lean",
        "skip_cert_refs",
        "skip_tags",
    ] {
        if flag(cmd, name) && !details {
            return Err(format!("{name}=1 requires details=1"));
        }
    }
    if flag(cmd, "timeout")
        && (!details
            || (cmd.attr("config_id").is_none() && cmd.attr("preferences_config_id").is_none()))
    {
        return Err("timeout=1 requires details=1 and a configuration context".to_string());
    }
    if let Some(field) = cmd.attr("sort_field") {
        if !matches!(field, "oid" | "name" | "family") {
            return Err(format!("Unsupported NVT sort field '{field}'"));
        }
    }
    Ok(())
}

fn flag(cmd: &ParsedCommand, name: &str) -> bool {
    cmd.attr(name) == Some("1")
}

fn nvt_sort_value<'a>(nvt: &'a DiscoveryNvt, field: &str) -> &'a str {
    match field {
        "name" => &nvt.name,
        "family" => &nvt.family,
        _ => &nvt.oid,
    }
}

#[allow(clippy::too_many_arguments)]
fn render_nvt(
    nvt: &DiscoveryNvt,
    details: bool,
    lean: bool,
    tags: bool,
    cert_refs: bool,
    preferences: bool,
    preference_count: bool,
    timeout: bool,
    config_values: Option<&BTreeMap<String, String>>,
) -> String {
    let mut xml = format!(
        "<nvt oid=\"{}\"><name>{}</name>",
        xml_escape_attr(&nvt.oid),
        xml_escape(&nvt.name)
    );
    if details {
        xml.push_str(&format!("<family>{}</family>", xml_escape(&nvt.family)));
        if !lean {
            xml.push_str(&format!(
                "<cvss_base>{}</cvss_base><severity>{}</severity>",
                nvt.cvss_base,
                xml_escape(&nvt.severity)
            ));
        }
        if tags {
            xml.push_str(&format!("<tags>{}</tags>", xml_escape(&nvt.tags)));
        }
        xml.push_str(&format!(
            "<solution type=\"{}\">Mock solution</solution>",
            xml_escape_attr(&nvt.solution_type)
        ));
        if cert_refs {
            xml.push_str("<refs><ref type=\"cert\" id=\"MOCK-CERT\"/></refs>");
        }
        let visible: Vec<_> = nvt
            .preferences
            .iter()
            .filter(|preference| !excluded_preference(&preference.key))
            .collect();
        if preference_count {
            xml.push_str(&format!(
                "<preference_count>{}</preference_count>",
                visible.len()
            ));
        }
        if preferences {
            xml.push_str("<preferences>");
            for preference in visible {
                xml.push_str(&render_preference(nvt, preference, config_values));
            }
            xml.push_str("</preferences>");
        }
        if timeout {
            let configured = config_values
                .and_then(|values| values.get(&format!("{}:0:entry:timeout", nvt.oid)))
                .and_then(|value| value.parse::<u32>().ok())
                .unwrap_or(nvt.timeout);
            xml.push_str(&format!(
                "<timeout>{configured}</timeout><default_timeout>{}</default_timeout>",
                nvt.timeout
            ));
        }
    }
    xml.push_str("</nvt>");
    xml
}

fn get_nvt_families(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    if !state.nvt_feed_available {
        return error_response(&cmd.name, 503, "NVT feed is unavailable");
    }
    let descending = cmd.attr("sort_order") == Some("descending");
    let mut counts = BTreeMap::<String, usize>::new();
    for nvt in state.nvts.values() {
        *counts.entry(nvt.family.clone()).or_default() += 1;
    }
    let mut families: Vec<_> = counts.into_iter().collect();
    if descending {
        families.reverse();
    }
    let items: String = families
        .iter()
        .map(|(name, count)| {
            format!(
                "<family><name>{}</name><max_nvt_count>{count}</max_nvt_count></family>",
                xml_escape(name)
            )
        })
        .collect();
    let count = families.len();
    format!(
        "<get_nvt_families_response status=\"200\" status_text=\"OK\"><families>{items}</families><family_count>{count}<filtered>{count}</filtered></family_count></get_nvt_families_response>"
    )
    .into_bytes()
}

fn get_preferences(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    if !state.nvt_feed_available {
        return error_response(&cmd.name, 503, "NVT feed is unavailable");
    }
    let nvt_oid = cmd.attr("nvt_oid");
    if let Some(oid) = nvt_oid {
        if !state.nvts.contains_key(oid) {
            return error_response(&cmd.name, 404, "NVT not found");
        }
    }
    let config_id = cmd.attr("config_id");
    if let Some(id) = config_id {
        if !state.config_nvts.contains_key(id) && !state.config_preferences.contains_key(id) {
            return error_response(&cmd.name, 404, "Scan configuration not found");
        }
    }
    let values = config_id.and_then(|id| state.config_preferences.get(id));
    let selector = cmd.attr("preference");
    if selector.is_some_and(str::is_empty) {
        return error_response(&cmd.name, 400, "Preference selector must not be empty");
    }
    let mut candidates = Vec::new();
    for nvt in state.nvts.values() {
        if nvt_oid.is_some_and(|oid| oid != nvt.oid) {
            continue;
        }
        for preference in &nvt.preferences {
            if excluded_preference(&preference.key) {
                continue;
            }
            let suffix = preference_suffix(&preference.key);
            if selector.is_none_or(|selector| selector == suffix) {
                candidates.push((preference.key.clone(), Some(nvt), preference));
            }
        }
    }
    if nvt_oid.is_none() {
        for preference in &state.scanner_preferences {
            if !excluded_preference(&preference.key)
                && selector.is_none_or(|selector| selector == preference_suffix(&preference.key))
            {
                candidates.push((preference.key.clone(), None, preference));
            }
        }
    }
    candidates.sort_by(|left, right| left.0.cmp(&right.0));
    if selector.is_some() {
        candidates.truncate(1);
    }
    let items: String = candidates
        .into_iter()
        .map(|(_, nvt, preference)| match nvt {
            Some(nvt) => render_preference(nvt, preference, values),
            None => render_scanner_preference(preference, values),
        })
        .collect();
    format!(
        "<get_preferences_response status=\"200\" status_text=\"OK\">{items}</get_preferences_response>"
    )
    .into_bytes()
}

fn excluded_preference(key: &str) -> bool {
    if matches!(
        key,
        "cache_folder"
            | "include_folders"
            | "nasl_no_signature_check"
            | "network_targets"
            | "ntp_save_sessions"
            | "max_checks"
            | "max_hosts"
    ) {
        return true;
    }
    let lower = key.to_ascii_lowercase();
    lower.starts_with("server_info_") || lower.ends_with(":0:entry:timeout")
}

fn preference_suffix(key: &str) -> &str {
    key.split_once(':')
        .and_then(|(_, rest)| rest.split_once(':'))
        .map_or("", |(_, suffix)| suffix)
}

fn render_preference(
    nvt: &DiscoveryNvt,
    preference: &DiscoveryPreference,
    config_values: Option<&BTreeMap<String, String>>,
) -> String {
    render_preference_identity(&nvt.oid, &nvt.name, preference, config_values)
}

fn render_preference_identity(
    nvt_oid: &str,
    nvt_name: &str,
    preference: &DiscoveryPreference,
    config_values: Option<&BTreeMap<String, String>>,
) -> String {
    let mut fields = preference.key.splitn(4, ':');
    let _oid = fields.next();
    let id = fields.next().unwrap_or_default();
    let type_ = fields.next().unwrap_or_default();
    let name = fields.next().unwrap_or_default();
    let selected = config_values
        .and_then(|values| values.get(&preference.key))
        .or(preference.default.as_ref())
        .unwrap_or(&preference.value);
    let password = type_.eq_ignore_ascii_case("password");
    let mut xml = format!(
        "<preference><nvt oid=\"{}\"><name>{}</name></nvt><id>{}</id><hr_name>{}</hr_name><name>{}</name><type>{}</type><value>{}</value>",
        xml_escape_attr(nvt_oid),
        xml_escape(nvt_name),
        xml_escape(id),
        xml_escape(name),
        xml_escape(name),
        xml_escape(type_),
        if password { String::new() } else { xml_escape(selected) },
    );
    let default = preference.default.as_deref().unwrap_or_default();
    xml.push_str(&format!(
        "<default>{}</default>",
        if password {
            String::new()
        } else {
            xml_escape(default)
        }
    ));
    if type_.eq_ignore_ascii_case("radio") {
        for alternative in &preference.alternatives {
            if alternative != selected {
                xml.push_str(&format!("<alt>{}</alt>", xml_escape(alternative)));
            }
        }
    }
    xml.push_str("</preference>");
    xml
}

fn render_scanner_preference(
    preference: &DiscoveryPreference,
    config_values: Option<&BTreeMap<String, String>>,
) -> String {
    render_preference_identity("", "", preference, config_values)
}

fn get_info(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    if !state.secinfo_permitted {
        return error_response(&cmd.name, 403, "Permission denied for security information");
    }
    if !state.scap_available {
        return error_response(&cmd.name, 503, "The SCAP database is required");
    }
    if !state.cert_available {
        return error_response(&cmd.name, 503, "The CERT database is required");
    }
    let Some(info_type) = cmd.attr("type") else {
        return error_response(&cmd.name, 400, "Missing required SecInfo type");
    };
    let Some(info_type) = canonical_info_type(info_type) else {
        return error_response(&cmd.name, 400, "Unsupported SecInfo type");
    };
    if info_type == "NVT" && !state.nvt_feed_available {
        return error_response(&cmd.name, 503, "NVT feed is unavailable");
    }
    if cmd.attr("name").is_some() && cmd.attr("info_id").is_some() {
        return error_response(&cmd.name, 400, "name and info_id are mutually exclusive");
    }
    if cmd
        .attr("details")
        .is_some_and(|value| !matches!(value, "0" | "1"))
    {
        return error_response(&cmd.name, 400, "Invalid details value");
    }
    let mut entries: Vec<_> = state
        .secinfo
        .iter()
        .filter(|entry| entry.info_type.eq_ignore_ascii_case(info_type))
        .cloned()
        .collect();
    let total = entries.len();
    if let Some(id) = cmd.attr("info_id") {
        entries.retain(|entry| entry.id == id);
        if entries.is_empty() {
            return error_response(&cmd.name, 404, "Security information not found");
        }
    }
    if let Some(name) = cmd.attr("name") {
        entries.retain(|entry| entry.name == name);
    }
    let query = match effective_query(cmd, state) {
        Ok(query) => query,
        Err((status, message)) => return error_response(&cmd.name, status, &message),
    };
    let list_path = cmd.attr("info_id").is_none() && cmd.attr("name").is_none();
    if list_path {
        if let Err(message) = query.apply_info(&mut entries) {
            return error_response(&cmd.name, 400, &message);
        }
    }
    let filtered = entries.len();
    let entries = if list_path {
        query.page(entries)
    } else {
        entries
    };
    let page = entries.len();
    let element = info_element(info_type);
    let details = flag(cmd, "details");
    let items: String = entries
        .iter()
        .map(|entry| {
            let detail = if details {
                format!("<raw_data>mock {}</raw_data>", xml_escape(&entry.id))
            } else {
                String::new()
            };
            format!(
                "<info id=\"{}\"><name>{}</name><{element}>{detail}</{element}></info>",
                xml_escape_attr(&entry.id),
                xml_escape(&entry.name),
            )
        })
        .collect();
    format!(
        "<get_info_response status=\"200\" status_text=\"OK\">{items}<info_count>{total}<filtered>{filtered}</filtered><page>{page}</page></info_count></get_info_response>"
    )
    .into_bytes()
}

fn canonical_info_type(value: &str) -> Option<&'static str> {
    INFO_TYPES
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(value))
}

fn info_element(info_type: &str) -> &'static str {
    match info_type {
        "CERT_BUND_ADV" => "cert_bund_adv",
        "CPE" => "cpe",
        "CVE" => "cve",
        "DFN_CERT_ADV" => "dfn_cert_adv",
        "NVT" => "nvt",
        _ => unreachable!("validated SecInfo type"),
    }
}

fn get_vulns(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Vec<u8> {
    let query = match effective_query(cmd, state) {
        Ok(query) => query,
        Err((status, message)) => return error_response(&cmd.name, status, &message),
    };
    let mut entries = state.vulnerabilities.clone();
    let total = entries.len();
    let list_path = cmd.attr("vuln_id").is_none();
    if let Some(id) = cmd.attr("vuln_id") {
        entries.retain(|entry| entry.id == id);
        if entries.is_empty() {
            return error_response(&cmd.name, 404, "Observed vulnerability not found");
        }
    } else if let Err(message) = query.apply_vulnerabilities(&mut entries) {
        return error_response(&cmd.name, 400, &message);
    }
    let filtered = entries.len();
    let entries = if list_path {
        query.page(entries)
    } else {
        entries
    };
    let page = entries.len();
    let items: String = entries
        .iter()
        .map(|entry| {
            format!(
                "<vuln id=\"{}\"><name>{}</name><type>{}</type><severity>{:.1}</severity><qod>{}</qod><results><count>{}</count></results><hosts><count>{}</count></hosts></vuln>",
                xml_escape_attr(&entry.id),
                xml_escape(&entry.name),
                xml_escape(&entry.type_),
                entry.severity,
                entry.qod,
                entry.result_count,
                entry.host_count,
            )
        })
        .collect();
    format!(
        "<get_vulns_response status=\"200\" status_text=\"OK\">{items}<vuln_count>{total}<filtered>{filtered}</filtered><page>{page}</page></vuln_count></get_vulns_response>"
    )
    .into_bytes()
}

#[derive(Debug, Clone)]
struct Query {
    predicates: Vec<(String, String)>,
    first: usize,
    rows: usize,
    sort: String,
    reverse: bool,
}

impl Default for Query {
    fn default() -> Self {
        Self {
            predicates: Vec::new(),
            first: 1,
            rows: MAX_ROWS,
            sort: "id".to_string(),
            reverse: false,
        }
    }
}

fn effective_query(cmd: &ParsedCommand, state: &DiscoverySnapshot) -> Result<Query, (u16, String)> {
    let filter = match cmd.attr("filt_id") {
        None | Some("0") => cmd.attr("filter").unwrap_or_default(),
        Some("-2") => state.user_default_filter.as_deref().ok_or((
            400,
            "User-default discovery filter is not modeled".to_string(),
        ))?,
        Some(id) => state
            .saved_filters
            .get(id)
            .map(String::as_str)
            .ok_or((404, "Saved discovery filter not found".to_string()))?,
    };
    parse_query(filter).map_err(|message| (400, message))
}

fn parse_query(filter: &str) -> Result<Query, String> {
    let mut query = Query::default();
    for token in tokenize(filter)? {
        let Some((field, value)) = token.split_once('=') else {
            return Err(format!("Malformed discovery filter predicate '{token}'"));
        };
        if field.is_empty() || value.is_empty() {
            return Err(format!("Malformed discovery filter predicate '{token}'"));
        }
        match field {
            "first" => {
                query.first = value
                    .parse::<usize>()
                    .map_err(|_| "Invalid first value".to_string())?
                    .max(1);
            }
            "rows" => {
                let rows = value
                    .parse::<isize>()
                    .map_err(|_| "Invalid rows value".to_string())?;
                query.rows = if rows == -1 {
                    MAX_ROWS
                } else if rows < 0 {
                    return Err("Invalid rows value".to_string());
                } else {
                    (rows as usize).min(MAX_ROWS)
                };
            }
            "sort" | "sort-reverse" => {
                query.sort = value.to_string();
                query.reverse = field == "sort-reverse";
            }
            _ => query
                .predicates
                .push((field.to_string(), value.to_string())),
        }
    }
    Ok(query)
}

fn tokenize(filter: &str) -> Result<Vec<String>, String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    let mut quote = None;
    for character in filter.chars() {
        if matches!(character, '\'' | '"') {
            if quote == Some(character) {
                quote = None;
            } else if quote.is_none() {
                quote = Some(character);
            } else {
                current.push(character);
            }
        } else if character.is_whitespace() && quote.is_none() {
            if !current.is_empty() {
                tokens.push(std::mem::take(&mut current));
            }
        } else {
            current.push(character);
        }
    }
    if quote.is_some() {
        return Err("Malformed quoted discovery filter".to_string());
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    Ok(tokens)
}

impl Query {
    fn page<T>(&self, values: Vec<T>) -> Vec<T> {
        let start = self.first.saturating_sub(1).min(values.len());
        values.into_iter().skip(start).take(self.rows).collect()
    }

    fn apply_info(&self, entries: &mut Vec<DiscoverySecInfo>) -> Result<(), String> {
        for (field, value) in &self.predicates {
            match field.as_str() {
                "id" | "uuid" => entries.retain(|entry| entry.id == *value),
                "name" => entries.retain(|entry| entry.name == *value),
                "severity" => {
                    let severity = numeric(value, field)?;
                    entries.retain(|entry| entry.severity == Some(severity));
                }
                _ => return Err(format!("Unsupported SecInfo filter field '{field}'")),
            }
        }
        match self.sort.as_str() {
            "id" | "uuid" => entries.sort_by(|left, right| left.id.cmp(&right.id)),
            "name" => entries.sort_by(|left, right| left.name.cmp(&right.name)),
            "severity" => entries.sort_by(|left, right| {
                cmp_float(
                    left.severity.unwrap_or_default(),
                    right.severity.unwrap_or_default(),
                )
            }),
            field => return Err(format!("Unsupported SecInfo sort field '{field}'")),
        }
        if self.reverse {
            entries.reverse();
        }
        Ok(())
    }

    fn apply_vulnerabilities(
        &self,
        entries: &mut Vec<DiscoveryVulnerability>,
    ) -> Result<(), String> {
        for (field, value) in &self.predicates {
            match field.as_str() {
                "id" | "uuid" => entries.retain(|entry| entry.id == *value),
                "name" => entries.retain(|entry| entry.name == *value),
                "type" => entries.retain(|entry| entry.type_ == *value),
                "severity" => {
                    let severity = numeric(value, field)?;
                    entries.retain(|entry| entry.severity == severity);
                }
                "min_qod" => {
                    let qod = value
                        .parse::<u32>()
                        .map_err(|_| "Invalid min_qod value".to_string())?;
                    entries.retain(|entry| entry.qod >= qod);
                }
                "task_id" => entries.retain(|entry| entry.task_id.as_deref() == Some(value)),
                "report_id" => entries.retain(|entry| entry.report_id.as_deref() == Some(value)),
                "host" => entries.retain(|entry| entry.host.as_deref() == Some(value)),
                _ => return Err(format!("Unsupported vulnerability filter field '{field}'")),
            }
        }
        match self.sort.as_str() {
            "id" | "uuid" => entries.sort_by(|left, right| left.id.cmp(&right.id)),
            "name" => entries.sort_by(|left, right| left.name.cmp(&right.name)),
            "type" => entries.sort_by(|left, right| left.type_.cmp(&right.type_)),
            "severity" => entries.sort_by(|left, right| cmp_float(left.severity, right.severity)),
            "qod" | "min_qod" => entries.sort_by_key(|entry| entry.qod),
            field => return Err(format!("Unsupported vulnerability sort field '{field}'")),
        }
        if self.reverse {
            entries.reverse();
        }
        Ok(())
    }
}

fn numeric(value: &str, field: &str) -> Result<f64, String> {
    let number = value
        .parse::<f64>()
        .map_err(|_| format!("Invalid {field} value"))?;
    if !number.is_finite() {
        return Err(format!("Invalid {field} value"));
    }
    Ok(number)
}

fn cmp_float(left: f64, right: f64) -> Ordering {
    left.partial_cmp(&right).unwrap_or(Ordering::Equal)
}
