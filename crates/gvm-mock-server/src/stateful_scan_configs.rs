// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Bounded stateful scan-configuration and policy lifecycle behavior.

use std::collections::{BTreeMap, BTreeSet};

use uuid::Uuid;

use crate::command_parser::{ParsedCommand, ParsedElement};
use crate::response_gen::error_response;
use crate::store::{Resource, ResourceStore, StoreError};
use crate::util::{xml_escape, xml_escape_attr};

pub(crate) fn handle_create(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    if let Some(envelope) = child(cmd, "get_configs_response") {
        return create_import(cmd, envelope, store);
    }
    let Some(copy) = child(cmd, "copy") else {
        return error_response(
            &cmd.name,
            400,
            "Configuration creation requires copy or import",
        );
    };
    let Some(source_id) = copy.text.as_deref().filter(|value| !value.is_empty()) else {
        return error_response(&cmd.name, 400, "Missing configuration copy source");
    };
    let Ok(source_id) = Uuid::parse_str(source_id) else {
        return error_response(&cmd.name, 400, "Invalid configuration copy source");
    };
    let name = child(cmd, "name").map(element_text);
    let comment = child(cmd, "comment").map(element_text);
    let usage = child(cmd, "usage_type").map(element_text);
    match store.copy_config(&source_id, name, comment, usage) {
        Ok(id) => created_response(id, store),
        Err(error) => store_error(&cmd.name, &error),
    }
}

fn create_import(cmd: &ParsedCommand, envelope: &ParsedElement, store: &ResourceStore) -> Vec<u8> {
    let Some(config) = envelope
        .children
        .iter()
        .find(|child| child.name == "config")
    else {
        return error_response(&cmd.name, 400, "Import requires a direct config");
    };
    let Some(name) = child_element(config, "name")
        .map(element_text)
        .filter(|name| !name.is_empty())
    else {
        return error_response(&cmd.name, 400, "Imported config requires a name");
    };
    let Some(selectors) = child_element(config, "nvt_selectors") else {
        return error_response(&cmd.name, 400, "Imported config requires nvt_selectors");
    };
    let Some(preferences) = child_element(config, "preferences") else {
        return error_response(&cmd.name, 400, "Imported config requires preferences");
    };
    let nvts = match parse_selectors(selectors, store) {
        Ok(nvts) => nvts,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    let preferences = match parse_preferences(preferences, store) {
        Ok(preferences) => preferences,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    let comment = child_element(config, "comment")
        .map(element_text)
        .unwrap_or_default();
    let inner_usage = child_element(config, "usage_type")
        .map(element_text)
        .unwrap_or("scan");
    let outer_usage = child(cmd, "usage_type")
        .map(element_text)
        .filter(|usage| !usage.is_empty());
    let usage = outer_usage.unwrap_or(inner_usage);
    match store.import_config(name, comment, usage, nvts, preferences) {
        Ok(id) => created_response(id, store),
        Err(error) => store_error(&cmd.name, &error),
    }
}

fn parse_selectors(
    selectors: &ParsedElement,
    store: &ResourceStore,
) -> Result<BTreeSet<String>, &'static str> {
    let discovery = store.discovery_snapshot();
    if selectors
        .children
        .iter()
        .any(|selector| selector.name == "all_selector")
    {
        return Ok(discovery.nvts.keys().cloned().collect());
    }
    let mut selected = BTreeSet::new();
    for selector in &selectors.children {
        if selector.name == "nvt" {
            let oid = selector
                .attributes
                .get("oid")
                .map(String::as_str)
                .or(selector.text.as_deref())
                .filter(|oid| !oid.is_empty())
                .ok_or("Mock limitation: NVT selector requires an OID")?;
            if !discovery.nvts.contains_key(oid) {
                return Err("Mock limitation: selector references an unseeded NVT");
            }
            selected.insert(oid.to_string());
            continue;
        }
        if selector.name != "nvt_selector" {
            return Err("Mock limitation: unsupported selector shape");
        }
        let target = child_element(selector, "family_or_nvt")
            .or_else(|| child_element(selector, "name"))
            .map(element_text)
            .filter(|target| !target.is_empty())
            .ok_or("Mock limitation: selector target is required")?;
        let include = child_element(selector, "include")
            .map(element_text)
            .is_none_or(|value| value != "0");
        let members: Vec<_> = if discovery.nvts.contains_key(target) {
            vec![target.to_string()]
        } else {
            let members: Vec<_> = discovery
                .nvts
                .values()
                .filter(|nvt| nvt.family == target)
                .map(|nvt| nvt.oid.clone())
                .collect();
            if members.is_empty() {
                return Err("Mock limitation: selector references an unseeded family");
            }
            members
        };
        for oid in members {
            if include {
                selected.insert(oid);
            } else {
                selected.remove(&oid);
            }
        }
    }
    Ok(selected)
}

fn parse_preferences(
    preferences: &ParsedElement,
    store: &ResourceStore,
) -> Result<BTreeMap<String, String>, &'static str> {
    let discovery = store.discovery_snapshot();
    let mut stored = BTreeMap::new();
    for preference in &preferences.children {
        if preference.name != "preference" {
            return Err("Mock limitation: unsupported preference shape");
        }
        let nvt_oid = child_element(preference, "nvt")
            .and_then(|nvt| nvt.attributes.get("oid"))
            .map(String::as_str)
            .unwrap_or_default();
        let id = child_element(preference, "id")
            .map(element_text)
            .unwrap_or_default();
        if !nvt_oid.is_empty() && id.is_empty() {
            return Err("NVT preferences require a nonempty ID");
        }
        if !nvt_oid.is_empty() && !discovery.nvts.contains_key(nvt_oid) {
            return Err("Mock limitation: preference references an unseeded NVT");
        }
        let mut name = child_element(preference, "name")
            .map(element_text)
            .unwrap_or_default()
            .to_string();
        let mut type_ = child_element(preference, "type")
            .map(element_text)
            .unwrap_or_default()
            .to_string();
        if !nvt_oid.is_empty() && (name.is_empty() || type_.is_empty()) {
            let prefix = format!("{nvt_oid}:{id}:");
            let definition = discovery.nvts.get(nvt_oid).and_then(|nvt| {
                nvt.preferences
                    .iter()
                    .find(|item| item.key.starts_with(&prefix))
            });
            let Some(definition) = definition else {
                return Err("Mock limitation: preference needs seeded feed metadata");
            };
            let mut definition_parts = definition.key[prefix.len()..].splitn(2, ':');
            let definition_type = definition_parts.next().unwrap_or_default();
            let definition_name = definition_parts.next().unwrap_or_default();
            if type_.is_empty() {
                type_ = definition_type.to_string();
            }
            if name.is_empty() {
                name = definition_name.to_string();
            }
        }
        let value = child_element(preference, "value").map(element_text);
        if nvt_oid.is_empty() && value.is_none() {
            continue;
        }
        let key = format!("{nvt_oid}:{id}:{type_}:{name}");
        stored.insert(key, value.unwrap_or_default().to_string());
    }
    Ok(stored)
}

pub(crate) fn handle_get(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let trash = flag(cmd.attr("trash"));
    let details = flag(cmd.attr("details"));
    let families = flag(cmd.attr("families"));
    let preferences = flag(cmd.attr("preferences"));
    let tasks = flag(cmd.attr("tasks"));
    if trash && (details || families || preferences || tasks) {
        return error_response(
            &cmd.name,
            400,
            "Mock limitation: expanded trash configuration queries are not modeled",
        );
    }
    let mut configs = if trash {
        store.list_trashed("config")
    } else {
        store.list("config")
    };
    configs.sort_by_key(|config| config.name.clone());

    if let Some(id) = cmd.attr("config_id") {
        let Ok(id) = Uuid::parse_str(id) else {
            return error_response(&cmd.name, 400, "Invalid config_id");
        };
        configs.retain(|config| config.id == id);
        if configs.is_empty() {
            return error_response(&cmd.name, 404, "Failed to find config");
        }
        let total = configs.len();
        return get_response(
            &configs,
            total,
            total,
            details,
            families,
            preferences,
            tasks,
            store,
        );
    }

    if let Some(usage) = cmd.attr("usage_type").filter(|usage| !usage.is_empty()) {
        configs.retain(|config| config.attr("usage_type") == Some(usage));
    }
    let total = configs.len();
    let filter = match selected_filter(cmd, store) {
        Ok(filter) => filter,
        Err(message) => return error_response(&cmd.name, 400, message),
    };
    let spec = FilterSpec::parse(filter.as_deref().unwrap_or_default());
    configs.retain(|config| spec.matches(config));
    let filtered = configs.len();
    spec.sort(&mut configs);
    let configs = spec.page(configs);
    get_response(
        &configs,
        total,
        filtered,
        details,
        families,
        preferences,
        tasks,
        store,
    )
}

fn get_response(
    configs: &[Resource],
    total: usize,
    filtered: usize,
    details: bool,
    families: bool,
    preferences: bool,
    tasks: bool,
    store: &ResourceStore,
) -> Vec<u8> {
    let page = configs.len();
    let items: String = configs
        .iter()
        .map(|config| render_config(config, details, families, preferences, tasks, store))
        .collect();
    format!(
        "<get_configs_response status=\"200\" status_text=\"OK\">{items}<config_count>{total}<filtered>{filtered}</filtered><page>{page}</page></config_count></get_configs_response>"
    )
    .into_bytes()
}

fn render_config(
    config: &Resource,
    details: bool,
    families: bool,
    preferences: bool,
    tasks: bool,
    store: &ResourceStore,
) -> String {
    let (nvts, configured_preferences) = store.config_observation(&config.id);
    let discovery = store.discovery_snapshot();
    let family_names: BTreeSet<_> = nvts
        .iter()
        .filter_map(|oid| discovery.nvts.get(oid).map(|nvt| nvt.family.clone()))
        .collect();
    let mut xml = format!(
        "<config id=\"{}\"><owner><name>admin</name></owner><name>{}</name><comment>{}</comment><creation_time>{}</creation_time><modification_time>{}</modification_time><writable>{}</writable><in_use>{}</in_use><usage_type>{}</usage_type><type>0</type><predefined>{}</predefined><family_count>{}<growing>0</growing></family_count><nvt_count>{}<growing>0</growing></nvt_count>",
        config.id,
        xml_escape(&config.name),
        xml_escape(&config.comment),
        config.creation_time,
        config.modification_time,
        if config.attr("predefined") == Some("1") { "0" } else { "1" },
        if store.config_tasks(&config.id, false).is_empty() { "0" } else { "1" },
        xml_escape(config.attr("usage_type").unwrap_or("scan")),
        config.attr("predefined").unwrap_or("0"),
        family_names.len(),
        nvts.len(),
    );
    if families || details {
        xml.push_str("<families>");
        for family in &family_names {
            let count = nvts
                .iter()
                .filter(|oid| {
                    discovery
                        .nvts
                        .get(*oid)
                        .is_some_and(|nvt| &nvt.family == family)
                })
                .count();
            xml.push_str(&format!(
                "<family><name>{}</name><nvt_count>{count}<growing>0</growing></nvt_count></family>",
                xml_escape(family)
            ));
        }
        xml.push_str("</families>");
    }
    if preferences || details {
        xml.push_str("<preferences>");
        for (key, value) in &configured_preferences {
            let mut parts = key.splitn(4, ':');
            let oid = parts.next().unwrap_or_default();
            let id = parts.next().unwrap_or_default();
            let type_ = parts.next().unwrap_or_default();
            let name = parts.next().unwrap_or_default();
            xml.push_str("<preference>");
            if !oid.is_empty() {
                xml.push_str(&format!("<nvt oid=\"{}\"/>", xml_escape_attr(oid)));
            }
            xml.push_str(&format!(
                "<id>{}</id><name>{}</name><type>{}</type><value>{}</value>",
                xml_escape(id),
                xml_escape(name),
                xml_escape(type_),
                xml_escape(value)
            ));
            if let Some(definition) = discovery.nvts.get(oid).and_then(|nvt| {
                nvt.preferences
                    .iter()
                    .find(|preference| preference.key == *key)
            }) {
                if let Some(default) = &definition.default {
                    xml.push_str(&format!("<default>{}</default>", xml_escape(default)));
                }
                for alternative in &definition.alternatives {
                    xml.push_str(&format!("<alt>{}</alt>", xml_escape(alternative)));
                }
            }
            xml.push_str("</preference>");
        }
        xml.push_str("</preferences>");
    }
    if details {
        xml.push_str("<nvt_selectors>");
        for oid in &nvts {
            xml.push_str(&format!(
                "<nvt_selector><include>1</include><type>2</type><family_or_nvt>{}</family_or_nvt></nvt_selector>",
                xml_escape(oid)
            ));
        }
        xml.push_str("</nvt_selectors>");
    }
    if tasks {
        xml.push_str("<tasks>");
        for task in store
            .config_tasks(&config.id, config.trashed)
            .into_iter()
            .filter(|task| task.attr("visible") != Some("0"))
        {
            xml.push_str(&format!(
                "<task id=\"{}\"><name>{}</name></task>",
                task.id,
                xml_escape(&task.name)
            ));
        }
        xml.push_str("</tasks>");
    }
    xml.push_str("</config>");
    xml
}

pub(crate) fn handle_modify(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    if cmd.children.iter().any(|child| {
        matches!(
            child.name.as_str(),
            "preference" | "nvt_selection" | "family_selection"
        )
    }) {
        return error_response(
            &cmd.name,
            400,
            "Mock limitation: configured preference and selection mutations are deferred",
        );
    }
    let Some(id) = cmd.attr("config_id") else {
        return error_response(&cmd.name, 400, "Missing config_id");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return error_response(&cmd.name, 400, "Invalid config_id");
    };
    let name = child(cmd, "name").map(element_text);
    let comment = child(cmd, "comment").map(element_text);
    match store.modify_config_metadata(&id, name, comment) {
        Ok(()) => b"<modify_config_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, &error),
    }
}

pub(crate) fn handle_delete(cmd: &ParsedCommand, store: &ResourceStore) -> Vec<u8> {
    let Some(id) = cmd.attr("config_id") else {
        return error_response(&cmd.name, 400, "Missing config_id");
    };
    let Ok(id) = Uuid::parse_str(id) else {
        return error_response(&cmd.name, 400, "Invalid config_id");
    };
    let ultimate = flag(cmd.attr("ultimate"));
    match store.delete_config_lifecycle(&id, ultimate) {
        Ok(()) => b"<delete_config_response status=\"200\" status_text=\"OK\"/>".to_vec(),
        Err(error) => store_error(&cmd.name, &error),
    }
}

fn created_response(id: Uuid, store: &ResourceStore) -> Vec<u8> {
    let name = store
        .get_typed(&id, "config")
        .map(|config| config.name)
        .unwrap_or_default();
    format!(
        "<create_config_response status=\"201\" status_text=\"OK, resource created\" id=\"{id}\"><config><name>{}</name></config></create_config_response>",
        xml_escape(&name)
    )
    .into_bytes()
}

fn selected_filter(
    cmd: &ParsedCommand,
    store: &ResourceStore,
) -> Result<Option<String>, &'static str> {
    if let Some(filter) = cmd.attr("filter") {
        return Ok(Some(filter.to_string()));
    }
    let Some(filter_id) = cmd.attr("filt_id") else {
        return Ok(None);
    };
    match filter_id {
        "0" => Ok(Some(String::new())),
        "-2" => Ok(Some("sort=name".to_string())),
        id => {
            let Ok(id) = Uuid::parse_str(id) else {
                return Err("Mock limitation: unresolved saved configuration filter");
            };
            store
                .get_typed(&id, "filter")
                .and_then(|filter| filter.attr("term").map(str::to_string))
                .map(Some)
                .ok_or("Mock limitation: unresolved saved configuration filter")
        }
    }
}

#[derive(Default)]
struct FilterSpec {
    name_exact: Option<String>,
    name_contains: Option<String>,
    id: Option<String>,
    usage: Option<String>,
    sort: Option<String>,
    descending: bool,
    first: usize,
    rows: Option<usize>,
}

impl FilterSpec {
    fn parse(filter: &str) -> Self {
        let mut spec = Self {
            first: 1,
            ..Self::default()
        };
        for term in filter.split_whitespace() {
            if let Some(value) = term.strip_prefix("name=") {
                spec.name_exact = Some(value.to_string());
            } else if let Some(value) = term.strip_prefix("name~") {
                spec.name_contains = Some(value.to_string());
            } else if let Some(value) = term.strip_prefix("id=") {
                spec.id = Some(value.to_string());
            } else if let Some(value) = term.strip_prefix("usage_type=") {
                spec.usage = Some(value.to_string());
            } else if let Some(value) = term.strip_prefix("sort-reverse=") {
                spec.sort = Some(value.to_string());
                spec.descending = true;
            } else if let Some(value) = term.strip_prefix("sort=") {
                spec.sort = Some(value.to_string());
            } else if let Some(value) = term.strip_prefix("first=") {
                spec.first = value.parse().unwrap_or(1).max(1);
            } else if let Some(value) = term.strip_prefix("rows=") {
                spec.rows = (value != "-1").then(|| value.parse().unwrap_or(0));
            }
        }
        spec
    }

    fn matches(&self, config: &Resource) -> bool {
        self.name_exact
            .as_deref()
            .is_none_or(|name| config.name == name)
            && self
                .name_contains
                .as_deref()
                .is_none_or(|name| config.name.contains(name))
            && self
                .id
                .as_deref()
                .is_none_or(|id| config.id.to_string() == id)
            && self
                .usage
                .as_deref()
                .is_none_or(|usage| config.attr("usage_type") == Some(usage))
    }

    fn sort(&self, configs: &mut [Resource]) {
        match self.sort.as_deref() {
            Some("id") => configs.sort_by_key(|config| config.id),
            Some("usage_type") => configs
                .sort_by_key(|config| config.attr("usage_type").unwrap_or_default().to_string()),
            _ => configs.sort_by_key(|config| config.name.clone()),
        }
        if self.descending {
            configs.reverse();
        }
    }

    fn page(&self, configs: Vec<Resource>) -> Vec<Resource> {
        let mut start = self.first.saturating_sub(1);
        if start >= configs.len() && !configs.is_empty() {
            start = 0;
        }
        let rows = self.rows.unwrap_or(configs.len());
        configs.into_iter().skip(start).take(rows).collect()
    }
}

fn child<'a>(cmd: &'a ParsedCommand, name: &str) -> Option<&'a ParsedElement> {
    cmd.children.iter().find(|child| child.name == name)
}

fn child_element<'a>(element: &'a ParsedElement, name: &str) -> Option<&'a ParsedElement> {
    element.children.iter().find(|child| child.name == name)
}

fn element_text(element: &ParsedElement) -> &str {
    element.text.as_deref().unwrap_or_default()
}

fn flag(value: Option<&str>) -> bool {
    value.is_some_and(|value| value == "1" || value.eq_ignore_ascii_case("true"))
}

fn store_error(command: &str, error: &StoreError) -> Vec<u8> {
    match error {
        StoreError::NotFound(_) => error_response(command, 404, "Failed to find config"),
        StoreError::InUse(_) => error_response(command, 400, "Configuration is in use"),
        StoreError::InvalidArgument(message)
        | StoreError::InvalidState(message)
        | StoreError::Inconsistent(message) => error_response(command, 400, message),
    }
}
