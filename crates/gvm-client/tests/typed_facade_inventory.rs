// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

const INTEGRATION_COVERED: &[&str] = &[
    "get_version",
    "authenticate",
    "get_agents",
    "get_agent",
    "modify_agent",
    "delete_agent",
    "sync_agents",
    "modify_agent_control_scan_config",
    "get_agent_installer_instruction",
    "get_agent_support_bundle",
    "get_targets",
    "get_target",
    "create_target",
    "modify_target",
    "delete_target",
    "create_oci_image_target",
    "clone_oci_image_target",
    "get_oci_image_target",
    "get_oci_image_targets",
    "modify_oci_image_target",
    "delete_oci_image_target",
    "create_web_application_target",
    "clone_web_application_target",
    "get_web_application_target",
    "get_web_application_targets",
    "modify_web_application_target",
    "delete_web_application_target",
    "create_agent_group",
    "clone_agent_group",
    "get_agent_group",
    "get_agent_groups",
    "modify_agent_group",
    "delete_agent_group",
    "get_scan_configs",
    "create_scan_config",
    "import_scan_config",
    "get_scan_config",
    "get_policies",
    "get_policy",
    "import_policy",
    "modify_scan_config",
    "modify_scan_config_set_name",
    "modify_scan_config_set_comment",
    "modify_policy_set_name",
    "modify_policy_set_comment",
    "delete_scan_config",
    "clone_scan_config",
    "get_scanners",
    "create_scanner",
    "get_scanner",
    "modify_scanner",
    "delete_scanner",
    "verify_scanner",
    "clone_scanner",
    "get_port_lists",
    "get_port_list",
    "create_port_list",
    "clone_port_list",
    "modify_port_list",
    "delete_port_list",
    "create_port_range",
    "delete_port_range",
    "get_tasks",
    "get_task",
    "create_task",
    "clone_task",
    "create_import_task",
    "create_container_task",
    "create_agent_group_task",
    "create_oci_image_target_task",
    "create_container_image_task",
    "create_web_application_task",
    "move_task",
    "get_audits",
    "get_audit",
    "create_audit",
    "clone_audit",
    "modify_audit",
    "delete_audit",
    "start_audit",
    "stop_audit",
    "resume_audit",
    "start_task",
    "resume_task",
    "modify_task",
    "stop_task",
    "delete_task",
    "empty_trashcan",
    "restore",
    "get_reports",
    "get_report",
    "get_audit_reports",
    "get_scan_report",
    "delete_report",
    "delete_audit_report",
    "get_audit_report",
    "get_audit_report_hosts",
    "get_report_hosts",
    "get_report_ports",
    "get_report_applications",
    "get_report_operating_systems",
    "get_report_cves",
    "get_report_vulns",
    "get_report_tls_certificates",
    "get_report_errors",
    "get_report_closed_cves",
    "get_report_export",
    "export_scan_report",
    "get_results",
    "get_result",
    "get_feeds",
    "get_feed",
    "get_timezones",
    "get_credential_stores",
    "verify_credential_store",
    "get_credential_store",
    "get_nvts",
    "get_nvt",
    "get_scan_config_nvts",
    "get_scan_config_nvt",
    "get_nvt_preferences",
    "get_nvt_preference",
    "get_nvt_families",
    "get_info",
    "get_info_list",
    "get_cves",
    "get_cve",
    "get_cpes",
    "get_cpe",
    "get_cert_bund_advisories",
    "get_cert_bund_advisory",
    "get_dfn_cert_advisories",
    "get_dfn_cert_advisory",
    "get_vulnerabilities",
    "get_vulnerability",
    "get_alerts",
    "get_alert",
    "create_alert",
    "clone_alert",
    "modify_alert",
    "delete_alert",
    "test_alert",
    "trigger_alert",
    "get_credentials",
    "create_credential",
    "modify_credential",
    "delete_credential",
    "create_credential_store_credential",
    "modify_credential_store_credential",
    "get_filters",
    "get_filter",
    "create_filter",
    "clone_filter",
    "modify_filter",
    "delete_filter",
    "get_notes",
    "get_note",
    "create_note",
    "clone_note",
    "modify_note",
    "delete_note",
    "get_overrides",
    "get_override",
    "create_override",
    "clone_override",
    "modify_override",
    "delete_override",
    "get_schedules",
    "get_schedule",
    "create_schedule",
    "clone_schedule",
    "modify_schedule",
    "delete_schedule",
    "get_tags",
    "get_tag",
    "create_tag",
    "clone_tag",
    "modify_tag",
    "delete_tag",
    "get_tickets",
    "create_ticket",
    "modify_ticket",
    "get_users",
    "get_user",
    "create_user",
    "clone_user",
    "modify_user",
    "delete_user",
    "get_groups",
    "get_group",
    "create_group",
    "clone_group",
    "modify_group",
    "delete_group",
    "get_roles",
    "get_role",
    "create_role",
    "clone_role",
    "modify_role",
    "delete_role",
    "get_permissions",
    "get_permission",
    "create_permission",
    "clone_permission",
    "modify_permission",
    "delete_permission",
    "get_hosts",
    "get_host",
    "create_host",
    "modify_host",
    "delete_host",
    "get_integration_config",
    "get_integration_configs",
    "modify_integration_config",
    "get_assets",
    "get_asset",
    "create_asset",
    "modify_asset",
    "delete_asset",
    "get_operating_system_assets",
    "get_operating_system_asset",
    "delete_operating_system_asset",
    "get_configs",
    "get_config",
    "create_config",
    "clone_config",
    "modify_config",
    "delete_config",
    "get_tls_certificates",
    "get_tls_certificate",
    "create_tls_certificate",
    "clone_tls_certificate",
    "modify_tls_certificate",
    "delete_tls_certificate",
    "get_report_formats",
    "get_report_format",
    "clone_report_format",
    "import_report_format",
    "modify_report_format",
    "delete_report_format",
    "verify_report_format",
    "import_report",
    "get_report_configs",
    "get_report_config",
    "create_report_config",
    "clone_report_config",
    "modify_report_config",
    "delete_report_config",
    "get_aggregates",
    "get_legacy_aggregates",
    "get_features",
    "get_settings",
    "get_system_reports",
    "get_help",
    "describe_auth",
    "get_resource_names",
    "get_resource_name",
    "get_license",
    "modify_auth",
    "modify_license",
    "run_wizard",
];

// Kept explicit so each public helper has exactly one of the three issue #398
// classifications. There are no signature-only exceptions in the current
// parser-returning facade and no known integration gaps.
const COMPILE_ONLY: &[&str] = &[];
const REQUIRES_INTEGRATION: &[&str] = &[];

const FROZEN_TICKET_HELPERS: [&str; 3] = ["create_ticket", "get_tickets", "modify_ticket"];

#[derive(Debug)]
struct TypedMethod {
    name: String,
    source: PathBuf,
    signature: String,
    body: String,
}

fn typed_facade_sources() -> Vec<(PathBuf, String)> {
    let source_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut paths = vec![source_root.join("typed.rs")];
    paths.extend(
        fs::read_dir(source_root.join("typed"))
            .expect("typed facade module directory should be readable")
            .map(|entry| {
                entry
                    .expect("typed facade module entry should be readable")
                    .path()
            })
            .filter(|path| path.extension().is_some_and(|extension| extension == "rs")),
    );
    paths.sort();
    paths
        .into_iter()
        .map(|path| {
            let source = fs::read_to_string(&path).unwrap_or_else(|error| {
                panic!(
                    "failed to read typed facade source {}: {error}",
                    path.display()
                )
            });
            (path, source)
        })
        .collect()
}

fn public_typed_methods() -> BTreeSet<String> {
    let mut methods = BTreeSet::new();
    for (path, source) in typed_facade_sources() {
        for method in source.lines().filter_map(|line| {
            line.trim_start()
                .strip_prefix("pub async fn ")
                .and_then(|rest| rest.split('(').next())
        }) {
            assert!(
                methods.insert(method.to_string()),
                "{method} is declared in more than one typed facade module; duplicate found in {}",
                path.display()
            );
        }
    }
    methods
}

fn method_end(source: &str, body_start: usize, path: &Path, method: &str) -> usize {
    let mut depth = 0_usize;
    for (offset, byte) in source.as_bytes()[body_start..].iter().enumerate() {
        match byte {
            b'{' => depth += 1,
            b'}' => {
                depth = depth.checked_sub(1).unwrap_or_else(|| {
                    panic!("unbalanced method body for {method} in {}", path.display())
                });
                if depth == 0 {
                    return body_start + offset + 1;
                }
            }
            _ => {}
        }
    }
    panic!(
        "unterminated method body for {method} in {}",
        path.display()
    );
}

fn typed_methods() -> Vec<TypedMethod> {
    let mut methods = Vec::new();
    for (path, source) in typed_facade_sources() {
        let mut offset = 0_usize;
        while let Some(relative_start) = source[offset..].find("pub async fn ") {
            let start = offset + relative_start;
            let name_start = start + "pub async fn ".len();
            let name_end = source[name_start..]
                .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
                .map(|relative| name_start + relative)
                .expect("public typed method name should terminate");
            let name = source[name_start..name_end].to_string();
            let body_start = source[start..]
                .find('{')
                .map(|relative| start + relative)
                .unwrap_or_else(|| panic!("{name} in {} has no body", path.display()));
            let end = method_end(&source, body_start, &path, &name);
            methods.push(TypedMethod {
                name,
                source: path.clone(),
                signature: source[start..body_start].to_string(),
                body: source[body_start..end].to_string(),
            });
            offset = end;
        }
    }
    methods
}

fn normalized_integration_sources() -> String {
    [
        include_str!("audit_integration.rs"),
        include_str!("client_integration.rs"),
        include_str!("report_config_integration.rs"),
        include_str!("report_format_canonical_integration.rs"),
        include_str!("scan_config_policy_canonical_integration.rs"),
        include_str!("structured_audit_report_integration.rs"),
        include_str!("tls_certificate_canonical_integration.rs"),
        include_str!("tls_certificate_integration.rs"),
        include_str!("typed_facade_coverage.rs"),
        include_str!("versioned_client.rs"),
    ]
    .concat()
    .chars()
    .filter(|ch| !ch.is_whitespace())
    .collect()
}

#[test]
fn every_public_typed_helper_has_exactly_one_enforced_classification() {
    let public = public_typed_methods();
    assert_eq!(public.len(), 261);
    let mut classified = BTreeSet::new();

    for (class, methods) in [
        ("integration covered", INTEGRATION_COVERED),
        ("compile only", COMPILE_ONLY),
        ("requires integration", REQUIRES_INTEGRATION),
    ] {
        for method in methods {
            assert!(
                classified.insert((*method).to_string()),
                "{method} appears in more than one typed-facade classification ({class})"
            );
        }
    }

    assert_eq!(
        classified, public,
        "update the typed-facade coverage inventory for every added or removed public helper"
    );
    assert!(
        REQUIRES_INTEGRATION.is_empty(),
        "typed facade still has helpers requiring integration coverage: {REQUIRES_INTEGRATION:?}"
    );
}

#[test]
fn execution_paths_preserve_the_typed_facade_contract() {
    let methods = typed_methods();
    assert_eq!(methods.len(), 261);

    let mut execute_helpers = BTreeSet::new();
    let mut raw_helpers = BTreeSet::new();
    for method in &methods {
        let execute_count = method.body.matches("self.execute(request).await").count();
        let send_count = method.body.matches("self.send(").count();
        assert!(
            !method.body.contains("self.call("),
            "typed helper {} in {} must not introduce a raw call path",
            method.name,
            method.source.display()
        );

        if FROZEN_TICKET_HELPERS.contains(&method.name.as_str()) {
            assert_eq!(
                execute_count, 0,
                "ticket helper {} migrated unexpectedly",
                method.name
            );
            assert_eq!(
                send_count, 1,
                "ticket helper {} must keep one raw send",
                method.name
            );
            assert_eq!(
                method.source.file_name().and_then(|name| name.to_str()),
                Some("tickets.rs")
            );
            raw_helpers.insert(method.name.clone());
        } else {
            assert!(
                method.signature.contains("request:") && method.signature.contains("Request"),
                "non-ticket helper {} in {} must accept one canonical request value",
                method.name,
                method.source.display()
            );
            assert_eq!(
                execute_count,
                1,
                "non-ticket helper {} in {} must delegate exactly once to execute",
                method.name,
                method.source.display()
            );
            assert_eq!(
                send_count,
                0,
                "non-ticket helper {} in {} must not use raw send",
                method.name,
                method.source.display()
            );
            execute_helpers.insert(method.name.clone());
        }
    }

    assert_eq!(execute_helpers.len(), 258);
    assert_eq!(
        raw_helpers,
        FROZEN_TICKET_HELPERS.map(str::to_string).into()
    );

    let sources = typed_facade_sources();
    let scan = sources
        .iter()
        .find(|(path, _)| path.file_name().is_some_and(|name| name == "scan.rs"))
        .map(|(_, source)| source)
        .expect("scan facade module should be discovered");
    assert!(!scan.contains("pub async fn sync_config("));
    assert!(!scan.contains("pub async fn sync_scan_config("));
}

#[test]
fn integration_classification_requires_a_direct_client_test_call() {
    let integration_sources = normalized_integration_sources();

    for method in INTEGRATION_COVERED {
        let call = format!(".{method}(");
        assert!(
            integration_sources.contains(&call),
            "{method} is classified as integration covered but has no direct client test call"
        );
    }
}
