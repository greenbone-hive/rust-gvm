// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const LEDGER_PATH: &str = "docs/canonical-request-disposition.tsv";
const UPDATE_ENV: &str = "UPDATE_CANONICAL_REQUEST_DISPOSITION";
const MIGRATION_GUIDE_PATH: &str = "docs/v0.7.0-migration.md";

const V06_REMOVED_FACADES: [&str; 32] = [
    "clone_oci_image_target_parsed",
    "clone_web_application_target_parsed",
    "create_oci_image_target_parsed",
    "create_report_format",
    "create_typed_schedule",
    "create_web_application_target_parsed",
    "delete_oci_image_target_parsed",
    "delete_web_application_target_parsed",
    "get_credential_stores_with_opts",
    "get_features_parsed",
    "get_help_with_mode",
    "get_integration_config_parsed",
    "get_integration_configs_parsed",
    "get_oci_image_target_parsed",
    "get_oci_image_targets_parsed",
    "get_report_applications_parsed",
    "get_report_configs_parsed",
    "get_report_cves_parsed",
    "get_report_export_with_opts",
    "get_report_hosts_parsed",
    "get_report_operating_systems_parsed",
    "get_report_ports_parsed",
    "get_report_vulnerabilities",
    "get_web_application_target_parsed",
    "get_web_application_targets_parsed",
    "modify_integration_config_parsed",
    "modify_oci_image_target_parsed",
    "modify_typed_schedule",
    "modify_web_application_target_parsed",
    "restore_from_trashcan",
    "sync_config",
    "sync_scan_config",
];

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Surface {
    kind: String,
    source: String,
    symbol: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Disposition {
    value: String,
    rationale: String,
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("workspace root should exist")
}

fn rust_sources(directory: &Path) -> Vec<PathBuf> {
    let mut sources = fs::read_dir(directory)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", directory.display()))
        .map(|entry| {
            entry
                .expect("source directory entry should be readable")
                .path()
        })
        .filter(|path| path.extension().is_some_and(|extension| extension == "rs"))
        .collect::<Vec<_>>();
    sources.sort();
    sources
}

fn identifier_after<'a>(line: &'a str, prefix: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(prefix)?;
    let length = rest
        .find(|character: char| !(character.is_ascii_alphanumeric() || character == '_'))
        .unwrap_or(rest.len());
    (length > 0).then_some(&rest[..length])
}

fn relative_source(root: &Path, source: &Path) -> String {
    source
        .strip_prefix(root)
        .expect("inventory source should be inside the workspace")
        .to_string_lossy()
        .replace('\\', "/")
}

fn collect_command_surfaces(root: &Path, surfaces: &mut BTreeSet<Surface>) {
    let directory = root.join("crates/gvm-gmp/src/commands");
    for source in rust_sources(&directory) {
        let relative = relative_source(root, &source);
        let contents = fs::read_to_string(&source)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));

        for line in contents.lines() {
            if let Some(symbol) = identifier_after(line, "pub struct ") {
                let kind = if symbol.ends_with("Opts") {
                    Some("options")
                } else if symbol.ends_with("Request") {
                    Some("request")
                } else {
                    None
                };
                if let Some(kind) = kind {
                    surfaces.insert(Surface {
                        kind: kind.to_string(),
                        source: relative.clone(),
                        symbol: symbol.to_string(),
                    });
                }
            }

            if let Some(symbol) = identifier_after(line, "pub fn ") {
                surfaces.insert(Surface {
                    kind: "builder".to_string(),
                    source: relative.clone(),
                    symbol: symbol.to_string(),
                });
            }
        }

        if relative.ends_with("/scan_configs.rs") {
            let lines = contents.lines().collect::<Vec<_>>();
            for (index, line) in lines.iter().enumerate() {
                if matches!(
                    line.trim(),
                    "clone_request!("
                        | "modify_request!("
                        | "delete_request!("
                        | "metadata_setter_request!("
                        | "comment_setter_request!("
                ) {
                    let symbol = lines[index + 1].trim().trim_end_matches(',').to_string();
                    surfaces.insert(Surface {
                        kind: "request".to_string(),
                        source: relative.clone(),
                        symbol,
                    });
                }
            }
        }

        if relative.ends_with("/reports.rs") {
            let lines = contents.lines().collect::<Vec<_>>();
            for (index, line) in lines.iter().enumerate() {
                if line.trim() == "report_projection_request!(" {
                    let symbol = lines[index + 1].trim().trim_end_matches(',').to_string();
                    surfaces.insert(Surface {
                        kind: "request".to_string(),
                        source: relative.clone(),
                        symbol,
                    });
                }
            }
        }
    }
}

fn collect_facade_surfaces(root: &Path, surfaces: &mut BTreeSet<Surface>) {
    let directory = root.join("crates/gvm-client/src/typed");
    for source in rust_sources(&directory) {
        let relative = relative_source(root, &source);
        let contents = fs::read_to_string(&source)
            .unwrap_or_else(|error| panic!("failed to read {}: {error}", source.display()));

        for line in contents.lines() {
            if let Some(symbol) = identifier_after(line.trim_start(), "pub async fn ") {
                surfaces.insert(Surface {
                    kind: "facade".to_string(),
                    source: relative.clone(),
                    symbol: symbol.to_string(),
                });
            }
        }
    }
}

fn collect_surfaces(root: &Path) -> BTreeSet<Surface> {
    let mut surfaces = BTreeSet::new();
    collect_command_surfaces(root, &mut surfaces);
    collect_facade_surfaces(root, &mut surfaces);
    surfaces
}

fn expected_ticket_surfaces() -> BTreeSet<Surface> {
    [
        ("builder", "clone_ticket"),
        ("builder", "create_ticket"),
        ("builder", "delete_ticket"),
        ("builder", "get_ticket"),
        ("builder", "get_tickets"),
        ("builder", "modify_ticket"),
        ("facade", "create_ticket"),
        ("facade", "get_tickets"),
        ("facade", "modify_ticket"),
        ("options", "CreateTicketOpts"),
        ("options", "GetTicketsOpts"),
        ("options", "ModifyTicketOpts"),
    ]
    .into_iter()
    .map(|(kind, symbol)| Surface {
        kind: kind.to_string(),
        source: if kind == "facade" {
            "crates/gvm-client/src/typed/tickets.rs"
        } else {
            "crates/gvm-gmp/src/commands/tickets.rs"
        }
        .to_string(),
        symbol: symbol.to_string(),
    })
    .collect()
}

fn parse_ledger(contents: &str) -> BTreeMap<Surface, Disposition> {
    let allowed_kinds = ["builder", "facade", "options", "request"];
    let allowed_dispositions = [
        "canonical-request",
        "frozen-ticket",
        "raw-custom",
        "removed",
        "retained-construction",
        "transitional",
    ];
    let mut ledger = BTreeMap::new();

    for (index, line) in contents.lines().enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let fields = line.split('\t').collect::<Vec<_>>();
        assert_eq!(
            fields.len(),
            5,
            "{}:{} must contain five tab-separated fields",
            LEDGER_PATH,
            index + 1
        );
        assert!(
            allowed_kinds.contains(&fields[0]),
            "{}:{} has unknown kind {:?}",
            LEDGER_PATH,
            index + 1,
            fields[0]
        );
        assert!(
            allowed_dispositions.contains(&fields[3]),
            "{}:{} has unknown disposition {:?}",
            LEDGER_PATH,
            index + 1,
            fields[3]
        );
        assert!(
            !fields[4].trim().is_empty(),
            "{}:{} must explain its disposition",
            LEDGER_PATH,
            index + 1
        );

        let surface = Surface {
            kind: fields[0].to_string(),
            source: fields[1].to_string(),
            symbol: fields[2].to_string(),
        };
        let old = ledger.insert(
            surface.clone(),
            Disposition {
                value: fields[3].to_string(),
                rationale: fields[4].to_string(),
            },
        );
        assert!(
            old.is_none(),
            "{}:{} duplicates {surface:?}",
            LEDGER_PATH,
            index + 1
        );
    }

    ledger
}

fn initial_disposition(surface: &Surface) -> Disposition {
    if surface.source.ends_with("/tickets.rs") {
        Disposition {
            value: "frozen-ticket".to_string(),
            rationale: "Ticket surface is frozen by product scope.".to_string(),
        }
    } else {
        Disposition {
            value: "transitional".to_string(),
            rationale: "Pending bounded family migration under #602.".to_string(),
        }
    }
}

fn render_ledger(actual: &BTreeSet<Surface>, existing: &BTreeMap<Surface, Disposition>) -> String {
    let mut entries = existing.clone();
    for surface in actual {
        entries
            .entry(surface.clone())
            .or_insert_with(|| initial_disposition(surface));
    }

    let mut output = String::from("# kind\tsource\tsymbol\tdisposition\trationale\n");
    for (surface, disposition) in entries {
        output.push_str(&format!(
            "{}\t{}\t{}\t{}\t{}\n",
            surface.kind, surface.source, surface.symbol, disposition.value, disposition.rationale
        ));
    }
    output
}

fn assert_source_correspondence(
    actual: &BTreeSet<Surface>,
    ledger: &BTreeMap<Surface, Disposition>,
) {
    let active = ledger
        .iter()
        .filter(|(_, disposition)| disposition.value != "removed")
        .map(|(surface, _)| surface.clone())
        .collect::<BTreeSet<_>>();
    let removed_but_present = ledger
        .iter()
        .filter(|(surface, disposition)| {
            disposition.value == "removed" && actual.contains(*surface)
        })
        .map(|(surface, _)| surface.clone())
        .collect::<Vec<_>>();

    assert_eq!(
        actual.difference(&active).collect::<Vec<_>>(),
        Vec::<&Surface>::new(),
        "public surfaces missing from {LEDGER_PATH}"
    );
    assert_eq!(
        active.difference(actual).collect::<Vec<_>>(),
        Vec::<&Surface>::new(),
        "active ledger entries no longer exist; mark them removed with a rationale"
    );
    assert!(
        removed_but_present.is_empty(),
        "removed ledger entries still exist in source: {removed_but_present:#?}"
    );
}

fn assert_retained_surface_contract(ledger: &BTreeMap<Surface, Disposition>) {
    let frozen = ledger
        .iter()
        .filter(|(_, disposition)| disposition.value == "frozen-ticket")
        .map(|(surface, _)| surface.clone())
        .collect::<BTreeSet<_>>();
    assert_eq!(frozen, expected_ticket_surfaces());

    let active_construction = ledger
        .iter()
        .filter(|(surface, disposition)| {
            matches!(surface.kind.as_str(), "builder" | "options") && disposition.value != "removed"
        })
        .map(|(surface, _)| (surface.kind.as_str(), surface.symbol.as_str()))
        .collect::<BTreeSet<_>>();
    let expected_construction = [
        ("builder", "clone_ticket"),
        ("builder", "create_ticket"),
        ("builder", "delete_ticket"),
        ("builder", "get_ticket"),
        ("builder", "get_tickets"),
        ("builder", "modify_ticket"),
        ("options", "AgentConfigOpts"),
        ("options", "CreateTicketOpts"),
        ("options", "GetTicketsOpts"),
        ("options", "ModifyTicketOpts"),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    assert_eq!(active_construction, expected_construction);

    for (surface, disposition) in ledger
        .iter()
        .filter(|(_, disposition)| disposition.value == "retained-construction")
    {
        assert!(
            !disposition
                .rationale
                .to_ascii_lowercase()
                .contains("compatibility"),
            "retention must have a concrete construction/discoverability reason: {surface:?}"
        );
        if surface.symbol == "AgentConfigOpts" {
            assert_eq!(surface.kind, "options");
            assert!(disposition.rationale.contains("shared"));
        } else {
            assert_eq!(surface.kind, "facade");
            assert!(surface.source.starts_with("crates/gvm-client/src/typed/"));
            assert!(
                disposition.rationale.contains("accepts")
                    || disposition.rationale.contains("Accepts"),
                "retained facade rationale must record canonical request acceptance: {surface:?}"
            );
            assert!(disposition
                .rationale
                .to_ascii_lowercase()
                .contains("request"));
        }
    }
}

fn assert_disposition_counts(ledger: &BTreeMap<Surface, Disposition>) {
    let counts = ledger
        .values()
        .fold(BTreeMap::new(), |mut counts, disposition| {
            *counts.entry(disposition.value.as_str()).or_insert(0_usize) += 1;
            counts
        });
    assert_eq!(ledger.len(), 1026, "#678 disposition ledger total drifted");
    assert_eq!(
        counts.get("transitional").copied().unwrap_or_default(),
        0,
        "the completed #658-#664 inventory must contain zero transitional rows"
    );
    assert_eq!(counts.get("canonical-request"), Some(&409));
    assert_eq!(counts.get("removed"), Some(&475));
    assert_eq!(counts.get("retained-construction"), Some(&130));
    assert_eq!(counts.get("frozen-ticket"), Some(&12));
}

#[test]
fn every_public_request_surface_has_an_explicit_disposition() {
    let root = workspace_root();
    let ledger_path = root.join(LEDGER_PATH);
    let actual = collect_surfaces(&root);

    if std::env::var(UPDATE_ENV).as_deref() == Ok("1") {
        let existing = fs::read_to_string(&ledger_path)
            .ok()
            .map(|contents| parse_ledger(&contents))
            .unwrap_or_default();
        fs::write(&ledger_path, render_ledger(&actual, &existing))
            .unwrap_or_else(|error| panic!("failed to update {}: {error}", ledger_path.display()));
    }

    let contents = fs::read_to_string(&ledger_path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", ledger_path.display()));
    let ledger = parse_ledger(&contents);
    assert_eq!(
        render_ledger(&actual, &ledger),
        contents,
        "{LEDGER_PATH} must be a sorted, reproducibly rendered inventory"
    );
    assert_source_correspondence(&actual, &ledger);
    assert_retained_surface_contract(&ledger);
    assert_disposition_counts(&ledger);
}

#[test]
fn raw_escape_hatches_and_unsupported_sync_boundary_are_explicit() {
    let root = workspace_root();
    let client = fs::read_to_string(root.join("crates/gvm-client/src/lib.rs"))
        .expect("client source should be readable");
    let protocol_request = fs::read_to_string(root.join("crates/gvm-protocol/src/request.rs"))
        .expect("protocol request source should be readable");
    assert!(protocol_request.contains("pub trait Request"));
    assert_eq!(client.matches("pub async fn send<R: Request>").count(), 2);
    assert_eq!(client.matches("pub async fn call<R: Request>").count(), 2);

    let actual = collect_surfaces(&root);
    for unsupported in [
        "SyncConfigRequest",
        "RestoreFromTrashcanRequest",
        "sync_config",
        "sync_scan_config",
        "restore_from_trashcan",
    ] {
        assert!(
            actual.iter().all(|surface| surface.symbol != unsupported),
            "unsupported or redundant surface is still public: {unsupported}"
        );
    }
}

#[test]
fn v06_removed_facades_have_explicit_migration_mappings() {
    let guide = fs::read_to_string(workspace_root().join(MIGRATION_GUIDE_PATH))
        .expect("v0.7 migration guide should be readable");
    let normalized_guide = guide.split_whitespace().collect::<Vec<_>>().join(" ");
    for symbol in V06_REMOVED_FACADES {
        assert!(
            guide.contains(&format!("`{symbol}`")),
            "{MIGRATION_GUIDE_PATH} must map removed v0.6.0 facade {symbol}"
        );
    }
    for required_audit_fact in [
        "417 public command-construction symbols",
        "407 are removed",
        "200 typed-facade names",
        "165 now take one complete request value",
        "32 are removed or renamed",
        "three frozen ticket helpers",
    ] {
        assert!(
            normalized_guide.contains(required_audit_fact),
            "{MIGRATION_GUIDE_PATH} is missing audited baseline fact {required_audit_fact:?}"
        );
    }
}
