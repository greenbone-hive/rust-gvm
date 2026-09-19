// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const LEDGER_PATH: &str = "docs/canonical-request-disposition.tsv";
const UPDATE_ENV: &str = "UPDATE_CANONICAL_REQUEST_DISPOSITION";

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
        active.difference(&actual).collect::<Vec<_>>(),
        Vec::<&Surface>::new(),
        "active ledger entries no longer exist; mark them removed with a rationale"
    );
    assert!(
        removed_but_present.is_empty(),
        "removed ledger entries still exist in source: {removed_but_present:#?}"
    );

    for (surface, disposition) in &ledger {
        if surface.source.ends_with("/tickets.rs") {
            assert_eq!(
                disposition.value, "frozen-ticket",
                "the frozen ticket surface cannot migrate under #602: {surface:?}"
            );
        }
    }

    let counts = ledger
        .values()
        .fold(BTreeMap::new(), |mut counts, disposition| {
            *counts.entry(disposition.value.as_str()).or_insert(0_usize) += 1;
            counts
        });
    assert_eq!(ledger.len(), 965, "#646 disposition ledger total drifted");
    assert_eq!(counts.get("transitional"), Some(&396));
    assert_eq!(counts.get("canonical-request"), Some(&191));
    assert_eq!(counts.get("removed"), Some(&255));
    assert_eq!(counts.get("retained-construction"), Some(&111));
    assert_eq!(counts.get("frozen-ticket"), Some(&12));
}
