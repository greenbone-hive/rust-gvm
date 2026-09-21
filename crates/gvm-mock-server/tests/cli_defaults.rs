// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::process::Command;

const BINARY: &str = env!("CARGO_BIN_EXE_gvm-mock-server");

#[test]
fn cli_help_publishes_the_22_7_default() {
    let output = Command::new(BINARY)
        .arg("--help")
        .output()
        .expect("run mock server help");
    assert!(output.status.success());
    let stdout = String::from_utf8(output.stdout).expect("help is UTF-8");
    assert!(
        stdout.contains("--version <VERSION>") && stdout.contains("[default: 22.7]"),
        "unexpected CLI help: {stdout}"
    );
}

#[test]
fn cli_publishes_the_package_build_version_without_shadowing_gmp_version() {
    let output = Command::new(BINARY)
        .arg("--build-version")
        .output()
        .expect("run mock server build-version command");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).expect("version is UTF-8"),
        format!("gvm-mock-server {}\n", env!("CARGO_PKG_VERSION"))
    );
}
