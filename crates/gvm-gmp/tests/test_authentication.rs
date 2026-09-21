// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

fn xml(request: &AuthenticateRequest) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn test_authenticate_basic() {
    assert_eq!(
        xml(&AuthenticateRequest::new("foo", "bar")),
        "<authenticate><credentials><username>foo</username><password>bar</password></credentials></authenticate>"
    );
}

#[test]
fn test_authenticate_rejects_empty_values_without_disclosure() {
    let error = AuthenticateRequest::new("", "secret")
        .validate()
        .unwrap_err();
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn test_authenticate_escapes_xml_special_chars() {
    assert_eq!(
        xml(&AuthenticateRequest::new(r#"<>&"'"#, r#""'&<>"#)),
        "<authenticate><credentials><username>&lt;&gt;&amp;&quot;&apos;</username><password>&quot;&apos;&amp;&lt;&gt;</password></credentials></authenticate>"
    );
}
