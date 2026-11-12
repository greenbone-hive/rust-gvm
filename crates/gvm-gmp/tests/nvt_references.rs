// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::too_many_lines, clippy::unwrap_used)]

use gvm_gmp::responses::{GetNvtsResponse, GetResultsResponse, NvtReferenceEntry};
use gvm_protocol::Response;

#[test]
fn result_nvt_preserves_mixed_generic_refs_without_changing_cves() {
    let response = Response::from(
        r#"<get_results_response status="200" status_text="OK">
            <result id="mixed">
                <nvt oid="1.3.6.1.4.1.25623.1.0.1">
                    <name>Mixed references</name>
                    <cve>CVE-2026-DIRECT</cve>
                    <refs>
                        <ref type="cve" id="CVE-2026-ATTR"/>
                        <ref type="cert-bund" id="WID-SEC-2026-0001"/>
                        <ref type="dfn-cert" id="DFN-CERT-2026-0002"/>
                        <ref type="cert-bund" id="CB-K16/1837"/>
                        <ref type="url" id="https://example.test/advisory?a=1&amp;b=&quot;two&quot;"/>
                        <ref type="vendor&amp;kind" id="ADV&lt;42&gt;&amp;more"/>
                        <ref type="future-reference" id="opaque-1"/>
                        <ref type="CVE" id="CVE-2026-UPPERCASE"/>
                        <ref type="cve">CVE-2026-TEXT-FALLBACK</ref>
                        <ref type="cve"/>
                        <ref id="missing-type"/>
                        <ref type="" id="empty-type"/>
                        <ref type="url" id=""/>
                    </refs>
                </nvt>
            </result>
            <result id="absent"><nvt oid="1.3.6.1.4.1.25623.1.0.2"><name>Absent</name></nvt></result>
            <result id="empty"><nvt oid="1.3.6.1.4.1.25623.1.0.3"><name>Empty</name><refs/></nvt></result>
        </get_results_response>"#,
    );

    let parsed = GetResultsResponse::from_response(&response).expect("results parse");
    let mixed = parsed.items[0].nvt.as_ref().expect("NVT is present");

    assert_eq!(
        mixed.cves,
        ["CVE-2026-DIRECT", "CVE-2026-ATTR", "CVE-2026-TEXT-FALLBACK",]
    );
    assert_eq!(
        mixed
            .refs
            .iter()
            .map(|reference| (reference.type_.as_str(), reference.id.as_str()))
            .collect::<Vec<_>>(),
        [
            ("cve", "CVE-2026-ATTR"),
            ("cert-bund", "WID-SEC-2026-0001"),
            ("dfn-cert", "DFN-CERT-2026-0002"),
            ("cert-bund", "CB-K16/1837"),
            ("url", "https://example.test/advisory?a=1&b=\"two\""),
            ("vendor&kind", "ADV<42>&more"),
            ("future-reference", "opaque-1"),
            ("CVE", "CVE-2026-UPPERCASE"),
        ]
    );
    let _: &NvtReferenceEntry = &mixed.refs[0];
    assert!(parsed.items[1].nvt.as_ref().unwrap().refs.is_empty());
    assert!(parsed.items[2].nvt.as_ref().unwrap().refs.is_empty());
}

#[test]
fn catalog_nvt_refs_ignore_malformed_and_warning_only_payloads() {
    let response = Response::from(
        r#"<get_nvts_response status="200" status_text="OK">
            <nvt oid="1"><name>Absent refs</name></nvt>
            <nvt oid="2"><name>Empty refs</name><refs/></nvt>
            <nvt oid="3"><name>CERT warning</name><refs>Warning: CERT-Bund and DFN-CERT data are unavailable.</refs></nvt>
            <nvt oid="4"><name>Malformed refs</name><refs>
                <ref type="url"/>
                <ref id="missing-type"/>
                <ref type="" id="empty-type"/>
                <ref type="unknown" id=""/>
                <warning>This text is not a reference.</warning>
                <ref type="unknown" id="kept&amp;decoded"/>
            </refs></nvt>
        </get_nvts_response>"#,
    );

    let parsed = GetNvtsResponse::from_response(&response).expect("NVT catalog parses");

    assert!(parsed.items[0].refs.is_empty());
    assert!(parsed.items[1].refs.is_empty());
    assert!(parsed.items[2].refs.is_empty());
    assert_eq!(
        parsed.items[3]
            .refs
            .iter()
            .map(|reference| (reference.type_.as_str(), reference.id.as_str()))
            .collect::<Vec<_>>(),
        [("unknown", "kept&decoded")]
    );
}

#[cfg(feature = "serde")]
#[test]
fn legacy_serde_payloads_without_refs_default_to_empty_collections() {
    let result_nvt: gvm_gmp::responses::NvtRef = serde_json::from_str(
        r#"{
            "oid":"1.3.6.1.4.1.25623.1.0.1",
            "name":"Legacy result NVT",
            "family":"General",
            "cvss_base":"7.5",
            "cves":["CVE-2026-0001"],
            "tags":null,
            "type_metadata":null,
            "epss":null
        }"#,
    )
    .expect("legacy NvtRef JSON deserializes");
    let catalog_nvt: gvm_gmp::responses::Nvt = serde_json::from_str(
        r#"{
            "oid":"1.3.6.1.4.1.25623.1.0.2",
            "name":"Legacy catalog NVT",
            "family":null,
            "cvss_base":null,
            "severity":null,
            "tags":null,
            "solution_type":null,
            "discovery":null,
            "epss":null
        }"#,
    )
    .expect("legacy Nvt JSON deserializes");

    assert!(result_nvt.refs.is_empty());
    assert!(catalog_nvt.refs.is_empty());
}
