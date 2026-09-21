// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::system::*;
use gvm_gmp::{GmpRequestCodec, GmpVersion, SortOrder};

fn typed_xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

#[test]
fn test_system_filtered_getters() {
    let mut settings = GetSettingsRequest::new();
    settings.filter_string = Some("name=Timezone".into());
    settings.first = Some(1);
    settings.max = Some(-1);
    settings.sort_field = Some("name".into());
    settings.sort_order = Some(SortOrder::Ascending);
    assert_eq!(
        typed_xml(&settings),
        "<get_settings filter=\"name=Timezone\" first=\"1\" max=\"-1\" sort_field=\"name\" sort_order=\"ascending\"/>"
    );
    assert_eq!(typed_xml(&GetLicenseRequest::new()), "<get_license/>");
    assert_eq!(typed_xml(&DescribeAuthRequest::new()), "<describe_auth/>");
    assert_eq!(typed_xml(&GetTimezonesRequest::new()), "<get_timezones/>");
    assert_eq!(
        typed_xml(&GetVulnsRequest {
            filter_string: Some("qod>0".into()),
            filter_id: Some(id("f2"))
        }),
        "<get_vulns filt_id=\"f2\" filter=\"qod&gt;0\"/>"
    );
}

#[test]
fn test_system_mutations() {
    let version = GmpVersion(22, 8);
    assert_eq!(
        typed_xml(&ModifyAuthRequest::new(
            "method:ldap_connect",
            [
                ("enable".into(), "true".into()),
                ("ldaphost".into(), "ldap.example".into()),
            ]
        )),
        "<modify_auth><group name=\"method:ldap_connect\"><auth_conf_setting><key>enable</key><value>true</value></auth_conf_setting><auth_conf_setting><key>ldaphost</key><value>ldap.example</value></auth_conf_setting></group></modify_auth>"
    );

    let mut license = ModifyLicenseRequest::new("YWJj");
    license.allow_empty = Some(true);
    assert_eq!(
        typed_xml(&license),
        "<modify_license allow_empty=\"1\"><file>YWJj</file></modify_license>"
    );
    assert_eq!(
        typed_xml(&ModifySettingRequest::new(id("s1"), "Europe/Berlin")),
        "<modify_setting setting_id=\"s1\"><value>RXVyb3BlL0Jlcmxpbg==</value></modify_setting>"
    );

    let mut wizard = RunWizardRequest::new(
        "quick",
        [
            ("target".into(), "10.0.0.1".into()),
            ("ports".into(), "T:1-5".into()),
        ],
    );
    wizard.mode = Some("step".into());
    wizard.read_only = Some(false);
    assert_eq!(
        String::from_utf8(wizard.encode(version).unwrap()).unwrap(),
        "<run_wizard read_only=\"0\"><mode>step</mode><name>quick</name><params><param><name>target</name><value>10.0.0.1</value></param><param><name>ports</name><value>T:1-5</value></param></params></run_wizard>"
    );
}
