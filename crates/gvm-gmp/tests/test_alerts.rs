// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::alerts::{
    AlertData, CloneAlertRequest, CreateAlertRequest, DeleteAlertRequest, GetAlertRequest,
    ModifyAlertRequest, TestAlertRequest, TriggerAlertRequest,
};
use gvm_gmp::{AlertCondition, AlertEvent, AlertMethod, GmpRequestCodec, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn create_alert_with_all_fields() {
    let mut request = CreateAlertRequest::new(
        "a",
        AlertEvent::TaskRunStatusChanged,
        AlertCondition::SeverityAtLeast,
        AlertMethod::Email,
    );
    request.comment = Some("c".into());
    request.event_data = vec![AlertData::new("status", "Done")];
    request.condition_data = vec![AlertData::new("severity", "5.5")];
    request.method_data = vec![AlertData::new("to_address", "ops@example.com")];
    request.filter_id = Some(id("f1"));
    request.active = Some(false);
    assert_eq!(
        xml(&request),
        "<create_alert><name>a</name><comment>c</comment><event>Task run status changed<data>Done<name>status</name></data></event><condition>Severity at least<data>5.5<name>severity</name></data></condition><method>Email<data>ops@example.com<name>to_address</name></data></method><filter id=\"f1\"/><active>0</active></create_alert>"
    );
}

#[test]
fn alert_lifecycle_requests_have_exact_xml() {
    assert_eq!(
        xml(&CloneAlertRequest::new(id("a1"))),
        "<create_alert><copy>a1</copy></create_alert>"
    );
    assert_eq!(
        xml(&GetAlertRequest::new(id("a1"))),
        "<get_alerts alert_id=\"a1\" details=\"1\"/>"
    );

    let mut modify = ModifyAlertRequest::new(id("a1"));
    modify.name = Some("renamed".into());
    modify.event = Some(AlertEvent::TaskRunStatusChanged);
    modify.event_data = vec![AlertData::new("status", "Done")];
    modify.condition = Some(AlertCondition::Always);
    modify.method = Some(AlertMethod::SysLog);
    modify.active = Some(true);
    assert_eq!(
        xml(&modify),
        "<modify_alert alert_id=\"a1\"><name>renamed</name><event>Task run status changed<data>Done<name>status</name></data></event><condition>Always</condition><method>Syslog</method><active>1</active></modify_alert>"
    );
    assert_eq!(
        xml(&DeleteAlertRequest::new(id("a1"), false)),
        "<delete_alert alert_id=\"a1\" ultimate=\"0\"/>"
    );
    assert_eq!(
        xml(&TestAlertRequest::new(id("a1"))),
        "<test_alert alert_id=\"a1\"/>"
    );
}

#[test]
fn trigger_alert_builds_get_reports_command() {
    let mut request = TriggerAlertRequest::new(id("a1"), id("r1"));
    request.filter_string = Some("severity>5".into());
    request.filter_id = Some(id("f1"));
    request.report_format_id = Some(id("rf1"));
    request.delta_report_id = Some(id("dr1"));
    assert_eq!(
        xml(&request),
        "<get_reports alert_id=\"a1\" delta_report_id=\"dr1\" filt_id=\"f1\" filter=\"severity&gt;5\" format_id=\"rf1\" report_id=\"r1\"/>"
    );
}
