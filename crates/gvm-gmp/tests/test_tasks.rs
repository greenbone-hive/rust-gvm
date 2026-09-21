// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical specialized-task and audit request conformance tests.

use gvm_gmp::commands::tasks::*;
use gvm_gmp::types::{CollectionUpdate, EntityId, ScalarUpdate};
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid ID")
}

fn encoded(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(
        request
            .encode(GmpVersion(22, 8))
            .expect("request should encode"),
    )
    .expect("request XML should be UTF-8")
}

#[test]
fn specialized_creation_shapes_encode_canonical_values() {
    let mut import = CreateImportTaskRequest::new("Import");
    import.comment = Some("Reports".into());
    assert_eq!(
        encoded(&import),
        "<create_task><name>Import</name><target id=\"0\"/><comment>Reports</comment></create_task>"
    );

    let mut container = CreateContainerTaskRequest::new("Container");
    container.comment = Some("Reports".into());
    assert_eq!(
        encoded(&container),
        encoded(&import).replace("Import", "Container")
    );

    let mut agent = CreateAgentGroupTaskRequest::new("Agents", id("agent-group-1"));
    agent.comment = Some("Agent scan".into());
    agent.alterable = Some(true);
    agent.schedule_id = Some(id("schedule-1"));
    agent.schedule_periods = Some(2);
    agent.alert_ids = vec![id("alert-1")];
    agent.observers = vec!["alice".into()];
    agent.observer_group_ids = vec![id("group-1")];
    agent.preferences = vec![TaskPreference::new("max_hosts", "10")];
    assert_eq!(
        encoded(&agent),
        "<create_task><name>Agents</name><usage_type>scan</usage_type><agent_group id=\"agent-group-1\"/><comment>Agent scan</comment><alterable>1</alterable><schedule id=\"schedule-1\"/><schedule_periods>2</schedule_periods><alert id=\"alert-1\"/><observers>alice<group id=\"group-1\"/></observers><preferences><preference><scanner_name>max_hosts</scanner_name><value>10</value></preference></preferences></create_task>"
    );

    let mut oci =
        CreateOciImageTargetTaskRequest::new("OCI", id("oci-target-1"), id("container-scanner-1"));
    oci.schedule_periods = Some(4);
    assert_eq!(
        encoded(&oci),
        "<create_task><name>OCI</name><usage_type>scan</usage_type><oci_image_target id=\"oci-target-1\"/><scanner id=\"container-scanner-1\"/><schedule_periods>4</schedule_periods></create_task>"
    );

    let alias = CreateContainerImageTaskRequest::new(
        "Container Image",
        id("oci-target-1"),
        id("container-scanner-1"),
    );
    assert_eq!(
        encoded(&alias),
        "<create_task><name>Container Image</name><usage_type>scan</usage_type><oci_image_target id=\"oci-target-1\"/><scanner id=\"container-scanner-1\"/></create_task>"
    );

    let web = CreateWebApplicationTaskRequest::new("Web", id("web-target-1"), id("web-scanner-1"));
    assert_eq!(
        encoded(&web),
        "<create_task><name>Web</name><usage_type>scan</usage_type><web_application_target id=\"web-target-1\"/><scanner id=\"web-scanner-1\"/></create_task>"
    );
}

#[test]
fn specialized_final_values_and_preferences_validate_without_leaking() {
    let secret = "confidential-task-preference";
    let preference = TaskPreference::new("token", secret);
    let debug = format!("{preference:?}");
    assert!(!debug.contains(secret));
    assert!(debug.contains("<redacted>"));

    let mut debug_request =
        CreateWebApplicationTaskRequest::new("Web", id("web-target"), id("scanner"));
    debug_request.preferences.push(preference);
    assert!(!format!("{debug_request:?}").contains(secret));

    let mut invalid_name = CreateImportTaskRequest::new("");
    invalid_name.comment = Some("valid".into());
    assert!(matches!(
        invalid_name.validate(),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));

    let mut container =
        CreateOciImageTargetTaskRequest::new("OCI", id("oci-target"), id("scanner"));
    container.preferences = vec![TaskPreference::new("in_assets", secret)];
    let error = container.validate().expect_err("in_assets must fail");
    assert!(!error.to_string().contains(secret));

    let mut web = CreateWebApplicationTaskRequest::new("Web", id("web-target"), id("scanner"));
    web.preferences = vec![TaskPreference::new("scan_mode", secret)];
    assert!(web.validate().is_err());
    web.preferences = vec![TaskPreference::new("ajax_spider_timeout", "-1")];
    assert!(web.validate().is_err());
    web.preferences = vec![TaskPreference::new("scan_mode", "safe")];
    assert!(web.validate().is_ok());
}

#[test]
fn move_owns_required_destination_semantics() {
    assert_eq!(
        encoded(&MoveTaskRequest::new(
            id("task-1"),
            TaskMoveDestination::Slave(id("scanner-1")),
        )),
        "<move_task slave_id=\"scanner-1\" task_id=\"task-1\"/>"
    );
    assert_eq!(
        encoded(&MoveTaskRequest::new(
            id("task-1"),
            TaskMoveDestination::Master,
        )),
        "<move_task slave_id=\"\" task_id=\"task-1\"/>"
    );
}

#[test]
fn audit_lifecycle_encodes_identity_and_complete_values() {
    let list = GetAuditsRequest {
        details: Some(true),
        ignore_pagination: Some(true),
        ..Default::default()
    };
    assert_eq!(
        encoded(&list),
        "<get_tasks details=\"1\" ignore_pagination=\"1\" usage_type=\"audit\"/>"
    );
    assert_eq!(
        encoded(&GetAuditRequest::new(id("audit-1"))),
        "<get_tasks details=\"1\" task_id=\"audit-1\" usage_type=\"audit\"/>"
    );

    let mut create =
        CreateAuditRequest::new("Audit", id("policy-1"), id("target-1"), id("scanner-1"));
    create.comment = Some("Compliance".into());
    create.observers = vec!["alice".into()];
    create.preferences = vec![TaskPreference::new("max_hosts", "10")];
    assert_eq!(
        encoded(&create),
        "<create_task><name>Audit</name><usage_type>audit</usage_type><config id=\"policy-1\"/><target id=\"target-1\"/><scanner id=\"scanner-1\"/><comment>Compliance</comment><observers>alice</observers><preferences><preference><scanner_name>max_hosts</scanner_name><value>10</value></preference></preferences></create_task>"
    );

    let mut clone = CloneAuditRequest::new(id("audit-1"));
    clone.comment = Some("Clone comment".into());
    clone.alterable = Some(false);
    assert_eq!(
        encoded(&clone),
        "<create_task><comment>Clone comment</comment><copy>audit-1</copy><alterable>0</alterable></create_task>"
    );

    let mut modify = ModifyAuditRequest::new(id("audit-1"));
    modify.name = Some("Renamed".into());
    modify.comment = Some(String::new());
    modify.policy_id = Some(id("policy-2"));
    modify.schedule_id = ScalarUpdate::Clear;
    modify.alert_ids = CollectionUpdate::Clear;
    modify.observers = CollectionUpdate::replace(["bob".into()]);
    modify.observer_group_ids = CollectionUpdate::replace([id("group-2")]);
    assert_eq!(
        encoded(&modify),
        "<modify_task task_id=\"audit-1\"><name>Renamed</name><comment></comment><schedule id=\"0\"/><config id=\"policy-2\"/><alert id=\"0\"/><observers>bob<group id=\"group-2\"/></observers></modify_task>"
    );

    assert_eq!(
        encoded(&DeleteAuditRequest::new(id("audit-1"), true)),
        "<delete_task task_id=\"audit-1\" ultimate=\"1\"/>"
    );
    assert_eq!(
        encoded(&StartAuditRequest::new(id("audit-1"))),
        "<start_task task_id=\"audit-1\"/>"
    );
    assert_eq!(
        encoded(&StopAuditRequest::new(id("audit-1"))),
        "<stop_task task_id=\"audit-1\"/>"
    );
    assert_eq!(
        encoded(&ResumeAuditRequest::new(id("audit-1"))),
        "<resume_task task_id=\"audit-1\"/>"
    );
}

#[test]
fn modify_audit_validates_final_observer_relationship_before_encoding() {
    let mut request = ModifyAuditRequest::new(id("audit-1"));
    request.comment = Some("would otherwise be sent".into());
    request.observer_group_ids = CollectionUpdate::replace([id("group-1")]);
    assert!(matches!(
        request.validate(),
        Err(GmpRequestError::InvalidCombination { .. })
    ));
    assert!(request.encode(GmpVersion(22, 8)).is_err());
}

#[test]
fn standard_task_requests_still_encode_canonical_shapes() {
    let mut create = CreateTaskRequest::new("Task", id("config"), id("target"), id("scanner"));
    create.schedule_periods = Some(5);
    assert!(encoded(&create).contains("<schedule_periods>5</schedule_periods>"));

    let mut modify = ModifyTaskRequest::new(id("task"));
    modify.comment = Some(String::new());
    assert_eq!(
        encoded(&modify),
        "<modify_task task_id=\"task\"><comment></comment></modify_task>"
    );
}
