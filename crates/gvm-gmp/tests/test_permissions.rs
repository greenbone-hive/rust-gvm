// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]
mod common;
use common::id;
use gvm_gmp::commands::permissions::*;
use gvm_gmp::responses::*;
use gvm_gmp::{
    GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse, GmpVersion,
    PermissionSubjectType, ScalarUpdate,
};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}
fn create() -> CreatePermissionRequest {
    CreatePermissionRequest::new(
        "get_tasks",
        PermissionSubject::new(id("s1"), PermissionSubjectType::Role),
    )
}

#[test]
fn create_complete_subject_and_inferred_or_explicit_resource() {
    let mut request = create();
    assert_eq!(xml(&request), "<create_permission><name>get_tasks</name><subject id=\"s1\"><type>role</type></subject></create_permission>");
    request.resource = Some(PermissionResource::new(id("t1")));
    assert_eq!(xml(&request), "<create_permission><name>get_tasks</name><resource id=\"t1\"/><subject id=\"s1\"><type>role</type></subject></create_permission>");
    request.comment = Some("c<&".into());
    request.resource.as_mut().unwrap().resource_type = Some("task".into());
    assert_eq!(xml(&request), "<create_permission><comment>c&lt;&amp;</comment><name>get_tasks</name><resource id=\"t1\"><type>task</type></resource><subject id=\"s1\"><type>role</type></subject></create_permission>");
}

#[test]
fn modify_omits_preserved_fields_and_encodes_clear_and_partial_subjects() {
    let mut request = ModifyPermissionRequest::new(id("p1"));
    assert_eq!(xml(&request), "<modify_permission permission_id=\"p1\"/>");
    request.comment = Some(String::new());
    request.resource_id = ScalarUpdate::Clear;
    request.subject_id = Some(id("s2"));
    assert_eq!(xml(&request), "<modify_permission permission_id=\"p1\"><comment></comment><resource id=\"0\"/><subject id=\"s2\"/></modify_permission>");
    request.subject_id = None;
    request.subject_type = Some(PermissionSubjectType::Group);
    request.resource_id = ScalarUpdate::Set(id("t2"));
    request.name = Some("get_targets".into());
    assert_eq!(xml(&request), "<modify_permission permission_id=\"p1\"><comment></comment><name>get_targets</name><resource id=\"t2\"/><subject><type>group</type></subject></modify_permission>");
}

#[test]
fn list_detail_clone_delete_exact_xml() {
    assert_eq!(xml(&GetPermissionsRequest::default()), "<get_permissions/>");
    assert_eq!(
        xml(&GetPermissionsRequest {
            filter_string: Some("name=foo & bar".into()),
            filter_id: Some(id("f1")),
            trash: Some(false),
            details: Some(true)
        }),
        "<get_permissions details=\"1\" filt_id=\"f1\" filter=\"name=foo &amp; bar\" trash=\"0\"/>"
    );
    assert_eq!(
        xml(&GetPermissionRequest::new(id("p1"))),
        "<get_permissions details=\"1\" permission_id=\"p1\"/>"
    );
    let mut clone = ClonePermissionRequest::new(id("p1"));
    assert_eq!(
        xml(&clone),
        "<create_permission><copy>p1</copy></create_permission>"
    );
    clone.comment = Some(String::new());
    assert_eq!(
        xml(&clone),
        "<create_permission><copy>p1</copy></create_permission>"
    );
    clone.comment = Some("copy".into());
    assert_eq!(
        xml(&clone),
        "<create_permission><comment>copy</comment><copy>p1</copy></create_permission>"
    );
    assert_eq!(
        xml(&DeletePermissionRequest::new(id("p1"), false)),
        "<delete_permission permission_id=\"p1\" ultimate=\"0\"/>"
    );
    assert_eq!(
        xml(&DeletePermissionRequest::new(id("p1"), true)),
        "<delete_permission permission_id=\"p1\" ultimate=\"1\"/>"
    );
}

#[test]
fn final_value_validation_and_super_semantics() {
    let mut request = create();
    for name in ["", "get_version", "GET_VERSION"] {
        request.name = name.into();
        assert!(matches!(
            request.encode(GmpVersion(22, 4)),
            Err(GmpRequestError::InvalidField { field: "name", .. })
        ));
    }
    request.name = "Super".into();
    assert!(request.validate().is_err());
    request.resource = Some(PermissionResource::new(id("r1")));
    assert!(request.validate().is_err());
    request.resource.as_mut().unwrap().resource_type = Some("task".into());
    assert!(request.validate().is_err());
    for kind in ["user", "group", "role"] {
        request.resource.as_mut().unwrap().resource_type = Some(kind.into());
        assert!(request.validate().is_ok());
    }
    request.resource.as_mut().unwrap().resource_type = Some(String::new());
    assert!(request.encode(GmpVersion(22, 8)).is_err());
    request.resource = Some(PermissionResource::new(id("0")));
    assert!(request.validate().is_err());
    request = create();
    request.subject.id = id("0");
    assert!(request.validate().is_err());

    let mut modify = ModifyPermissionRequest::new(id("p1"));
    modify.name = Some("Super".into());
    assert!(modify.validate().is_ok()); // Stored resource is authoritative.
    modify.resource_id = ScalarUpdate::Clear;
    assert!(modify.encode(GmpVersion(22, 8)).is_err());
    modify.resource_id = ScalarUpdate::Set(id("r1"));
    modify.resource_type = Some("user".into());
    assert!(modify.validate().is_ok());
    modify.subject_id = Some(id("0"));
    assert!(modify.validate().is_err());
    let diagnostic = format!("{:?}", modify.validate().unwrap_err());
    assert!(!diagnostic.contains("p1"));
}

#[test]
fn semantic_metadata_and_response_associations() {
    fn response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}
    response::<_, GetPermissionsResponse>(&GetPermissionsRequest::default());
    response::<_, GetPermissionsResponse>(&GetPermissionRequest::new(id("p1")));
    response::<_, CreatePermissionResponse>(&create());
    response::<_, CreatePermissionResponse>(&ClonePermissionRequest::new(id("p1")));
    response::<_, ModifyPermissionResponse>(&ModifyPermissionRequest::new(id("p1")));
    response::<_, DeletePermissionResponse>(&DeletePermissionRequest::new(id("p1"), false));
    assert_eq!(
        GetPermissionRequest::new(id("p1")).command(),
        Some(GmpCommand::with_semantic_name(
            "get_permissions",
            "get_permission"
        ))
    );
    assert_eq!(
        ClonePermissionRequest::new(id("p1")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_permission",
            "clone_permission"
        ))
    );
}

#[test]
fn partial_resource_type_and_mutated_modification_are_validated() {
    let mut request = ModifyPermissionRequest::new(id("p1"));
    request.resource_type = Some("group".into());
    assert_eq!(xml(&request), "<modify_permission permission_id=\"p1\"><resource><type>group</type></resource></modify_permission>");
    request.resource_type = Some(String::new());
    assert!(request.encode(GmpVersion(22, 4)).is_err());
    request.resource_type = Some("target".into());
    request.name = Some("Super".into());
    request.resource_id = ScalarUpdate::Set(id("r1"));
    assert!(request.encode(GmpVersion(22, 8)).is_err());
    request.name = None;
    request.resource_id = ScalarUpdate::Set(id("0"));
    assert!(request.encode(GmpVersion(22, 8)).is_err());
    request.resource_id = ScalarUpdate::Omitted;
    request.name = Some(String::new());
    assert!(request.encode(GmpVersion(22, 8)).is_err());
}

#[test]
fn every_request_keeps_baseline_wire_metadata() {
    let requests: Vec<(Box<dyn GmpRequestCodec>, &str)> = vec![
        (
            Box::new(GetPermissionsRequest::default()),
            "get_permissions",
        ),
        (
            Box::new(GetPermissionRequest::new(id("p1"))),
            "get_permissions",
        ),
        (Box::new(create()), "create_permission"),
        (
            Box::new(ClonePermissionRequest::new(id("p1"))),
            "create_permission",
        ),
        (
            Box::new(ModifyPermissionRequest::new(id("p1"))),
            "modify_permission",
        ),
        (
            Box::new(DeletePermissionRequest::new(id("p1"), true)),
            "delete_permission",
        ),
    ];
    for (request, wire) in requests {
        assert_eq!(request.command().unwrap().wire_name(), wire);
        let baseline = request.encode(GmpVersion(22, 4)).unwrap();
        for minor in 5..=8 {
            assert_eq!(request.encode(GmpVersion(22, minor)).unwrap(), baseline);
        }
    }
}
