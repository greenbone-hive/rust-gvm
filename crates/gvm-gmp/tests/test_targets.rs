// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::capabilities::{command_capability, GvmdEvidence};
use gvm_gmp::commands::targets::{
    CloneTargetRequest, CreateTargetRequest, DeleteTargetRequest, GetTargetRequest,
    GetTargetsRequest, ModifyTargetRequest,
};
use gvm_gmp::{
    AliveTest, GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpResponse, GmpVersion,
    ScalarUpdate, ServicePort, TargetHost, TargetHosts, TargetPortSelection,
};

fn host(value: &str) -> TargetHost {
    value.parse().expect("valid target host")
}

fn hosts(included: &[&str], excluded: &[&str]) -> TargetHosts {
    TargetHosts::new(
        included.iter().map(|value| host(value)),
        excluded.iter().map(|value| host(value)),
    )
    .expect("valid target hosts")
}

fn direct_ports() -> TargetPortSelection {
    TargetPortSelection::PortRange("T:1-65535".parse().expect("valid port range"))
}

fn request_xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(
        request
            .encode(GmpVersion(22, 8))
            .expect("valid target request"),
    )
    .expect("valid UTF-8")
}

#[test]
fn target_requests_have_exact_wire_shapes() {
    assert_eq!(
        request_xml(&GetTargetsRequest {
            filter_string: Some("name=production".into()),
            filter_id: Some(id("filter-1")),
            trash: Some(true),
            details: Some(true),
        }),
        "<get_targets details=\"1\" filt_id=\"filter-1\" filter=\"name=production\" trash=\"1\"/>"
    );
    assert_eq!(
        request_xml(&GetTargetRequest::new(id("target-1"))),
        "<get_targets details=\"1\" target_id=\"target-1\"/>"
    );
    assert_eq!(
        request_xml(&DeleteTargetRequest::new(id("target-1"), true)),
        "<delete_target target_id=\"target-1\" ultimate=\"1\"/>"
    );
    assert_eq!(
        request_xml(&CloneTargetRequest::new(id("target-1"))),
        "<create_target><copy>target-1</copy></create_target>"
    );
}

#[test]
fn create_target_request_has_complete_exact_wire() {
    let request = CreateTargetRequest {
        name: "production".into(),
        comment: Some("primary & external".into()),
        hosts: hosts(&["192.0.2.1", "192.0.2.2"], &["192.0.2.3"]),
        alive_test: Some(AliveTest::IcmpAndArpPing),
        ports: TargetPortSelection::PortList(id("port-list-1")),
        ssh_credential_id: Some(id("ssh-1")),
        ssh_credential_port: Some(ServicePort::new(2222).expect("valid port")),
        ssh_elevate_credential_id: Some(id("elevate-1")),
        smb_credential_id: Some(id("smb-1")),
        krb5_credential_id: None,
        esxi_credential_id: Some(id("esxi-1")),
        snmp_credential_id: Some(id("snmp-1")),
        reverse_lookup_only: Some(true),
        reverse_lookup_unify: Some(false),
        allow_simultaneous_ips: Some(true),
    };

    assert_eq!(
        request_xml(&request),
        "<create_target><name>production</name><comment>primary &amp; external</comment><hosts>192.0.2.1,192.0.2.2</hosts><exclude_hosts>192.0.2.3</exclude_hosts><alive_tests>ICMP &amp; ARP Ping</alive_tests><port_list id=\"port-list-1\"/><ssh_credential id=\"ssh-1\"><port>2222</port></ssh_credential><ssh_elevate_credential id=\"elevate-1\"/><smb_credential id=\"smb-1\"/><esxi_credential id=\"esxi-1\"/><snmp_credential id=\"snmp-1\"/><reverse_lookup_only>1</reverse_lookup_only><reverse_lookup_unify>0</reverse_lookup_unify><allow_simultaneous_ips>1</allow_simultaneous_ips></create_target>"
    );
}

#[test]
fn modify_target_request_preserves_atomic_and_scalar_updates() {
    let mut request = ModifyTargetRequest::new(id("target-1"));
    request.name = Some("renamed".into());
    request.hosts = Some(hosts(&["192.0.2.1", "192.0.2.2"], &["192.0.2.3"]));
    request.alive_test = Some(AliveTest::IcmpPing);
    request.port_list_id = ScalarUpdate::set(id("port-list-1"));
    request.ssh_credential_id = ScalarUpdate::set(id("ssh-1"));
    request.ssh_credential_port = ScalarUpdate::Clear;
    request.ssh_elevate_credential_id = ScalarUpdate::Clear;
    request.smb_credential_id = ScalarUpdate::set(id("smb-1"));
    request.reverse_lookup_only = Some(true);
    request.allow_simultaneous_ips = Some(false);

    assert_eq!(
        request_xml(&request),
        "<modify_target target_id=\"target-1\"><name>renamed</name><hosts>192.0.2.1,192.0.2.2</hosts><exclude_hosts>192.0.2.3</exclude_hosts><alive_tests>ICMP Ping</alive_tests><port_list id=\"port-list-1\"/><ssh_credential id=\"ssh-1\"><port>0</port></ssh_credential><ssh_elevate_credential id=\"0\"/><smb_credential id=\"smb-1\"/><reverse_lookup_only>1</reverse_lookup_only><allow_simultaneous_ips>0</allow_simultaneous_ips></modify_target>"
    );
}

#[test]
fn modify_target_comment_distinguishes_omission_replacement_and_clear() {
    let omitted = ModifyTargetRequest::new(id("target-1"));
    assert_eq!(
        request_xml(&omitted),
        "<modify_target target_id=\"target-1\"/>"
    );

    let mut replacement = ModifyTargetRequest::new(id("target-1"));
    replacement.comment = Some("primary & <external>".into());
    assert_eq!(
        request_xml(&replacement),
        "<modify_target target_id=\"target-1\"><comment>primary &amp; &lt;external&gt;</comment></modify_target>"
    );

    let mut clear = ModifyTargetRequest::new(id("target-1"));
    clear.comment = Some(String::new());
    assert_eq!(
        request_xml(&clear),
        "<modify_target target_id=\"target-1\"><comment></comment></modify_target>"
    );
}

#[test]
fn constructor_values_can_be_mutated_but_final_validation_is_authoritative() {
    let mut create = CreateTargetRequest::new("target", hosts(&["192.0.2.1"], &[]), direct_ports());
    create.ssh_credential_port = Some(ServicePort::new(2222).expect("valid port"));
    assert_eq!(
        create.validate(),
        Err(GmpRequestError::invalid_combination(
            &["ssh_credential_port", "ssh_credential_id"],
            "setting an SSH credential port requires an SSH credential identifier",
        ))
    );

    let mut modify = ModifyTargetRequest::new(id("target-1"));
    modify.port_list_id = ScalarUpdate::Clear;
    assert_eq!(
        modify.validate(),
        Err(GmpRequestError::invalid_field(
            "port_list_id",
            "gvmd does not support clearing a target port-list relationship",
        ))
    );
}

#[test]
fn target_credential_combinations_are_typed_and_value_free() {
    let mut create = CreateTargetRequest::new("target", hosts(&["192.0.2.1"], &[]), direct_ports());
    create.ssh_credential_id = Some(id("same-secret-looking-id"));
    create.ssh_elevate_credential_id = Some(id("same-secret-looking-id"));
    let error = create
        .validate()
        .expect_err("matching credentials are invalid");
    assert!(matches!(error, GmpRequestError::InvalidCombination { .. }));
    assert!(!error.to_string().contains("same-secret-looking-id"));

    let mut modify = ModifyTargetRequest::new(id("target-1"));
    modify.smb_credential_id = ScalarUpdate::set(id("smb-1"));
    modify.krb5_credential_id = ScalarUpdate::set(id("krb-1"));
    assert!(matches!(
        modify.validate(),
        Err(GmpRequestError::InvalidCombination {
            fields: &["smb_credential_id", "krb5_credential_id"],
            ..
        })
    ));
}

#[test]
fn target_requests_expose_semantic_capability_metadata() {
    assert_eq!(
        GetTargetsRequest::default().command(),
        Some(GmpCommand::new("get_targets"))
    );
    assert_eq!(
        GetTargetRequest::new(id("target-1")).command(),
        Some(GmpCommand::with_semantic_name("get_targets", "get_target"))
    );
    assert_eq!(
        CloneTargetRequest::new(id("target-1")).command(),
        Some(GmpCommand::with_semantic_name(
            "create_target",
            "clone_target"
        ))
    );
    assert_eq!(
        CreateTargetRequest::new("target", hosts(&["192.0.2.1"], &[]), direct_ports()).command(),
        Some(GmpCommand::new("create_target"))
    );
    assert_eq!(
        ModifyTargetRequest::new(id("target-1")).command(),
        Some(GmpCommand::new("modify_target"))
    );
    assert_eq!(
        DeleteTargetRequest::new(id("target-1"), false).command(),
        Some(GmpCommand::new("delete_target"))
    );
}

#[test]
fn target_wire_commands_have_pinned_public_gvmd_schema_evidence() {
    for command in [
        "create_target",
        "delete_target",
        "get_targets",
        "modify_target",
    ] {
        assert_eq!(
            command_capability(command).map(|capability| capability.gvmd_evidence),
            Some(GvmdEvidence::PinnedSchema),
            "{command} must remain anchored in the pinned public gvmd schema"
        );
    }
}

#[test]
fn target_requests_remain_statically_associated_with_responses() {
    fn assert_response<R: GmpRequest<Response = T>, T: GmpResponse>(_: &R) {}

    assert_response::<_, gvm_gmp::responses::GetTargetsResponse>(&GetTargetsRequest::default());
    assert_response::<_, gvm_gmp::responses::GetTargetsResponse>(&GetTargetRequest::new(id(
        "target-1",
    )));
    assert_response::<_, gvm_gmp::responses::CreateTargetResponse>(&CloneTargetRequest::new(id(
        "target-1",
    )));
    assert_response::<_, gvm_gmp::responses::CreateTargetResponse>(&CreateTargetRequest::new(
        "target",
        hosts(&["192.0.2.1"], &[]),
        direct_ports(),
    ));
    assert_response::<_, gvm_gmp::responses::ModifyTargetResponse>(&ModifyTargetRequest::new(id(
        "target-1",
    )));
    assert_response::<_, gvm_gmp::responses::DeleteTargetResponse>(&DeleteTargetRequest::new(
        id("target-1"),
        false,
    ));
}
