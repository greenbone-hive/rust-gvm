// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::configs::ConfigUsageType;
use gvm_gmp::commands::scan_configs::*;
use gvm_gmp::responses::{
    CreateScanConfigResponse, DeleteScanConfigResponse, GetScanConfigPreferenceResponse,
    GetScanConfigPreferencesResponse, GetScanConfigsResponse, ModifyScanConfigResponse,
};
use gvm_gmp::{GmpRequest, GmpRequestCodec, GmpResponse, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).unwrap()).unwrap()
}

fn valid_import(name: &str) -> String {
    format!(
        "<get_configs_response><config id=\"exported-id\"><name>{name}</name><nvt_selectors/><preferences/></config></get_configs_response>"
    )
}

fn assert_response<R, T>(_: &R)
where
    R: GmpRequest<Response = T>,
    T: GmpResponse,
{
}

#[test]
fn scoped_queries_encode_complete_independent_controls() {
    assert_eq!(
        xml(&GetScanConfigsRequest::new()),
        "<get_configs usage_type=\"scan\"/>"
    );
    assert_eq!(
        xml(&GetPoliciesRequest::new()),
        "<get_configs usage_type=\"policy\"/>"
    );
    assert_eq!(
        xml(&GetScanConfigRequest::new(id("config-1"))),
        "<get_configs config_id=\"config-1\" details=\"1\" usage_type=\"scan\"/>"
    );
    assert_eq!(
        xml(&GetPolicyRequest::new(id("policy-1"))),
        "<get_configs config_id=\"policy-1\" details=\"1\" usage_type=\"policy\"/>"
    );

    let request = GetPolicyRequest {
        policy_id: id("policy-1"),
        filter_string: Some("name=Baseline first=2 rows=1 sort-reverse=name".into()),
        filter_id: Some(id("0")),
        trash: Some(false),
        details: Some(false),
        families: Some(true),
        preferences: Some(false),
        audits: Some(true),
    };
    assert_eq!(
        xml(&request),
        "<get_configs config_id=\"policy-1\" details=\"0\" families=\"1\" filt_id=\"0\" filter=\"name=Baseline first=2 rows=1 sort-reverse=name\" preferences=\"0\" tasks=\"1\" trash=\"0\" usage_type=\"policy\"/>"
    );

    let request = GetScanConfigsRequest {
        config_id: None,
        filter_string: Some(String::new()),
        filter_id: Some(id("-2")),
        trash: Some(true),
        details: None,
        families: None,
        preferences: None,
        tasks: None,
    };
    assert_eq!(
        xml(&request),
        "<get_configs filt_id=\"-2\" filter=\"\" trash=\"1\" usage_type=\"scan\"/>"
    );
}

#[test]
fn named_creation_and_clones_encode_copy_first() {
    let mut scan = CreateScanConfigRequest::new("Named scan", id("base-1"));
    scan.comment = Some("Copied".into());
    assert_eq!(
        xml(&scan),
        "<create_config><copy>base-1</copy><name>Named scan</name><comment>Copied</comment></create_config>"
    );

    let mut policy = CreatePolicyRequest::new("Baseline & policy", id("base-1"));
    policy.comment = Some("Copied".into());
    assert_eq!(
        xml(&policy),
        "<create_config><copy>base-1</copy><name>Baseline &amp; policy</name><comment>Copied</comment><usage_type>policy</usage_type></create_config>"
    );

    let mut scan_clone = CloneScanConfigRequest::new(id("base-1"));
    assert_eq!(
        xml(&scan_clone),
        "<create_config><copy>base-1</copy></create_config>"
    );
    scan_clone.name = Some(String::new());
    scan_clone.comment = Some(String::new());
    scan_clone.usage_type = Some(ConfigUsageType::Scan);
    assert_eq!(
        xml(&scan_clone),
        "<create_config><copy>base-1</copy><name></name><comment></comment><usage_type>scan</usage_type></create_config>"
    );

    let policy_clone = ClonePolicyRequest::new(id("policy-1"));
    assert_eq!(
        xml(&policy_clone),
        "<create_config><copy>policy-1</copy></create_config>"
    );
}

#[test]
fn imports_strip_only_bom_and_declaration_and_add_outer_usage() {
    let carrier = valid_import("Imported");
    let request = ImportScanConfigRequest::new(format!(
        "\u{feff}<?xml version=\"1.0\" encoding=\"UTF-8\"?>{carrier}"
    ));
    assert_eq!(
        xml(&request),
        format!("<create_config>{carrier}</create_config>")
    );

    let mut override_request = ImportScanConfigRequest::new(carrier.clone());
    override_request.usage_type = Some(ConfigUsageType::Policy);
    assert_eq!(
        xml(&override_request),
        format!("<create_config>{carrier}<usage_type>policy</usage_type></create_config>")
    );

    let policy = ImportPolicyRequest::new(carrier.clone());
    assert_eq!(
        xml(&policy),
        format!("<create_config>{carrier}<usage_type>policy</usage_type></create_config>")
    );
}

#[test]
fn import_preserves_xml_text_cdata_comments_and_preference_children() {
    let carrier = concat!(
        "<get_configs_response><!--keep--><config>",
        "<name>Imported &amp; retained</name>",
        "<nvt_selectors><all_selector/></nvt_selectors>",
        "<preferences><preference><nvt oid=\"1.3.6.1\"/><id>1</id><name>Secret</name><type>radio</type>",
        "<value>A&amp;B<![CDATA[<C>]]></value><default></default><alt>one</alt><alt>two</alt>",
        "</preference></preferences></config></get_configs_response>"
    );
    let request = ImportScanConfigRequest::new(carrier);
    assert_eq!(
        xml(&request),
        format!("<create_config>{carrier}</create_config>")
    );
}

#[test]
fn import_validation_rechecks_mutated_xml_and_keeps_errors_confidential() {
    let mut request = ImportScanConfigRequest::new(valid_import("Secret imported name"));
    assert!(request.validate().is_ok());
    request.xml =
        "<get_configs_response><config><name>secret</name></config></get_configs_response>".into();
    let error = request.validate().unwrap_err();
    assert_eq!(request.encode(GmpVersion(22, 4)), Err(error));
    assert!(!error.to_string().contains("secret"));
    assert!(!format!("{request:?}").contains("secret"));

    for invalid in [
        "",
        "<get_configs_response/>",
        "<get_configs_response><config><name>x</name><nvt_selectors/></config></get_configs_response>",
        "<get_configs_response><config><name>x</name><preferences/></config></get_configs_response>",
        "<get_configs_response><config><name></name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<get_configs_response><config><name>x</name><name>y</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config><config><name>y</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<get_configs_response xmlns=\"urn:lookalike\"><config><name>x</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<x:get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config></x:get_configs_response>",
        "<!DOCTYPE x><get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<get_configs_response><config><name>x</name><nvt_selectors/><preferences><preference><nvt oid=\"1.3.6.1\"/><id/></preference></preferences></config></get_configs_response>",
        "<get_configs_response><config><name>x\u{1}</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<get_configs_response><config extension=\"x\u{1}\"><name>x</name><nvt_selectors/><preferences/></config></get_configs_response>",
        "<?xml version=\"1.0\" encoding=\"ISO-8859-1\"?><get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config></get_configs_response>",
        " <get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config></get_configs_response><?xml version=\"1.0\"?>",
        "<get_configs_response><config><name>x</name><nvt_selectors/><preferences/></config></get_configs_response>tail",
    ] {
        assert!(
            ImportScanConfigRequest::new(invalid).validate().is_err(),
            "accepted invalid carrier: {invalid}"
        );
    }
}

#[test]
fn metadata_setters_and_deletions_have_exact_no_op_and_optional_semantics() {
    let mut scan = ModifyScanConfigRequest::new(id("config-1"));
    assert_eq!(xml(&scan), "<modify_config config_id=\"config-1\"/>");
    scan.name = Some("Renamed".into());
    scan.comment = Some("Updated".into());
    assert_eq!(
        xml(&scan),
        "<modify_config config_id=\"config-1\"><name>Renamed</name><comment>Updated</comment></modify_config>"
    );

    let mut policy = ModifyPolicyRequest::new(id("policy-1"));
    policy.comment = Some(String::new());
    assert_eq!(
        xml(&policy),
        "<modify_config config_id=\"policy-1\"><comment></comment></modify_config>"
    );

    assert_eq!(
        xml(&ModifyScanConfigSetNameRequest::new(id("config-1"), "")),
        "<modify_config config_id=\"config-1\"><name></name></modify_config>"
    );
    assert_eq!(
        xml(&ModifyPolicySetNameRequest::new(
            id("policy-1"),
            "Policy name"
        )),
        "<modify_config config_id=\"policy-1\"><name>Policy name</name></modify_config>"
    );
    assert_eq!(
        xml(&ModifyScanConfigSetCommentRequest::new(
            id("config-1"),
            None
        )),
        "<modify_config config_id=\"config-1\"/>"
    );
    assert_eq!(
        xml(&ModifyPolicySetCommentRequest::new(
            id("policy-1"),
            Some(String::new())
        )),
        "<modify_config config_id=\"policy-1\"><comment></comment></modify_config>"
    );

    let mut delete_scan = DeleteScanConfigRequest::new(id("config-1"));
    assert_eq!(xml(&delete_scan), "<delete_config config_id=\"config-1\"/>");
    delete_scan.ultimate = Some(false);
    assert_eq!(
        xml(&delete_scan),
        "<delete_config config_id=\"config-1\" ultimate=\"0\"/>"
    );
    let mut delete_policy = DeletePolicyRequest::new(id("policy-1"));
    delete_policy.ultimate = Some(true);
    assert_eq!(
        xml(&delete_policy),
        "<delete_config config_id=\"policy-1\" ultimate=\"1\"/>"
    );
}

#[test]
#[allow(clippy::too_many_lines)]
fn all_lifecycle_requests_have_semantic_metadata_and_response_associations() {
    let import = valid_import("Imported");
    let requests = [
        (
            GetScanConfigsRequest::new().command().unwrap(),
            "get_scan_configs",
        ),
        (
            GetScanConfigRequest::new(id("c")).command().unwrap(),
            "get_scan_config",
        ),
        (GetPoliciesRequest::new().command().unwrap(), "get_policies"),
        (
            GetPolicyRequest::new(id("p")).command().unwrap(),
            "get_policy",
        ),
        (
            CreateScanConfigRequest::new("n", id("b"))
                .command()
                .unwrap(),
            "create_scan_config",
        ),
        (
            CreatePolicyRequest::new("n", id("b")).command().unwrap(),
            "create_policy",
        ),
        (
            CloneScanConfigRequest::new(id("c")).command().unwrap(),
            "clone_scan_config",
        ),
        (
            ClonePolicyRequest::new(id("p")).command().unwrap(),
            "clone_policy",
        ),
        (
            ImportScanConfigRequest::new(&import).command().unwrap(),
            "import_scan_config",
        ),
        (
            ImportPolicyRequest::new(&import).command().unwrap(),
            "import_policy",
        ),
        (
            ModifyScanConfigRequest::new(id("c")).command().unwrap(),
            "modify_scan_config",
        ),
        (
            ModifyPolicyRequest::new(id("p")).command().unwrap(),
            "modify_policy",
        ),
        (
            DeleteScanConfigRequest::new(id("c")).command().unwrap(),
            "delete_scan_config",
        ),
        (
            DeletePolicyRequest::new(id("p")).command().unwrap(),
            "delete_policy",
        ),
        (
            ModifyScanConfigSetNameRequest::new(id("c"), "n")
                .command()
                .unwrap(),
            "modify_scan_config_set_name",
        ),
        (
            ModifyScanConfigSetCommentRequest::new(id("c"), None)
                .command()
                .unwrap(),
            "modify_scan_config_set_comment",
        ),
        (
            ModifyPolicySetNameRequest::new(id("p"), "n")
                .command()
                .unwrap(),
            "modify_policy_set_name",
        ),
        (
            ModifyPolicySetCommentRequest::new(id("p"), None)
                .command()
                .unwrap(),
            "modify_policy_set_comment",
        ),
        (
            GetScanConfigPreferencesRequest::new().command().unwrap(),
            "get_scan_config_preferences",
        ),
        (
            GetScanConfigPreferenceRequest::new("entry:Name")
                .command()
                .unwrap(),
            "get_scan_config_preference",
        ),
        (
            ModifyScanConfigSetNvtPreferenceRequest::new(id("c"), "name", "oid", None)
                .command()
                .unwrap(),
            "modify_scan_config_set_nvt_preference",
        ),
        (
            ModifyScanConfigSetScannerPreferenceRequest::new(id("c"), "name", None)
                .command()
                .unwrap(),
            "modify_scan_config_set_scanner_preference",
        ),
        (
            ModifyScanConfigSetNvtSelectionRequest::new(id("c"), "family", vec![])
                .command()
                .unwrap(),
            "modify_scan_config_set_nvt_selection",
        ),
        (
            ModifyScanConfigSetFamilySelectionRequest::new(id("c"), vec![], false)
                .command()
                .unwrap(),
            "modify_scan_config_set_family_selection",
        ),
        (
            ModifyPolicySetNvtPreferenceRequest::new(id("p"), "name", "oid", None)
                .command()
                .unwrap(),
            "modify_policy_set_nvt_preference",
        ),
        (
            ModifyPolicySetScannerPreferenceRequest::new(id("p"), "name", None)
                .command()
                .unwrap(),
            "modify_policy_set_scanner_preference",
        ),
        (
            ModifyPolicySetNvtSelectionRequest::new(id("p"), "family", vec![])
                .command()
                .unwrap(),
            "modify_policy_set_nvt_selection",
        ),
        (
            ModifyPolicySetFamilySelectionRequest::new(id("p"), vec![], false)
                .command()
                .unwrap(),
            "modify_policy_set_family_selection",
        ),
    ];
    for (command, semantic) in requests {
        assert_eq!(
            command.wire_name(),
            match semantic {
                "get_scan_configs" | "get_scan_config" | "get_policies" | "get_policy" =>
                    "get_configs",
                "get_scan_config_preferences" | "get_scan_config_preference" => "get_preferences",
                "create_scan_config" | "create_policy" | "clone_scan_config" | "clone_policy"
                | "import_scan_config" | "import_policy" => "create_config",
                "modify_scan_config"
                | "modify_policy"
                | "modify_scan_config_set_name"
                | "modify_scan_config_set_comment"
                | "modify_policy_set_name"
                | "modify_policy_set_comment"
                | "modify_scan_config_set_nvt_preference"
                | "modify_scan_config_set_scanner_preference"
                | "modify_scan_config_set_nvt_selection"
                | "modify_scan_config_set_family_selection"
                | "modify_policy_set_nvt_preference"
                | "modify_policy_set_scanner_preference"
                | "modify_policy_set_nvt_selection"
                | "modify_policy_set_family_selection" => "modify_config",
                _ => "delete_config",
            }
        );
        assert_eq!(command.semantic_name(), Some(semantic));
    }

    assert_response::<_, GetScanConfigsResponse>(&GetScanConfigsRequest::new());
    assert_response::<_, GetScanConfigsResponse>(&GetScanConfigRequest::new(id("c")));
    assert_response::<_, CreateScanConfigResponse>(&CreateScanConfigRequest::new("n", id("b")));
    assert_response::<_, CreateScanConfigResponse>(&CloneScanConfigRequest::new(id("c")));
    assert_response::<_, CreateScanConfigResponse>(&ImportScanConfigRequest::new(import));
    assert_response::<_, ModifyScanConfigResponse>(&ModifyScanConfigRequest::new(id("c")));
    assert_response::<_, DeleteScanConfigResponse>(&DeleteScanConfigRequest::new(id("c")));
    assert_response::<_, GetScanConfigPreferencesResponse>(&GetScanConfigPreferencesRequest::new());
    assert_response::<_, GetScanConfigPreferenceResponse>(&GetScanConfigPreferenceRequest::new(
        "entry:Name",
    ));
    assert_response::<_, ModifyScanConfigResponse>(&ModifyPolicySetFamilySelectionRequest::new(
        id("p"),
        vec![],
        false,
    ));
}

#[test]
#[allow(clippy::too_many_lines)]
fn preference_and_selection_requests_encode_exact_complete_values() {
    let mut list = GetScanConfigPreferencesRequest::new();
    list.nvt_oid = Some("1.3.6.1".into());
    list.config_id = Some(id("c1"));
    assert_eq!(
        xml(&list),
        "<get_preferences config_id=\"c1\" nvt_oid=\"1.3.6.1\"/>"
    );

    let mut single = GetScanConfigPreferenceRequest::new("entry:Timeout & retries");
    single.nvt_oid = Some("1.3.6.1".into());
    single.config_id = Some(id("c1"));
    assert_eq!(
        xml(&single),
        "<get_preferences config_id=\"c1\" nvt_oid=\"1.3.6.1\" preference=\"entry:Timeout &amp; retries\"/>"
    );

    assert_eq!(
        xml(&ModifyScanConfigSetNvtPreferenceRequest::new(
            id("c1"),
            "1.3.6.1:1:entry:timeout",
            "1.3.6.1",
            Some("30".into()),
        )),
        "<modify_config config_id=\"c1\"><preference><nvt oid=\"1.3.6.1\"/><name>1.3.6.1:1:entry:timeout</name><value>MzA=</value></preference></modify_config>"
    );
    assert_eq!(
        xml(&ModifyPolicySetNvtPreferenceRequest::new(
            id("p1"),
            "1.3.6.1:1:entry:timeout",
            "1.3.6.1",
            Some("MzA=".into()),
        )),
        "<modify_config config_id=\"p1\"><preference><nvt oid=\"1.3.6.1\"/><name>1.3.6.1:1:entry:timeout</name><value>TXpBPQ==</value></preference></modify_config>"
    );
    assert_eq!(
        xml(&ModifyScanConfigSetScannerPreferenceRequest::new(
            id("c1"),
            "Scanner option",
            Some(String::new()),
        )),
        "<modify_config config_id=\"c1\"><preference><name>Scanner option</name><value></value></preference></modify_config>"
    );
    assert_eq!(
        xml(&ModifyPolicySetScannerPreferenceRequest::new(
            id("p1"),
            "Scanner option",
            None,
        )),
        "<modify_config config_id=\"p1\"><preference><name>Scanner option</name></preference></modify_config>"
    );
    assert_eq!(
        xml(&ModifyScanConfigSetNvtSelectionRequest::new(
            id("c1"),
            "General",
            vec!["1.3.6.2".into(), "1.3.6.1".into()],
        )),
        "<modify_config config_id=\"c1\"><nvt_selection><family>General</family><nvt oid=\"1.3.6.2\"/><nvt oid=\"1.3.6.1\"/></nvt_selection></modify_config>"
    );
    assert_eq!(
        xml(&ModifyPolicySetNvtSelectionRequest::new(
            id("p1"),
            "General",
            vec![],
        )),
        "<modify_config config_id=\"p1\"><nvt_selection><family>General</family></nvt_selection></modify_config>"
    );
    let families = vec![
        NvtFamilySelection {
            name: "General".into(),
            growing: true,
            all: false,
        },
        NvtFamilySelection {
            name: "Web & application".into(),
            growing: false,
            all: true,
        },
    ];
    assert_eq!(
        xml(&ModifyScanConfigSetFamilySelectionRequest::new(
            id("c1"),
            families.clone(),
            true,
        )),
        "<modify_config config_id=\"c1\"><family_selection><growing>1</growing><family><name>General</name><all>0</all><growing>1</growing></family><family><name>Web &amp; application</name><all>1</all><growing>0</growing></family></family_selection></modify_config>"
    );
    assert_eq!(
        xml(&ModifyPolicySetFamilySelectionRequest::new(
            id("p1"),
            vec![],
            false,
        )),
        "<modify_config config_id=\"p1\"><family_selection><growing>0</growing></family_selection></modify_config>"
    );
}

#[test]
fn final_mutated_values_are_validated_and_secret_diagnostics_are_redacted() {
    let mut list = GetScanConfigPreferencesRequest::new();
    list.nvt_oid = Some(String::new());
    assert!(list.encode(GmpVersion(22, 4)).is_err());

    let mut single = GetScanConfigPreferenceRequest::new("valid");
    single.preference = "secret\u{0}".into();
    let error = single.validate().expect_err("invalid XML must fail");
    assert!(!error.to_string().contains("secret"));

    let mut preference = ModifyScanConfigSetNvtPreferenceRequest::new(
        id("c1"),
        "1.3.6.1:1:password:Password",
        "1.3.6.1",
        Some("do-not-leak".into()),
    );
    assert!(!format!("{preference:?}").contains("do-not-leak"));
    preference.nvt_oid.clear();
    let error = preference.validate().expect_err("empty OID must fail");
    assert!(!format!("{error:?} {error}").contains("do-not-leak"));

    let empty_radio = ModifyPolicySetNvtPreferenceRequest::new(
        id("p1"),
        "1.3.6.1:2:radio:Mode",
        "1.3.6.1",
        Some(String::new()),
    );
    assert!(empty_radio.validate().is_err());

    let mut selection =
        ModifyScanConfigSetNvtSelectionRequest::new(id("c1"), "General", vec!["1.3.6.1".into()]);
    selection.nvt_oids[0].clear();
    assert!(selection.validate().is_err());

    let mut families = ModifyPolicySetFamilySelectionRequest::new(
        id("p1"),
        vec![NvtFamilySelection {
            name: "General".into(),
            growing: false,
            all: true,
        }],
        false,
    );
    families.families[0].name.clear();
    assert!(families.validate().is_err());
}
