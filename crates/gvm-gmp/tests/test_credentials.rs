// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use std::error::Error as _;

use common::id;
use gvm_gmp::commands::credentials::{
    CloneCredentialRequest, CreateCredentialRequest, CreateCredentialStoreCredentialRequest,
    CredentialStorePreference, DeleteCredentialRequest, GetCredentialRequest,
    GetCredentialStoreRequest, GetCredentialStoresRequest, GetCredentialsRequest,
    ModifyCredentialRequest, ModifyCredentialStoreCredentialRequest, ModifyCredentialStoreRequest,
    VerifyCredentialStoreRequest,
};
use gvm_gmp::{
    CredentialStoreCredentialType, CredentialType, GmpRequest, GmpRequestCodec, GmpRequestError,
    GmpVersion, SnmpAuthAlgorithm, SnmpPrivacyAlgorithm,
};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn standard_credential_requests_encode_exact_xml() {
    assert_eq!(
        xml(&GetCredentialsRequest {
            filter_string: Some("name=credential".into()),
            filter_id: Some(id("filter-1")),
            trash: Some(true),
            details: Some(false),
        }),
        "<get_credentials details=\"0\" filt_id=\"filter-1\" filter=\"name=credential\" trash=\"1\"/>"
    );
    assert_eq!(
        xml(&GetCredentialRequest::new(id("credential-1"))),
        "<get_credentials credential_id=\"credential-1\" details=\"1\"/>"
    );

    let mut create = CreateCredentialRequest::new("credential");
    create.comment = Some("primary".into());
    create.credential_type = Some(CredentialType::UsernamePassword);
    create.login = Some("alice".into());
    create.password = Some("secret".into());
    assert_eq!(
        xml(&create),
        "<create_credential><name>credential</name><comment>primary</comment><type>up</type><login>alice</login><password>secret</password></create_credential>"
    );
    assert_eq!(
        xml(&CloneCredentialRequest::new(id("credential-1"))),
        "<create_credential><copy>credential-1</copy></create_credential>"
    );

    let mut modify = ModifyCredentialRequest::new(id("credential-1"));
    modify.name = Some("renamed".into());
    modify.comment = Some("updated".into());
    assert_eq!(
        xml(&modify),
        "<modify_credential credential_id=\"credential-1\"><name>renamed</name><comment>updated</comment></modify_credential>"
    );
    assert_eq!(
        xml(&DeleteCredentialRequest::new(id("credential-1"), true)),
        "<delete_credential credential_id=\"credential-1\" ultimate=\"1\"/>"
    );
}

#[test]
fn credential_value_families_encode_exact_xml() {
    let mut ssh = CreateCredentialRequest::new("ssh");
    ssh.credential_type = Some(CredentialType::UsernameSshKey);
    ssh.login = Some("root".into());
    ssh.private_key = Some("PRIVATE".into());
    ssh.key_phrase = Some("phrase".into());
    assert_eq!(
        xml(&ssh),
        "<create_credential><name>ssh</name><type>usk</type><key><phrase>phrase</phrase><private>PRIVATE</private></key><login>root</login></create_credential>"
    );

    let mut kerberos = CreateCredentialRequest::new("kerberos");
    kerberos.credential_type = Some(CredentialType::Kerberos5);
    kerberos.login = Some("principal".into());
    kerberos.password = Some("secret".into());
    kerberos.kdcs = vec!["kdc1.example".into(), "kdc2.example".into()];
    kerberos.realm = Some("EXAMPLE.COM".into());
    assert_eq!(
        xml(&kerberos),
        "<create_credential><name>kerberos</name><type>krb5</type><kdcs><kdc>kdc1.example</kdc><kdc>kdc2.example</kdc></kdcs><login>principal</login><password>secret</password><realm>EXAMPLE.COM</realm></create_credential>"
    );

    let mut certificate = CreateCredentialRequest::new("certificate");
    certificate.credential_type = Some(CredentialType::ClientCertificate);
    certificate.private_key = Some("PRIVATE".into());
    certificate.certificate = Some("CERT".into());
    assert_eq!(
        xml(&certificate),
        "<create_credential><name>certificate</name><type>cc</type><certificate>CERT</certificate><key><private>PRIVATE</private></key></create_credential>"
    );

    let mut snmp = CreateCredentialRequest::new("snmp");
    snmp.credential_type = Some(CredentialType::SnmpV3);
    snmp.login = Some("snmp-user".into());
    snmp.password = Some("auth-secret".into());
    snmp.auth_algorithm = Some(SnmpAuthAlgorithm::Sha1);
    snmp.privacy_password = Some("privacy-secret".into());
    snmp.privacy_algorithm = Some(SnmpPrivacyAlgorithm::Aes);
    assert_eq!(
        xml(&snmp),
        "<create_credential><name>snmp</name><type>snmp</type><login>snmp-user</login><password>auth-secret</password><auth_algorithm>sha1</auth_algorithm><privacy><algorithm>aes</algorithm><password>privacy-secret</password></privacy></create_credential>"
    );
}

#[test]
fn credential_store_requests_encode_exact_xml() {
    assert_eq!(
        xml(&GetCredentialStoresRequest {
            filter_string: Some("name=store".into()),
            filter_id: Some(id("filter-1")),
            details: Some(true),
        }),
        "<get_credential_stores details=\"1\" filt_id=\"filter-1\" filter=\"name=store\"/>"
    );
    let mut get = GetCredentialStoreRequest::new(id("store-1"));
    get.details = Some(true);
    assert_eq!(
        xml(&get),
        "<get_credential_stores credential_store_id=\"store-1\" details=\"1\"/>"
    );
    assert_eq!(
        xml(&VerifyCredentialStoreRequest::new(id("store-1"))),
        "<verify_credential_store credential_store_id=\"store-1\"/>"
    );

    let mut store = ModifyCredentialStoreRequest::new(id("store-1"));
    store.active = Some(true);
    store.host = Some("store.example".into());
    store.path = Some("/vault".into());
    store.port = Some(8200);
    store.comment = Some("primary".into());
    store.preferences.push(CredentialStorePreference {
        name: "token".into(),
        value: "secret".into(),
    });
    assert_eq!(
        xml(&store),
        "<modify_credential_store credential_store_id=\"store-1\"><active>1</active><host>store.example</host><path>/vault</path><port>8200</port><comment>primary</comment><preferences><preference><name>token</name><value>secret</value></preference></preferences></modify_credential_store>"
    );

    let mut create = CreateCredentialStoreCredentialRequest::new(
        "stored",
        CredentialStoreCredentialType::UsernamePassword,
        "vault-1",
        "host-1",
    );
    create.comment = Some("from store".into());
    create.credential_store_id = Some(id("store-1"));
    assert_eq!(
        xml(&create),
        "<create_credential><name>stored</name><type>cs_up</type><comment>from store</comment><credential_store_id>store-1</credential_store_id><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
    );

    let mut snmp = CreateCredentialStoreCredentialRequest::new(
        "stored snmp",
        CredentialStoreCredentialType::Snmp,
        "vault-1",
        "auth-host-1",
    );
    snmp.auth_algorithm = Some(SnmpAuthAlgorithm::Sha1);
    snmp.privacy_algorithm = Some(SnmpPrivacyAlgorithm::Aes);
    snmp.privacy_host_identifier = Some("privacy-host-1".into());
    assert_eq!(
        xml(&snmp),
        "<create_credential><name>stored snmp</name><type>cs_snmp</type><auth_algorithm>sha1</auth_algorithm><privacy><algorithm>aes</algorithm></privacy><vault_id>vault-1</vault_id><host_identifier>auth-host-1</host_identifier><privacy_host_identifier>privacy-host-1</privacy_host_identifier></create_credential>"
    );

    let mut kerberos = CreateCredentialStoreCredentialRequest::new(
        "stored kerberos",
        CredentialStoreCredentialType::Kerberos5,
        "vault-1",
        "host-1",
    );
    kerberos.kdcs = vec!["kdc1.example".into(), "kdc2.example".into()];
    kerberos.realm = Some("EXAMPLE.COM".into());
    assert_eq!(
        xml(&kerberos),
        "<create_credential><name>stored kerberos</name><type>cs_krb5</type><kdcs><kdc>kdc1.example</kdc><kdc>kdc2.example</kdc></kdcs><realm>EXAMPLE.COM</realm><vault_id>vault-1</vault_id><host_identifier>host-1</host_identifier></create_credential>"
    );

    let mut modify = ModifyCredentialStoreCredentialRequest::new(id("credential-1"));
    modify.name = Some("stored renamed".into());
    modify.credential_store_id = Some(id("store-1"));
    modify.kdc = Some("legacy-kdc.example".into());
    modify.kdcs = vec!["new-kdc1.example".into(), "new-kdc2.example".into()];
    modify.realm = Some("NEW.EXAMPLE.COM".into());
    modify.vault_id = Some("vault-2".into());
    modify.host_identifier = Some("host-2".into());
    assert_eq!(
        xml(&modify),
        "<modify_credential credential_id=\"credential-1\"><name>stored renamed</name><credential_store_id>store-1</credential_store_id><kdc>legacy-kdc.example</kdc><kdcs><kdc>new-kdc1.example</kdc><kdc>new-kdc2.example</kdc></kdcs><realm>NEW.EXAMPLE.COM</realm><vault_id>vault-2</vault_id><host_identifier>host-2</host_identifier></modify_credential>"
    );
}

#[test]
fn credential_requests_expose_exact_semantic_command_metadata() {
    fn command(request: &impl GmpRequestCodec) -> (&'static str, Option<&'static str>) {
        let command = request.command().expect("canonical command metadata");
        (command.wire_name(), command.semantic_name())
    }

    assert_eq!(
        command(&GetCredentialsRequest::default()),
        ("get_credentials", None)
    );
    assert_eq!(
        command(&GetCredentialRequest::new(id("credential-1"))),
        ("get_credentials", Some("get_credential"))
    );
    assert_eq!(
        command(&CreateCredentialRequest::new("credential")),
        ("create_credential", None)
    );
    assert_eq!(
        command(&CloneCredentialRequest::new(id("credential-1"))),
        ("create_credential", Some("clone_credential"))
    );
    assert_eq!(
        command(&ModifyCredentialRequest::new(id("credential-1"))),
        ("modify_credential", None)
    );
    assert_eq!(
        command(&DeleteCredentialRequest::new(id("credential-1"), false)),
        ("delete_credential", None)
    );
    assert_eq!(
        command(&GetCredentialStoresRequest::default()),
        ("get_credential_stores", None)
    );
    assert_eq!(
        command(&GetCredentialStoreRequest::new(id("store-1"))),
        ("get_credential_stores", Some("get_credential_store"))
    );
    assert_eq!(
        command(&VerifyCredentialStoreRequest::new(id("store-1"))),
        ("verify_credential_store", None)
    );
    assert_eq!(
        command(&ModifyCredentialStoreRequest::new(id("store-1"))),
        ("modify_credential_store", None)
    );
    assert_eq!(
        command(&CreateCredentialStoreCredentialRequest::new(
            "stored",
            CredentialStoreCredentialType::PasswordOnly,
            "vault-1",
            "host-1",
        )),
        (
            "create_credential",
            Some("create_credential_store_credential")
        )
    );
    assert_eq!(
        command(&ModifyCredentialStoreCredentialRequest::new(id(
            "credential-1"
        ))),
        (
            "modify_credential",
            Some("modify_credential_store_credential")
        )
    );
}

#[test]
fn credential_request_response_associations_are_compile_time_checked() {
    use gvm_gmp::responses::{
        CreateCredentialResponse, DeleteCredentialResponse, GetCredentialStoresResponse,
        GetCredentialsResponse, ModifyCredentialResponse, ModifyCredentialStoreResponse,
        VerifyCredentialStoreResponse,
    };

    fn response_is<R, T>()
    where
        R: GmpRequest<Response = T>,
        T: gvm_gmp::GmpResponse,
    {
    }

    response_is::<GetCredentialsRequest, GetCredentialsResponse>();
    response_is::<GetCredentialRequest, GetCredentialsResponse>();
    response_is::<CreateCredentialRequest, CreateCredentialResponse>();
    response_is::<CloneCredentialRequest, CreateCredentialResponse>();
    response_is::<ModifyCredentialRequest, ModifyCredentialResponse>();
    response_is::<DeleteCredentialRequest, DeleteCredentialResponse>();
    response_is::<GetCredentialStoresRequest, GetCredentialStoresResponse>();
    response_is::<GetCredentialStoreRequest, GetCredentialStoresResponse>();
    response_is::<VerifyCredentialStoreRequest, VerifyCredentialStoreResponse>();
    response_is::<ModifyCredentialStoreRequest, ModifyCredentialStoreResponse>();
    response_is::<CreateCredentialStoreCredentialRequest, CreateCredentialResponse>();
    response_is::<ModifyCredentialStoreCredentialRequest, ModifyCredentialResponse>();
}

#[test]
fn credential_validation_uses_final_values_and_gvmd_type_requirements() {
    let mut empty_name = CreateCredentialRequest::new("credential");
    empty_name.name.clear();
    assert!(matches!(
        empty_name.validate(),
        Err(GmpRequestError::InvalidField { field: "name", .. })
    ));

    let mut key_phrase_without_key = CreateCredentialRequest::new("ssh");
    key_phrase_without_key.key_phrase = Some("phrase-sentinel".into());
    assert!(matches!(
        key_phrase_without_key.validate(),
        Err(GmpRequestError::InvalidCombination {
            fields: &["key_phrase", "private_key", "public_key"],
            ..
        })
    ));

    let mut privacy_without_algorithm = CreateCredentialRequest::new("snmp");
    privacy_without_algorithm.privacy_password = Some("privacy-sentinel".into());
    assert!(matches!(
        privacy_without_algorithm.validate(),
        Err(GmpRequestError::InvalidCombination {
            fields: &["privacy_password", "privacy_algorithm"],
            ..
        })
    ));

    for credential_type in [
        CredentialType::ClientCertificate,
        CredentialType::Kerberos5,
        CredentialType::PgpEncryptionKey,
        CredentialType::SmimeCertificate,
        CredentialType::SnmpV1Or2c,
        CredentialType::SnmpV3,
        CredentialType::UsernamePassword,
        CredentialType::UsernameSshKey,
    ] {
        let mut request = CreateCredentialRequest::new("typed");
        request.credential_type = Some(credential_type);
        assert!(
            request.validate().is_err(),
            "{credential_type:?} must enforce gvmd-required fields"
        );
    }

    let mut ssh = CreateCredentialRequest::new("ssh");
    ssh.credential_type = Some(CredentialType::UsernameSshKey);
    ssh.login = Some("root".into());
    assert!(ssh.validate().is_ok());

    let mut username_password = CreateCredentialRequest::new("generated password");
    username_password.credential_type = Some(CredentialType::UsernamePassword);
    username_password.login = Some("generated-user".into());
    assert!(username_password.validate().is_ok());

    let mut password_only = CreateCredentialRequest::new("generated password only");
    password_only.credential_type = Some(CredentialType::PasswordOnly);
    assert!(password_only.validate().is_ok());

    let mut modify = ModifyCredentialRequest::new(id("credential-1"));
    modify.login = Some(String::new());
    assert!(matches!(
        modify.validate(),
        Err(GmpRequestError::InvalidField { field: "login", .. })
    ));
}

#[test]
fn credential_store_validation_rejects_invalid_mutated_values() {
    let mut create = CreateCredentialStoreCredentialRequest::new(
        "stored",
        CredentialStoreCredentialType::PasswordOnly,
        "vault-1",
        "host-1",
    );
    create.vault_id.clear();
    assert!(matches!(
        create.validate(),
        Err(GmpRequestError::InvalidField {
            field: "vault_id",
            ..
        })
    ));
    create.vault_id = "vault-1".into();
    create.host_identifier.clear();
    assert!(matches!(
        create.validate(),
        Err(GmpRequestError::InvalidField {
            field: "host_identifier",
            ..
        })
    ));

    let snmp = CreateCredentialStoreCredentialRequest::new(
        "stored snmp",
        CredentialStoreCredentialType::Snmp,
        "vault-1",
        "host-1",
    );
    assert!(matches!(
        snmp.validate(),
        Err(GmpRequestError::InvalidField {
            field: "auth_algorithm",
            ..
        })
    ));

    let mut snmp = snmp;
    snmp.auth_algorithm = Some(SnmpAuthAlgorithm::Sha1);
    snmp.privacy_host_identifier = Some("privacy-host-1".into());
    assert!(matches!(
        snmp.validate(),
        Err(GmpRequestError::InvalidCombination {
            fields: &["privacy_host_identifier", "privacy_algorithm"],
            ..
        })
    ));

    let mut kerberos = CreateCredentialStoreCredentialRequest::new(
        "stored kerberos",
        CredentialStoreCredentialType::Kerberos5,
        "vault-1",
        "host-1",
    );
    assert!(matches!(
        kerberos.validate(),
        Err(GmpRequestError::InvalidCombination {
            fields: &["kdc", "kdcs"],
            ..
        })
    ));
    kerberos.kdc = Some("kdc.example".into());
    assert!(matches!(
        kerberos.validate(),
        Err(GmpRequestError::InvalidField { field: "realm", .. })
    ));
    kerberos.realm = Some("EXAMPLE.COM".into());
    assert!(kerberos.validate().is_ok());

    let mut modify = ModifyCredentialStoreCredentialRequest::new(id("credential-1"));
    modify.vault_id = Some(String::new());
    assert!(matches!(
        modify.validate(),
        Err(GmpRequestError::InvalidField {
            field: "vault_id",
            ..
        })
    ));

    let mut store = ModifyCredentialStoreRequest::new(id("store-1"));
    store.preferences.push(CredentialStorePreference {
        name: String::new(),
        value: "preference-sentinel".into(),
    });
    assert!(matches!(
        store.validate(),
        Err(GmpRequestError::InvalidField {
            field: "preference.name",
            ..
        })
    ));
}

#[test]
fn credential_debug_and_error_formatting_do_not_disclose_secrets() {
    let secrets = [
        "password-sentinel",
        "private-key-sentinel",
        "key-phrase-sentinel",
        "public-key-sentinel",
        "certificate-sentinel",
        "community-sentinel",
        "privacy-sentinel",
    ];
    let mut request = CreateCredentialRequest::new("credential");
    request.password = Some(secrets[0].into());
    request.private_key = Some(secrets[1].into());
    request.key_phrase = Some(secrets[2].into());
    request.public_key = Some(secrets[3].into());
    request.certificate = Some(secrets[4].into());
    request.community = Some(secrets[5].into());
    request.privacy_password = Some(secrets[6].into());
    let debug = format!("{request:?}");
    for secret in secrets {
        assert!(!debug.contains(secret));
    }
    assert!(debug.contains("<redacted>"));
    assert!(debug.contains("<present>"));

    request.name.clear();
    let error = request.validate().expect_err("mutated name must fail");
    let error_paths = format!("{error:?}\n{error}");
    for secret in secrets {
        assert!(!error_paths.contains(secret));
    }
    assert!(error.source().is_none());
}

#[test]
fn credential_store_debug_formatting_does_not_disclose_secrets() {
    let secrets = [
        "store-host-sentinel",
        "store-path-sentinel",
        "preference-sentinel",
        "vault-sentinel",
        "host-identifier-sentinel",
        "privacy-host-identifier-sentinel",
    ];
    let mut store = ModifyCredentialStoreRequest::new(id("store-1"));
    store.host = Some(secrets[0].into());
    store.path = Some(secrets[1].into());
    store.preferences.push(CredentialStorePreference {
        name: "token".into(),
        value: secrets[2].into(),
    });
    let mut stored = CreateCredentialStoreCredentialRequest::new(
        "stored",
        CredentialStoreCredentialType::PasswordOnly,
        secrets[3],
        secrets[4],
    );
    stored.credential_store_id = Some(id("store-1"));
    stored.privacy_host_identifier = Some(secrets[5].into());
    let mut modified = ModifyCredentialStoreCredentialRequest::new(id("credential-1"));
    modified.vault_id = Some(secrets[3].into());
    modified.host_identifier = Some(secrets[4].into());
    modified.privacy_host_identifier = Some(secrets[5].into());

    store.preferences[0].name.clear();
    let error = store
        .validate()
        .expect_err("empty preference name must fail");
    let formatted = format!("{store:?}\n{stored:?}\n{modified:?}\n{error:?}\n{error}");
    for secret in secrets {
        assert!(!formatted.contains(secret));
    }
    assert!(formatted.contains("<redacted>"));
    assert!(error.source().is_none());
}
