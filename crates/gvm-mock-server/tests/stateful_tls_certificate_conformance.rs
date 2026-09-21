// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::too_many_lines, clippy::unwrap_used)]
#![cfg(feature = "unix-socket-tests")]

use std::sync::{Arc, Mutex};

use base64::Engine as _;
use gvm_mock_server::{GmpVersion, MockGmpServer, Resource, ResourceStore, ServerMode};
use gvm_protocol::Response;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use uuid::Uuid;

const CERT_A_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\nMOCK-A\n-----END CERTIFICATE-----\n";
const CERT_A_DER: &[u8] = b"\x30\x82MOCK-A-DER\0\xff";
const CERT_B_PEM: &[u8] = b"-----BEGIN CERTIFICATE-----\r\nMOCK-B\r\n-----END CERTIFICATE-----\r\n";
const INVALID_CERTIFICATE: &[u8] = b"mock-invalid-certificate";
const CERT_A_SHA: &str = "AA:AA:AA:AA:AA:AA:AA:AA";
const CERT_A_MD5: &str = "AA:AA:AA:AA";
const CERT_B_SHA: &str = "BB:BB:BB:BB:BB:BB:BB:BB";
const CERT_B_MD5: &str = "BB:BB:BB:BB";
const FOREIGN_A: Uuid = Uuid::from_u128(0xa0000000000000000000000000000001);
const FOREIGN_B: Uuid = Uuid::from_u128(0xb0000000000000000000000000000001);
const FOREIGN_C: Uuid = Uuid::from_u128(0xc0000000000000000000000000000002);
const OWN_A: Uuid = Uuid::from_u128(0xa0000000000000000000000000000002);
const OWN_OTHER: Uuid = Uuid::from_u128(0xc0000000000000000000000000000001);
const SAVED_FILTER: Uuid = Uuid::from_u128(0xd0000000000000000000000000000001);
const SHARED_SOURCE: &str = "e0000000-0000-0000-0000-000000000001";

async fn server(
    seed: impl FnOnce(&ResourceStore) + Send + 'static,
) -> (MockGmpServer, ResourceStore) {
    let observed = Arc::new(Mutex::new(None));
    let observed_seed = Arc::clone(&observed);
    let server = MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(GmpVersion::V22_8)
        .credentials("admin", "admin")
        .seed(move |store| {
            seed(store);
            *observed_seed.lock().expect("store slot") = Some(store.clone());
        })
        .unix_socket_auto()
        .build()
        .await
        .expect("server starts");
    let store = observed
        .lock()
        .expect("store slot")
        .clone()
        .expect("seed closure ran");
    (server, store)
}

async fn connect(server: &MockGmpServer) -> UnixStream {
    let mut stream = UnixStream::connect(server.socket_path().unwrap())
        .await
        .unwrap();
    let response = exchange(&mut stream, b"<authenticate><credentials><username>admin</username><password>admin</password></credentials></authenticate>").await;
    assert_eq!(response.status_code(), Some(200));
    stream
}

async fn exchange(stream: &mut UnixStream, xml: &[u8]) -> Response {
    stream.write_all(xml).await.unwrap();
    let mut bytes = vec![0; 256 * 1024];
    let size = stream.read(&mut bytes).await.unwrap();
    bytes.truncate(size);
    Response::new(bytes)
}

async fn send(stream: &mut UnixStream, xml: impl AsRef<[u8]>) -> Response {
    exchange(stream, xml.as_ref()).await
}

fn body(response: &Response) -> &str {
    response.as_str().expect("UTF-8 response")
}

fn created_id(response: &Response) -> Uuid {
    assert_eq!(response.status_code(), Some(201), "{}", body(response));
    Uuid::parse_str(&response.id().expect("created ID")).unwrap()
}

fn create(bytes: &[u8], extra: &str) -> String {
    let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
    format!("<create_tls_certificate>{extra}<certificate>{encoded}</certificate></create_tls_certificate>")
}

fn seeded_certificate(
    id: Uuid,
    owner: &str,
    name: &str,
    comment: &str,
    certificate: &[u8],
    sha: &str,
    md5: &str,
) -> Resource {
    let mut resource = Resource::with_id("tls_certificate", name, id);
    resource.comment = comment.to_string();
    resource.set_attr("owner", owner);
    resource.set_attr(
        "certificate",
        &base64::engine::general_purpose::STANDARD.encode(certificate),
    );
    resource.set_attr(
        "certificate_format",
        if certificate == CERT_A_DER {
            "DER"
        } else {
            "PEM"
        },
    );
    resource.set_attr("sha256_fingerprint", sha);
    resource.set_attr("md5_fingerprint", md5);
    resource.set_attr("subject_dn", "CN=seeded.example");
    resource.set_attr("issuer_dn", "CN=Mock Test CA");
    resource.set_attr("activation_time", "2026-01-01T00:00:00Z");
    resource.set_attr("expiration_time", "2036-01-01T00:00:00Z");
    resource.set_attr("serial", "01");
    resource.set_attr("valid", "1");
    resource.set_attr("time_status", "valid");
    resource.set_attr("trust", "1");
    resource
}

#[tokio::test]
async fn create_validates_registered_payloads_defaults_and_owner_fingerprint_identity() {
    let (server, store) = server(|store| {
        let mut foreign = seeded_certificate(
            FOREIGN_B, "bob", "Bob B", "foreign", CERT_B_PEM, CERT_B_SHA, CERT_B_MD5,
        );
        foreign.set_attr("visible_to", "admin");
        store.seed(foreign);
    })
    .await;
    let mut stream = connect(&server).await;
    let before = store.list("tls_certificate").len();
    for xml in [
        "<create_tls_certificate/>",
        "<create_tls_certificate><certificate></certificate></create_tls_certificate>",
        "<create_tls_certificate><certificate>not-base64!</certificate></create_tls_certificate>",
        &create(INVALID_CERTIFICATE, ""),
        &create(b"unregistered-certificate", ""),
    ] {
        let response = send(&mut stream, xml).await;
        assert_eq!(response.status_code(), Some(400), "{}", body(&response));
        assert_eq!(store.list("tls_certificate").len(), before);
    }

    let created = created_id(&send(&mut stream, create(CERT_A_PEM, "")).await);
    let detail = send(
        &mut stream,
        format!("<get_tls_certificates tls_certificate_id=\"{created}\" details=\"1\"/>"),
    )
    .await;
    for expected in [
        "<owner><name>admin</name></owner>",
        &format!("<name>{CERT_A_SHA}</name>"),
        "<comment></comment>",
        "<trust>0</trust>",
        "<valid>1</valid>",
        "<origin_type>Import</origin_type>",
    ] {
        assert!(body(&detail).contains(expected), "{}", body(&detail));
    }

    let pem_der_duplicate = send(&mut stream, create(CERT_A_DER, "<name>different</name>")).await;
    assert_eq!(pem_der_duplicate.status_code(), Some(400));
    let foreign_fingerprint_for_new_owner = created_id(
        &send(
            &mut stream,
            create(CERT_B_PEM, "<name>  preserved  </name><trust>1</trust>"),
        )
        .await,
    );
    let detail = send(
        &mut stream,
        format!(
            "<get_tls_certificates tls_certificate_id=\"{foreign_fingerprint_for_new_owner}\"/>"
        ),
    )
    .await;
    assert!(body(&detail).contains("<name>  preserved  </name>"));
    assert!(body(&detail).contains("<trust>1</trust>"));
    assert_eq!(store.list("tls_certificate").len(), before + 2);
    server.shutdown().await;
}

#[tokio::test]
async fn create_checks_each_fingerprint_and_empty_name_fallback_independently() {
    for (sha, md5) in [(CERT_B_SHA, "different-md5"), ("different-sha", CERT_B_MD5)] {
        let (server, store) = server(move |store| {
            store.seed(seeded_certificate(
                OWN_A,
                "admin",
                "Collision",
                "",
                b"independent-collision-fixture",
                sha,
                md5,
            ));
        })
        .await;
        let mut stream = connect(&server).await;
        let before = store.list("tls_certificate").len();
        let response = send(&mut stream, create(CERT_B_PEM, "")).await;
        assert_eq!(response.status_code(), Some(400));
        assert_eq!(store.list("tls_certificate").len(), before);
        server.shutdown().await;
    }

    let (server, _store) = server(|_| {}).await;
    let mut stream = connect(&server).await;
    let created = created_id(
        &send(
            &mut stream,
            create(CERT_B_PEM, "<name></name><comment></comment>"),
        )
        .await,
    );
    let detail = send(
        &mut stream,
        format!("<get_tls_certificates tls_certificate_id=\"{created}\"/>"),
    )
    .await;
    assert!(body(&detail).contains(&format!("<name>{CERT_B_SHA}</name>")));
    let active = send(&mut stream, "<get_tls_certificates trash=\"0\"/>").await;
    assert_eq!(active.status_code(), Some(200));
    server.shutdown().await;
}

#[tokio::test]
async fn clone_obeys_visibility_collisions_empty_overrides_and_copy_precedence() {
    let (server, _store) = server(|store| {
        let mut foreign = seeded_certificate(
            FOREIGN_A,
            "bob",
            "Foreign A",
            "source comment",
            CERT_A_PEM,
            CERT_A_SHA,
            CERT_A_MD5,
        );
        foreign.set_attr("visible_to", "admin");
        foreign.set_attr("tag_ids", "f0000000-0000-0000-0000-000000000001");
        foreign.set_attr("source_id", SHARED_SOURCE);
        foreign.set_attr("source_origin_type", "Report");
        foreign.set_attr("last_seen", "2026-09-19T00:00:00Z");
        store.seed(foreign);

        let own = seeded_certificate(
            OWN_OTHER,
            "admin",
            "Conflict",
            "own",
            b"other-seeded-certificate",
            "CC:CC:CC:CC",
            "CC:CC",
        );
        store.seed(own);

        let mut foreign_b = seeded_certificate(
            FOREIGN_B,
            "bob",
            "Foreign B",
            "B comment",
            CERT_B_PEM,
            CERT_B_SHA,
            CERT_B_MD5,
        );
        foreign_b.set_attr("visible_to", "admin");
        store.seed(foreign_b);

        let mut foreign_c = seeded_certificate(
            FOREIGN_C,
            "bob",
            "Foreign C",
            "C comment",
            b"foreign-certificate-c",
            "EE:EE:EE:EE",
            "EE:EE",
        );
        foreign_c.set_attr("visible_to", "admin");
        store.seed(foreign_c);

        let invisible = seeded_certificate(
            Uuid::from_u128(0xb0000000000000000000000000000002),
            "carol",
            "Invisible",
            "hidden",
            b"hidden",
            "DD:DD",
            "DD",
        );
        store.seed(invisible);
    })
    .await;
    let mut stream = connect(&server).await;

    let clone = created_id(
        &send(
            &mut stream,
            format!(
                "<create_tls_certificate><copy>{FOREIGN_A}</copy><name></name><comment></comment><certificate>{}</certificate><trust>0</trust></create_tls_certificate>",
                base64::engine::general_purpose::STANDARD.encode(CERT_B_PEM),
            ),
        )
        .await,
    );
    let detail = send(
        &mut stream,
        format!("<get_tls_certificates tls_certificate_id=\"{clone}\" details=\"1\"/>"),
    )
    .await;
    for expected in [
        "<owner><name>admin</name></owner>",
        "<name>Foreign A</name>",
        "<comment>source comment</comment>",
        &format!("<sha256_fingerprint>{CERT_A_SHA}</sha256_fingerprint>"),
        "<trust>1</trust>",
        "<tag id=\"f0000000-0000-0000-0000-000000000001\"",
        "<sources></sources>",
        "<last_seen></last_seen>",
    ] {
        assert!(body(&detail).contains(expected), "{}", body(&detail));
    }
    assert!(!body(&detail).contains("<origin_type>Report</origin_type>"));

    let same_fingerprint = send(
        &mut stream,
        format!("<create_tls_certificate><copy>{FOREIGN_A}</copy><name>new</name></create_tls_certificate>"),
    )
    .await;
    assert_eq!(same_fingerprint.status_code(), Some(400));

    let name_collision = send(
        &mut stream,
        format!("<create_tls_certificate><copy>{FOREIGN_B}</copy><name>Conflict</name></create_tls_certificate>"),
    )
    .await;
    assert_eq!(name_collision.status_code(), Some(400));

    let overridden = created_id(
        &send(
            &mut stream,
            format!(
                "<create_tls_certificate><copy>{FOREIGN_C}</copy><name>  C copy  </name><comment>replacement</comment></create_tls_certificate>"
            ),
        )
        .await,
    );
    let overridden_detail = send(
        &mut stream,
        format!("<get_tls_certificates tls_certificate_id=\"{overridden}\"/>"),
    )
    .await;
    assert!(body(&overridden_detail).contains("<name>  C copy  </name>"));
    assert!(body(&overridden_detail).contains("<comment>replacement</comment>"));
    let missing = send(
        &mut stream,
        "<create_tls_certificate><copy>ffffffff-ffff-ffff-ffff-ffffffffffff</copy></create_tls_certificate>",
    )
    .await;
    assert_eq!(missing.status_code(), Some(404));
    let inaccessible = send(
        &mut stream,
        "<create_tls_certificate><copy>b0000000-0000-0000-0000-000000000002</copy></create_tls_certificate>",
    )
    .await;
    assert_eq!(inaccessible.status_code(), Some(404));
    server.shutdown().await;
}

#[tokio::test]
async fn modify_and_query_model_clear_preserve_expansion_filter_and_id_bypass() {
    let (server, store) = server(|store| {
        let mut a = seeded_certificate(
            OWN_A, "admin", "Alpha", "original", CERT_A_PEM, CERT_A_SHA, CERT_A_MD5,
        );
        a.set_attr("source_id", SHARED_SOURCE);
        a.set_attr("source_origin_type", "Import");
        a.set_attr("last_seen", "2026-09-19T00:00:00Z");
        a.set_attr("host_ids", "10000000-0000-0000-0000-000000000001");
        a.set_attr("report_ids", "20000000-0000-0000-0000-000000000001");
        store.seed(a);
        let b = seeded_certificate(
            OWN_OTHER, "admin", "Beta", "second", CERT_B_PEM, CERT_B_SHA, CERT_B_MD5,
        );
        store.seed(b);
        let mut filter = Resource::with_id("filter", "Alpha only", SAVED_FILTER);
        filter.set_attr("term", "name=Alpha rows=1");
        store.seed(filter);
    })
    .await;
    let mut stream = connect(&server).await;
    let before = store.get(&OWN_A).unwrap();

    let compact = send(
        &mut stream,
        "<get_tls_certificates filter=\"sort=name rows=1\" include_certificate_data=\"0\" ignore_pagination=\"1\"/>",
    )
    .await;
    assert!(body(&compact).contains("<tls_certificate_count>2<filtered>2</filtered><page>1</page>"));
    assert!(body(&compact).contains("<certificate format=\"PEM\"></certificate>"));
    assert!(!body(&compact).contains("<sources>"));

    let data_only = send(
        &mut stream,
        "<get_tls_certificates filter=\"name=Alpha\" include_certificate_data=\"1\" details=\"0\"/>",
    )
    .await;
    assert!(
        body(&data_only).contains(&base64::engine::general_purpose::STANDARD.encode(CERT_A_PEM))
    );
    assert!(!body(&data_only).contains("<sources>"));

    let details = send(
        &mut stream,
        "<get_tls_certificates filter=\"host_id=10000000-0000-0000-0000-000000000001\" details=\"1\" include_certificate_data=\"0\"/>",
    )
    .await;
    assert!(body(&details).contains("<sources><source"));
    assert!(body(&details).contains(&base64::engine::general_purpose::STANDARD.encode(CERT_A_PEM)));

    let saved = send(
        &mut stream,
        format!("<get_tls_certificates filt_id=\"{SAVED_FILTER}\" filter=\"name=Beta\"/>"),
    )
    .await;
    assert!(body(&saved).contains("<name>Alpha</name>"));
    assert!(!body(&saved).contains("<name>Beta</name>"));

    let selected = send(
        &mut stream,
        format!(
            "<get_tls_certificates tls_certificate_id=\"{OWN_A}\" filter=\"name=Nope rows=0\"/>"
        ),
    )
    .await;
    assert!(body(&selected).contains("<name>Alpha</name>"));

    let no_op = send(
        &mut stream,
        format!("<modify_tls_certificate tls_certificate_id=\"{OWN_A}\"><private>ignored</private><certificate>ignored</certificate><copy>ignored</copy></modify_tls_certificate>"),
    )
    .await;
    assert_eq!(no_op.status_code(), Some(200));
    assert_eq!(
        store.get(&OWN_A).unwrap().modification_time,
        before.modification_time
    );

    let modified = send(
        &mut stream,
        format!("<modify_tls_certificate tls_certificate_id=\"{OWN_A}\"><name></name><comment></comment><trust>0</trust></modify_tls_certificate>"),
    )
    .await;
    assert_eq!(modified.status_code(), Some(200));
    let after = store.get(&OWN_A).unwrap();
    assert_eq!(after.name, "");
    assert_eq!(after.comment, "");
    assert_eq!(after.attr("trust"), Some("0"));
    assert_eq!(after.attr("valid"), Some("1"));
    assert_eq!(after.attr("certificate"), before.attr("certificate"));

    let colliding_name_is_not_preflighted = send(
        &mut stream,
        format!(
            "<modify_tls_certificate tls_certificate_id=\"{OWN_A}\"><name>Beta</name><trust>1</trust></modify_tls_certificate>"
        ),
    )
    .await;
    assert_eq!(colliding_name_is_not_preflighted.status_code(), Some(200));
    let after = store.get(&OWN_A).unwrap();
    assert_eq!(after.name, "Beta");
    assert_eq!(after.comment, "");
    assert_eq!(after.attr("trust"), Some("1"));
    assert_eq!(after.attr("valid"), Some("1"));

    let read_before = after.clone();
    let _ = send(
        &mut stream,
        format!("<get_tls_certificates tls_certificate_id=\"{OWN_A}\" details=\"1\"/>"),
    )
    .await;
    let read_after = store.get(&OWN_A).unwrap();
    assert_eq!(read_after.name, read_before.name);
    assert_eq!(read_after.comment, read_before.comment);
    assert_eq!(read_after.attrs, read_before.attrs);

    let trash = send(&mut stream, "<get_tls_certificates trash=\"1\"/>").await;
    assert_eq!(trash.status_code(), Some(400));
    let unsupported = send(
        &mut stream,
        "<get_tls_certificates filter=\"unknown=value\"/>",
    )
    .await;
    assert_eq!(unsupported.status_code(), Some(400));
    server.shutdown().await;
}

#[tokio::test]
async fn deletion_is_permanent_for_every_ultimate_spelling_and_preserves_other_resources() {
    let delete_ids = [
        Uuid::from_u128(0x90000000000000000000000000000001),
        Uuid::from_u128(0x90000000000000000000000000000002),
        Uuid::from_u128(0x90000000000000000000000000000003),
    ];
    let (server, store) = server(move |store| {
        for (index, id) in delete_ids.into_iter().enumerate() {
            let mut certificate = seeded_certificate(
                id,
                "admin",
                &format!("Delete {index}"),
                "delete",
                CERT_A_PEM,
                &format!("{index}:SHA"),
                &format!("{index}:MD5"),
            );
            certificate.set_attr("source_id", SHARED_SOURCE);
            certificate.set_attr("tag_ids", "f0000000-0000-0000-0000-000000000001");
            store.seed(certificate);
        }
        let mut survivor = seeded_certificate(
            Uuid::from_u128(0x90000000000000000000000000000004),
            "admin",
            "Survivor",
            "shared observation",
            CERT_B_PEM,
            CERT_B_SHA,
            CERT_B_MD5,
        );
        survivor.set_attr("source_id", SHARED_SOURCE);
        store.seed(survivor);
        store.seed(Resource::with_id(
            "report",
            "Unrelated report",
            Uuid::from_u128(0x91000000000000000000000000000001),
        ));
        store.seed(Resource::with_id(
            "asset",
            "Unrelated host",
            Uuid::from_u128(0x92000000000000000000000000000001),
        ));
    })
    .await;
    let mut stream = connect(&server).await;

    for (id, ultimate) in [
        (delete_ids[0], ""),
        (delete_ids[1], " ultimate=\"0\""),
        (delete_ids[2], " ultimate=\"1\""),
    ] {
        let response = send(
            &mut stream,
            format!("<delete_tls_certificate tls_certificate_id=\"{id}\"{ultimate}/>"),
        )
        .await;
        assert_eq!(response.status_code(), Some(200));
        assert!(store.get(&id).is_none());
        let detail = send(
            &mut stream,
            format!("<get_tls_certificates tls_certificate_id=\"{id}\"/>"),
        )
        .await;
        assert_eq!(detail.status_code(), Some(404));
        let restore = send(&mut stream, format!("<restore id=\"{id}\"/>")).await;
        assert_eq!(restore.status_code(), Some(404));
    }
    assert_eq!(store.list("tls_certificate").len(), 1);
    assert_eq!(store.list("report").len(), 1);
    assert_eq!(store.list("asset").len(), 1);
    let survivor = &store.list("tls_certificate")[0];
    assert_eq!(survivor.attr("source_id"), Some(SHARED_SOURCE));
    server.shutdown().await;
}
