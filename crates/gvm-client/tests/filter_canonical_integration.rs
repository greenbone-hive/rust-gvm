// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::filters::{
    CloneFilterRequest, CreateFilterRequest, DeleteFilterRequest, GetFilterRequest,
    GetFiltersRequest, ModifyFilterRequest,
};
use gvm_gmp::FilterType;
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

async fn stateful_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Stateful)
        .version(MockVersion::V22_4)
        .credentials("admin", "admin")
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

#[tokio::test]
async fn canonical_filter_requests_round_trip_through_stateful_mock() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("Unix socket path"),
    ))
    .await
    .expect("client should connect");
    client
        .authenticate("admin", "admin")
        .await
        .expect("authentication should succeed");
    server.clear_history();

    let mut create = CreateFilterRequest::new("Original filter");
    create.comment = Some("created canonically".into());
    create.term = Some("rows=10".into());
    create.filter_type = Some(FilterType::Task);
    let created = client
        .create_filter(create)
        .await
        .expect("filter creation should succeed");

    let mut detail = GetFilterRequest::new(created.id.clone());
    detail.alerts = Some(true);
    let fetched = client
        .get_filter(detail)
        .await
        .expect("filter detail should succeed");
    let filter = fetched.items.first().expect("created filter returned");
    assert_eq!(filter.meta.name, "Original filter");
    assert_eq!(filter.meta.comment.as_deref(), Some("created canonically"));
    assert_eq!(filter.term.as_deref(), Some("rows=10"));
    assert_eq!(filter.type_.as_deref(), Some("task"));

    let mut modify = ModifyFilterRequest::new(created.id.clone());
    modify.name = Some("Renamed filter".into());
    modify.comment = Some(String::new());
    modify.term = Some(String::new());
    modify.filter_type = Some(FilterType::Result);
    client
        .modify_filter(modify)
        .await
        .expect("filter modification should succeed");

    let fetched = client
        .get_filter(GetFilterRequest::new(created.id.clone()))
        .await
        .expect("modified filter should be retrievable");
    let filter = fetched.items.first().expect("modified filter returned");
    assert_eq!(filter.meta.name, "Renamed filter");
    assert_eq!(filter.meta.comment, None);
    assert_eq!(filter.term, None);
    assert_eq!(filter.type_.as_deref(), Some("result"));

    let mut clone = CloneFilterRequest::new(created.id.clone());
    clone.name = Some("Cloned filter".into());
    clone.comment = Some("clone override".into());
    let cloned = client
        .clone_filter(clone)
        .await
        .expect("filter clone should succeed");

    let listed = client
        .get_filters(GetFiltersRequest::default())
        .await
        .expect("filter list should succeed");
    assert!(listed.items.iter().any(|item| item.meta.id == created.id));
    let clone = listed
        .items
        .iter()
        .find(|item| item.meta.id == cloned.id)
        .expect("cloned filter should be listed");
    assert_eq!(clone.meta.name, "Cloned filter");
    assert_eq!(clone.meta.comment.as_deref(), Some("clone override"));
    assert_eq!(clone.type_.as_deref(), Some("result"));

    client
        .delete_filter(DeleteFilterRequest::new(created.id.clone(), false))
        .await
        .expect("filter trash should succeed");
    let trashed = client
        .get_filters(GetFiltersRequest {
            trash: Some(true),
            ..Default::default()
        })
        .await
        .expect("trash list should succeed");
    assert!(trashed.items.iter().any(|item| item.meta.id == created.id));

    client
        .delete_filter(DeleteFilterRequest::new(cloned.id, true))
        .await
        .expect("ultimate clone deletion should succeed");

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        std::str::from_utf8(record.raw_xml())
            .is_ok_and(|xml| xml.contains("<get_filters alerts=\"1\" details=\"1\""))
    }));
    assert!(history.iter().all(|record| {
        std::str::from_utf8(record.raw_xml()).is_ok_and(|xml| !xml.contains("sort_order"))
    }));

    server.shutdown().await;
}
