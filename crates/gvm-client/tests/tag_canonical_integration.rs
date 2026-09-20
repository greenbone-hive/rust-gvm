// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::tags::{
    CloneTagRequest, CreateTagRequest, DeleteTagRequest, GetTagRequest, GetTagsRequest,
    ModifyTagRequest, TagResourceAction, TagResourceUpdate, TagResources,
};
use gvm_gmp::{EntityId, EntityType};
use gvm_mock_server::{GmpVersion as MockVersion, MockGmpServer, ServerMode};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid entity id")
}

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
#[allow(clippy::too_many_lines)]
async fn canonical_tag_requests_round_trip_through_stateful_mock() {
    let Some(server) = stateful_server().await else {
        return;
    };
    let mut client = GmpClient::connect(UnixSocketConnection::with_path(
        server.socket_path().expect("Unix socket path"),
    ))
    .await
    .expect("client should connect");
    client
        .authenticate(gvm_gmp::commands::authentication::AuthenticateRequest::new(
            "admin", "admin",
        ))
        .await
        .expect("authentication should succeed");
    server.clear_history();

    let mut resources = TagResources::new(EntityType::Task);
    resources.resource_ids = vec![id("task-1"), id("task-2")];
    resources.filter = Some("status=Running".into());
    let mut create = CreateTagRequest::new("Original tag", resources);
    create.comment = Some("created canonically".into());
    create.value = Some("blue".into());
    create.active = Some(true);
    let created = client
        .create_tag(create)
        .await
        .expect("tag creation should succeed");

    let fetched = client
        .get_tag(GetTagRequest::new(created.id.clone()))
        .await
        .expect("tag detail should succeed");
    let tag = fetched.items.first().expect("created tag returned");
    assert_eq!(tag.meta.name, "Original tag");
    assert_eq!(tag.meta.comment.as_deref(), Some("created canonically"));
    assert_eq!(tag.value.as_deref(), Some("blue"));
    assert_eq!(tag.resource_type.as_deref(), Some("task"));
    assert_eq!(tag.resource_count, Some(2));
    assert!(tag.active);

    let mut update_resources = TagResources::new(EntityType::Policy);
    update_resources.resource_ids = vec![id("config-1")];
    update_resources.filter = Some("name=baseline".into());
    let mut modify = ModifyTagRequest::new(created.id.clone());
    modify.name = Some("Renamed tag".into());
    modify.comment = Some(String::new());
    modify.value = Some(String::new());
    modify.resource_update = Some(TagResourceUpdate {
        resources: update_resources,
        action: Some(TagResourceAction::Set),
    });
    modify.active = Some(false);
    client
        .modify_tag(modify)
        .await
        .expect("tag modification should succeed");

    let fetched = client
        .get_tag(GetTagRequest::new(created.id.clone()))
        .await
        .expect("modified tag should be retrievable");
    let tag = fetched.items.first().expect("modified tag returned");
    assert_eq!(tag.meta.name, "Renamed tag");
    assert_eq!(tag.meta.comment, None);
    assert_eq!(tag.value, None);
    assert_eq!(tag.resource_type.as_deref(), Some("config"));
    assert_eq!(tag.resource_count, Some(1));
    assert!(!tag.active);

    let mut add = ModifyTagRequest::new(created.id.clone());
    let mut add_resources = TagResources::new(EntityType::Config);
    add_resources.resource_ids = vec![id("config-2")];
    add.resource_update = Some(TagResourceUpdate {
        resources: add_resources,
        action: Some(TagResourceAction::Add),
    });
    client
        .modify_tag(add)
        .await
        .expect("resource addition should succeed");
    let fetched = client
        .get_tag(GetTagRequest::new(created.id.clone()))
        .await
        .expect("tag after resource addition should be retrievable");
    assert_eq!(fetched.items[0].resource_count, Some(2));

    let mut remove = ModifyTagRequest::new(created.id.clone());
    let mut remove_resources = TagResources::new(EntityType::Config);
    remove_resources.resource_ids = vec![id("config-1")];
    remove.resource_update = Some(TagResourceUpdate {
        resources: remove_resources,
        action: Some(TagResourceAction::Remove),
    });
    client
        .modify_tag(remove)
        .await
        .expect("resource removal should succeed");
    let fetched = client
        .get_tag(GetTagRequest::new(created.id.clone()))
        .await
        .expect("tag after resource removal should be retrievable");
    assert_eq!(fetched.items[0].resource_count, Some(1));

    let mut clone = CloneTagRequest::new(created.id.clone());
    clone.name = Some("Cloned tag".into());
    clone.comment = Some("clone override".into());
    let cloned = client
        .clone_tag(clone)
        .await
        .expect("tag clone should succeed");

    let listed = client
        .get_tags(GetTagsRequest {
            names_only: Some(true),
            ..Default::default()
        })
        .await
        .expect("tag list should succeed");
    assert!(listed.items.iter().any(|item| item.meta.id == created.id));
    let clone = listed
        .items
        .iter()
        .find(|item| item.meta.id == cloned.id)
        .expect("cloned tag should be listed");
    assert_eq!(clone.meta.name, "Cloned tag");
    assert_eq!(clone.meta.comment.as_deref(), Some("clone override"));
    assert_eq!(clone.resource_type.as_deref(), Some("config"));

    client
        .delete_tag(DeleteTagRequest::new(created.id.clone(), false))
        .await
        .expect("tag trash should succeed");
    let trashed = client
        .get_tags(GetTagsRequest {
            trash: Some(true),
            ..Default::default()
        })
        .await
        .expect("trash list should succeed");
    assert!(trashed.items.iter().any(|item| item.meta.id == created.id));

    client
        .delete_tag(DeleteTagRequest::new(cloned.id, true))
        .await
        .expect("ultimate clone deletion should succeed");

    let history = server.command_history();
    assert!(history.iter().any(|record| {
        std::str::from_utf8(record.raw_xml())
            .is_ok_and(|xml| xml.contains("<get_tags names_only=\"1\""))
    }));
    assert!(history.iter().any(|record| {
        std::str::from_utf8(record.raw_xml()).is_ok_and(|xml| {
            xml.contains("<resources action=\"set\" filter=\"name=baseline\"")
                && xml.contains("<type>config</type>")
                && xml.contains("<value></value><comment></comment>")
        })
    }));
    assert!(history.iter().all(|record| {
        std::str::from_utf8(record.raw_xml()).is_ok_and(|xml| !xml.contains("severity"))
    }));

    server.shutdown().await;
}
