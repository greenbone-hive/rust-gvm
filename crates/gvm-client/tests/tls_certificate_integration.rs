// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]
#![cfg(feature = "unix-socket-tests")]

use gvm_client::GmpClient;
use gvm_connection::UnixSocketConnection;
use gvm_gmp::commands::tls_certificates::CloneTlsCertificateRequest;
use gvm_gmp::types::EntityId;
use gvm_mock_server::{MockGmpServer, ServerMode};

async fn echo_server() -> Option<MockGmpServer> {
    match MockGmpServer::builder()
        .mode(ServerMode::Echo)
        .unix_socket_auto()
        .build()
        .await
    {
        Ok(server) => Some(server),
        Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(error) => panic!("server should start: {error}"),
    }
}

fn unix_connection(server: &MockGmpServer) -> UnixSocketConnection {
    UnixSocketConnection::with_path(server.socket_path().expect("unix socket path"))
}

#[tokio::test]
async fn canonical_clone_executes_directly_and_through_the_facade() {
    let Some(server) = echo_server().await else {
        return;
    };
    let connection = unix_connection(&server);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("client should connect");

    let request = CloneTlsCertificateRequest::new(EntityId::new("tls1").expect("valid id"));
    let response = client
        .execute(request.clone())
        .await
        .expect("direct clone should execute");
    assert!(!response.id.as_str().is_empty());
    client
        .clone_tls_certificate(request)
        .await
        .expect("facade clone should execute");

    let history = server.command_history();
    assert_eq!(history.len(), 3); // negotiation, direct clone, facade clone
    for command in history
        .iter()
        .filter(|record| record.command_name() == "create_tls_certificate")
    {
        assert_eq!(
            std::str::from_utf8(command.raw_xml()).expect("valid UTF-8 command"),
            "<create_tls_certificate><copy>tls1</copy></create_tls_certificate>"
        );
    }

    server.shutdown().await;
}
