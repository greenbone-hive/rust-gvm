// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs)]

use std::collections::VecDeque;
use std::io;

use async_trait::async_trait;
use gvm_client::GmpClient;
use gvm_connection::{ConnectionError, GvmConnection};
use gvm_gmp::commands::nvts::GetNvtsRequest;
use gvm_gmp::commands::results::GetResultsRequest;

struct ScriptedConnection {
    responses: VecDeque<Vec<u8>>,
    connected: bool,
}

impl ScriptedConnection {
    fn new(responses: impl IntoIterator<Item = &'static str>) -> Self {
        Self {
            responses: responses
                .into_iter()
                .map(|response| response.as_bytes().to_vec())
                .collect(),
            connected: false,
        }
    }
}

#[async_trait]
impl GvmConnection for ScriptedConnection {
    async fn connect(&mut self) -> gvm_connection::Result<()> {
        self.connected = true;
        Ok(())
    }

    async fn disconnect(&mut self) -> gvm_connection::Result<()> {
        self.connected = false;
        Ok(())
    }

    async fn send(&mut self, _data: &[u8]) -> gvm_connection::Result<()> {
        if self.connected {
            Ok(())
        } else {
            Err(ConnectionError::NotConnected)
        }
    }

    async fn read(&mut self) -> gvm_connection::Result<Vec<u8>> {
        self.responses.pop_front().ok_or_else(|| {
            ConnectionError::ReadFailed(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "scripted response exhausted",
            ))
        })
    }

    fn is_connected(&self) -> bool {
        self.connected
    }
}

#[tokio::test]
async fn typed_execution_delivers_refs_to_result_and_catalog_callers() {
    let connection = ScriptedConnection::new([
        r#"<get_version_response status="200" status_text="OK"><version>22.8</version></get_version_response>"#,
        r#"<get_results_response status="200" status_text="OK"><result id="result-1"><nvt oid="1"><name>Result NVT</name><refs><ref type="url" id="https://example.test/result"/></refs></nvt></result></get_results_response>"#,
        r#"<get_nvts_response status="200" status_text="OK"><nvt oid="2"><name>Catalog NVT</name><refs><ref type="dfn-cert" id="DFN-CERT-2026-0002"/></refs></nvt></get_nvts_response>"#,
    ]);
    let mut client = GmpClient::connect(connection)
        .await
        .expect("scripted client connects");

    let results = client
        .execute(GetResultsRequest::default())
        .await
        .expect("typed result execution succeeds");
    let catalog = client
        .get_nvts(GetNvtsRequest {
            details: Some(true),
            ..GetNvtsRequest::default()
        })
        .await
        .expect("typed NVT facade succeeds");

    let result_ref = &results.items[0]
        .nvt
        .as_ref()
        .expect("result NVT is projected")
        .refs[0];
    assert_eq!(result_ref.type_, "url");
    assert_eq!(result_ref.id, "https://example.test/result");
    assert_eq!(catalog.items[0].refs[0].type_, "dfn-cert");
    assert_eq!(catalog.items[0].refs[0].id, "DFN-CERT-2026-0002");
}
