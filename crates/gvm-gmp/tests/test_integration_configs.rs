// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::integration_configs::*;
use gvm_gmp::{GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).unwrap()).unwrap()
}

#[test]
fn test_get_integration_configs_variants() {
    assert_eq!(
        xml(&GetIntegrationConfigsRequest::default()),
        "<get_integration_configs/>"
    );
    assert_eq!(
        xml(&GetIntegrationConfigsRequest {
            filter_string: Some("name=demo".into()),
            filter_id: Some(id("f1")),
        }),
        "<get_integration_configs filt_id=\"f1\" filter=\"name=demo\"/>"
    );
    assert_eq!(
        xml(&GetIntegrationConfigRequest::new(id("ic1"), Some(false))),
        "<get_integration_configs details=\"0\" integration_config_id=\"ic1\"/>"
    );
}

#[test]
fn test_modify_integration_config_variants() {
    assert_eq!(
        xml(&ModifyIntegrationConfigRequest::new(id("ic1"))),
        "<modify_integration_config uuid=\"ic1\"><service><url></url><cacert></cacert></service><oidc><url></url><client><id></id><secret></secret></client></oidc></modify_integration_config>"
    );
    assert_eq!(
        {
            let mut request = ModifyIntegrationConfigRequest::new(id("ic1"));
            request.service_url = Some("https://service.example".into());
            request.oidc_provider_url = Some("https://oidc.example".into());
            request.oidc_provider_client_id = Some("client-id".into());
            request.oidc_provider_client_secret = Some("client-secret".into());
            xml(&request)
        },
        "<modify_integration_config uuid=\"ic1\"><service><url>https://service.example</url><cacert></cacert></service><oidc><url>https://oidc.example</url><client><id>client-id</id><secret>client-secret</secret></client></oidc></modify_integration_config>"
    );

    let mut partial = ModifyIntegrationConfigRequest::new(id("ic1"));
    partial.service_url = Some("https://partial.example".into());
    assert!(matches!(
        partial.validate(),
        Err(GmpRequestError::InvalidCombination { .. })
    ));
}
