// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Compile coverage for the complete public README quick start.

#![allow(clippy::print_stdout, dead_code, missing_docs)]

use gvm_client::GmpClient;
use gvm_connection::{UnixSocketConfig, UnixSocketConnection};
use gvm_gmp::commands::targets::{CreateTargetRequest, GetTargetsRequest};
use gvm_gmp::commands::tasks::{CreateTaskRequest, StartTaskRequest};
use gvm_gmp::{TargetHost, TargetHosts, TargetPortSelection};

async fn quick_start_compiles() -> Result<(), Box<dyn std::error::Error>> {
    let conn = UnixSocketConnection::new(UnixSocketConfig::new("/run/gvmd/gvmd.sock"));
    let mut client = GmpClient::connect(conn).await?;
    println!("Connected, GMP version: {}", client.version());

    client.authenticate("admin", "admin").await?;

    let hosts = TargetHosts::new(["192.168.1.0/24".parse::<TargetHost>()?], [])?;
    let ports = TargetPortSelection::PortRange("T:1-65535".parse()?);
    let target = client
        .create_target(CreateTargetRequest::new("My Target", hosts, ports))
        .await?;
    println!("Created target: {}", target.id);

    let targets = client.get_targets(GetTargetsRequest::default()).await?;
    for target in &targets.items {
        println!("  {} — {}", target.meta.id, target.meta.name);
    }

    let config_id = "daba56c8-73ec-11df-a475-002264764cea".parse()?;
    let scanner_id = "08b69003-5fc2-4037-a479-93b440211c73".parse()?;
    let task = client
        .create_task(CreateTaskRequest::new(
            "My Scan", config_id, target.id, scanner_id,
        ))
        .await?;
    client
        .start_task(StartTaskRequest::new(task.id.clone()))
        .await?;
    println!("Started task: {}", task.id);

    client.disconnect().await?;
    Ok(())
}

#[test]
fn quick_start_target_request_has_required_port_selection() -> Result<(), Box<dyn std::error::Error>>
{
    let hosts = TargetHosts::new(["192.168.1.0/24".parse::<TargetHost>()?], [])?;
    let ports = TargetPortSelection::PortRange("T:1-65535".parse()?);
    let request = CreateTargetRequest::new("My Target", hosts, ports);

    assert_eq!(request.hosts.included()[0].as_str(), "192.168.1.0/24");
    assert!(matches!(request.ports, TargetPortSelection::PortRange(_)));
    Ok(())
}
