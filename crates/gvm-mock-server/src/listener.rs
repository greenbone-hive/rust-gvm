// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Network listeners for Unix sockets and TCP.

#[cfg(feature = "ssh")]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::fault::FaultEngine;
use crate::fixtures::FixtureStore;
use crate::handler::{HandleResult, SessionHandler};
use crate::history::CommandHistory;
use crate::response_gen::{error_response, LargeReportConfig};
use crate::scenario::{ScenarioMode, ScenarioStep};
use crate::store::ResourceStore;
use crate::version::GmpVersion;
use crate::ServerMode;

#[cfg(feature = "ssh")]
const MAX_RECORDED_SSH_EXEC_REQUESTS: usize = 64;

#[cfg(feature = "ssh")]
pub(crate) struct SshTestState {
    pub(crate) authorized_keys: Vec<(String, String)>,
    auth_delay_once: Option<std::time::Duration>,
    channel_open_delay_once: Option<std::time::Duration>,
    exec_delay_once: Option<std::time::Duration>,
    reject_exec_once: bool,
    close_exec_once: bool,
    auth_delay_used: AtomicBool,
    channel_open_delay_used: AtomicBool,
    exec_delay_used: AtomicBool,
    reject_exec_used: AtomicBool,
    close_exec_used: AtomicBool,
    exec_requests: std::sync::Mutex<Vec<Vec<u8>>>,
}

#[cfg(feature = "ssh")]
impl SshTestState {
    pub(crate) fn new(
        authorized_keys: Vec<(String, String)>,
        auth_delay_once: Option<std::time::Duration>,
        channel_open_delay_once: Option<std::time::Duration>,
        exec_delay_once: Option<std::time::Duration>,
        reject_exec_once: bool,
        close_exec_once: bool,
    ) -> Self {
        Self {
            authorized_keys,
            auth_delay_once,
            channel_open_delay_once,
            exec_delay_once,
            reject_exec_once,
            close_exec_once,
            auth_delay_used: AtomicBool::new(false),
            channel_open_delay_used: AtomicBool::new(false),
            exec_delay_used: AtomicBool::new(false),
            reject_exec_used: AtomicBool::new(false),
            close_exec_used: AtomicBool::new(false),
            exec_requests: std::sync::Mutex::new(Vec::new()),
        }
    }

    pub(crate) fn take_auth_delay(&self) -> Option<std::time::Duration> {
        self.auth_delay_once.filter(|_| {
            !self
                .auth_delay_used
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        })
    }

    pub(crate) fn take_channel_open_delay(&self) -> Option<std::time::Duration> {
        self.channel_open_delay_once.filter(|_| {
            !self
                .channel_open_delay_used
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        })
    }

    pub(crate) fn take_exec_delay(&self) -> Option<std::time::Duration> {
        self.exec_delay_once.filter(|_| {
            !self
                .exec_delay_used
                .swap(true, std::sync::atomic::Ordering::Relaxed)
        })
    }

    pub(crate) fn take_reject_exec(&self) -> bool {
        self.reject_exec_once
            && !self
                .reject_exec_used
                .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn take_close_exec(&self) -> bool {
        self.close_exec_once
            && !self
                .close_exec_used
                .swap(true, std::sync::atomic::Ordering::Relaxed)
    }

    pub(crate) fn record_exec_request(&self, command: &[u8]) {
        let mut requests = self
            .exec_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if requests.len() == MAX_RECORDED_SSH_EXEC_REQUESTS {
            requests.remove(0);
        }
        requests.push(command.to_vec());
    }

    pub(crate) fn exec_requests(&self) -> Vec<Vec<u8>> {
        self.exec_requests
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Shared state across all sessions.
pub struct ListenerState {
    /// Server operating mode.
    pub(crate) mode: ServerMode,
    /// GMP version to advertise.
    pub(crate) version: GmpVersion,
    /// Command history shared with all sessions.
    pub(crate) history: CommandHistory,
    /// Counter for assigning session IDs.
    pub(crate) session_counter: AtomicU64,
    /// Fixture store (if using Fixture mode).
    pub(crate) fixtures: Option<FixtureStore>,
    /// Resource store (if using Stateful mode).
    pub(crate) store: Option<ResourceStore>,
    /// Scenario configuration (if using Scenario mode).
    pub(crate) scenario_config: Option<(ScenarioMode, Vec<ScenarioStep>)>,
    /// Large synthetic report configuration.
    pub(crate) large_report: Option<LargeReportConfig>,
    /// Maximum size of one XML request.
    pub(crate) max_request_bytes: Option<usize>,
    /// Deadline for receiving one complete XML request.
    pub(crate) request_timeout: std::time::Duration,
    /// Shared capacity for active transport sessions/channels.
    pub(crate) session_slots: Arc<Semaphore>,
    /// Tasks serving accepted sessions.
    pub(crate) session_tasks: TaskTracker,
    /// Fault injection engine.
    pub(crate) fault_engine: FaultEngine,
    /// SSH-only deterministic authentication and channel test controls.
    #[cfg(feature = "ssh")]
    pub(crate) ssh_test: Arc<SshTestState>,
    /// Shutdown signal shared by listeners and session tasks.
    pub(crate) cancellation: CancellationToken,
}

impl ListenerState {
    pub(crate) fn next_session_id(&self) -> u64 {
        self.session_counter.fetch_add(1, Ordering::Relaxed)
    }

    pub(crate) async fn acquire_session_slot(&self) -> Option<OwnedSemaphorePermit> {
        let slots = Arc::clone(&self.session_slots);
        tokio::select! {
            () = self.cancellation.cancelled() => None,
            permit = slots.acquire_owned() => permit.ok(),
        }
    }

    pub(crate) async fn drain_sessions(&self) {
        self.session_tasks.close();
        self.session_tasks.wait().await;
    }
}

/// Removes stateful authentication when a transport session ends or is cancelled.
pub(crate) struct SessionGuard {
    store: Option<ResourceStore>,
    session_id: u64,
}

impl SessionGuard {
    pub(crate) fn new(store: Option<ResourceStore>, session_id: u64) -> Self {
        Self { store, session_id }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        if let Some(store) = &self.store {
            store.end_session(self.session_id);
        }
    }
}

/// Run a Unix socket listener.
pub async fn run_unix_listener(listener: UnixListener, state: Arc<ListenerState>) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        let Some(permit) = state.acquire_session_slot().await else {
                            break;
                        };
                        let state = Arc::clone(&state);
                        state.session_tasks.clone().spawn(async move {
                            let _permit = permit;
                            handle_stream(stream, &state).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!("Unix accept error: {e}");
                    }
                }
            }
            () = state.cancellation.cancelled() => {
                tracing::debug!("Unix listener shutting down");
                break;
            }
        }
    }
    state.drain_sessions().await;
}

/// Run a TCP listener.
pub async fn run_tcp_listener(listener: TcpListener, state: Arc<ListenerState>) {
    loop {
        tokio::select! {
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        tracing::debug!("TCP connection from {addr}");
                        let Some(permit) = state.acquire_session_slot().await else {
                            break;
                        };
                        let state = Arc::clone(&state);
                        state.session_tasks.clone().spawn(async move {
                            let _permit = permit;
                            handle_stream(stream, &state).await;
                        });
                    }
                    Err(e) => {
                        tracing::warn!("TCP accept error: {e}");
                    }
                }
            }
            () = state.cancellation.cancelled() => {
                tracing::debug!("TCP listener shutting down");
                break;
            }
        }
    }
    state.drain_sessions().await;
}

/// Handle a single client connection (works for both Unix and TCP streams).
pub(crate) async fn handle_stream<S>(mut stream: S, state: &ListenerState)
where
    S: AsyncReadExt + AsyncWriteExt + Unpin,
{
    let session_id = state.next_session_id();
    let _session_guard = SessionGuard::new(state.store.clone(), session_id);
    let handler = SessionHandler::new(
        state.mode,
        state.version,
        state.history.clone(),
        session_id,
        state.fixtures.clone(),
        state.store.clone(),
        state.scenario_config.clone(),
        state.large_report,
        state.fault_engine.fork(),
    );

    let mut buf = vec![0u8; 16 * 1024];
    let mut xml_reader = gvm_protocol::XmlReader::with_buffer_limit(state.max_request_bytes);
    let mut request_deadline = None;

    loop {
        let read_result = if let Some(deadline) = request_deadline {
            tokio::select! {
                () = state.cancellation.cancelled() => return,
                result = tokio::time::timeout_at(deadline, stream.read(&mut buf)) => {
                    match result {
                        Ok(result) => result,
                        Err(_) => {
                            tracing::debug!("Request deadline exceeded on session {session_id}");
                            break;
                        }
                    }
                }
            }
        } else {
            tokio::select! {
                () = state.cancellation.cancelled() => return,
                result = stream.read(&mut buf) => result,
            }
        };
        let n = match read_result {
            Ok(0) => break, // Connection closed
            Ok(n) => n,
            Err(e) => {
                tracing::debug!("Read error on session {session_id}: {e}");
                break;
            }
        };

        let mut offset = 0;
        while offset < n {
            if xml_reader.data().is_empty() {
                request_deadline = Some(Instant::now() + state.request_timeout);
            }
            let (consumed, result) =
                try_extract_command(&mut xml_reader, &buf[offset..n], &handler);
            offset = offset.saturating_add(consumed);

            match result {
                CommandResult::Response { bytes, delay } => {
                    request_deadline = None;
                    if let Some(d) = delay {
                        tokio::time::sleep(d).await;
                    }
                    if let Err(e) = stream.write_all(&bytes).await {
                        tracing::debug!("Write error on session {session_id}: {e}");
                        return;
                    }
                }
                CommandResult::NeedMore => break,
                CommandResult::Disconnect => {
                    tracing::debug!("Fault: disconnecting session {session_id}");
                    return;
                }
                CommandResult::Reject { bytes, reason } => {
                    tracing::debug!("Rejecting session {session_id} input: {reason}");
                    let _ = stream.write_all(&bytes).await;
                    return;
                }
            }
        }
    }
}

/// Result of trying to extract a command.
pub(crate) enum CommandResult {
    /// A response to send back (optionally after delay).
    Response {
        bytes: Vec<u8>,
        delay: Option<std::time::Duration>,
    },
    /// Need more data.
    NeedMore,
    /// Disconnect (fault injection).
    Disconnect,
    /// Reject malformed or oversized XML and close the session.
    Reject { bytes: Vec<u8>, reason: String },
}

/// Try to extract a complete XML command from the buffer.
pub(crate) fn try_extract_command(
    reader: &mut gvm_protocol::XmlReader,
    data: &[u8],
    handler: &SessionHandler,
) -> (usize, CommandResult) {
    let consumed = match reader.feed_frame(data) {
        Ok(consumed) => consumed,
        Err(error) => {
            return (
                0,
                CommandResult::Reject {
                    bytes: error_response("unknown", 400, "Malformed or oversized XML request"),
                    reason: error.to_string(),
                },
            );
        }
    };

    let command_xml = match reader.take_frame() {
        Ok(Some(command_xml)) => command_xml,
        Ok(None) => return (consumed, CommandResult::NeedMore),
        Err(error) => {
            return (
                consumed,
                CommandResult::Reject {
                    bytes: error_response("unknown", 400, "Malformed or oversized XML request"),
                    reason: error.to_string(),
                },
            );
        }
    };

    let result = match handler.handle_command(&command_xml) {
        HandleResult::Respond { bytes, delay } => CommandResult::Response { bytes, delay },
        HandleResult::Disconnect => CommandResult::Disconnect,
    };
    (consumed, result)
}
