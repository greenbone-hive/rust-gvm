// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Command history recording for inspection.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::Instant;

/// Default maximum number of command records retained by the mock server.
pub const DEFAULT_MAX_HISTORY_ENTRIES: usize = 1_024;

/// Default maximum number of raw XML bytes retained by the mock server.
pub const DEFAULT_MAX_HISTORY_BYTES: usize = 16 * 1024 * 1024;

/// Retention limits for command history.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CommandHistoryLimits {
    pub(crate) max_entries: Option<usize>,
    pub(crate) max_bytes: Option<usize>,
}

impl CommandHistoryLimits {
    /// Create bounded history limits.
    ///
    /// At least one limit must be set, and every configured limit must be
    /// greater than zero.
    pub(crate) fn bounded(max_entries: Option<usize>, max_bytes: Option<usize>) -> Self {
        Self {
            max_entries,
            max_bytes,
        }
    }

    /// Create explicitly unbounded history limits.
    pub(crate) const fn unbounded() -> Self {
        Self {
            max_entries: None,
            max_bytes: None,
        }
    }
}

impl Default for CommandHistoryLimits {
    fn default() -> Self {
        Self::bounded(
            Some(DEFAULT_MAX_HISTORY_ENTRIES),
            Some(DEFAULT_MAX_HISTORY_BYTES),
        )
    }
}

/// A recorded GMP command.
#[derive(Debug, Clone)]
pub struct CommandRecord {
    /// The command name (e.g., "get_tasks").
    command_name: String,
    /// The raw XML bytes received.
    raw_xml: Vec<u8>,
    /// When the command was received.
    timestamp: Instant,
    /// Session identifier.
    session_id: u64,
}

impl CommandRecord {
    /// Create a new command record.
    pub fn new(command_name: String, raw_xml: Vec<u8>, session_id: u64) -> Self {
        Self {
            command_name,
            raw_xml,
            timestamp: Instant::now(),
            session_id,
        }
    }

    /// Get the command name.
    pub fn command_name(&self) -> &str {
        &self.command_name
    }

    /// Get the raw XML bytes.
    pub fn raw_xml(&self) -> &[u8] {
        &self.raw_xml
    }

    /// Get the session ID.
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get the timestamp.
    pub fn timestamp(&self) -> Instant {
        self.timestamp
    }
}

/// Snapshot of command-history retention and eviction counters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandHistoryStats {
    retained_records: usize,
    retained_bytes: usize,
    dropped_records: u64,
    dropped_bytes: u64,
}

impl CommandHistoryStats {
    /// Number of command records currently retained.
    pub fn retained_records(self) -> usize {
        self.retained_records
    }

    /// Number of raw XML bytes currently retained.
    pub fn retained_bytes(self) -> usize {
        self.retained_bytes
    }

    /// Number of records rejected or evicted since creation or the last clear.
    pub fn dropped_records(self) -> u64 {
        self.dropped_records
    }

    /// Number of raw XML bytes rejected or evicted since creation or the last clear.
    pub fn dropped_bytes(self) -> u64 {
        self.dropped_bytes
    }
}

#[derive(Debug)]
struct HistoryState {
    records: VecDeque<CommandRecord>,
    retained_bytes: usize,
    dropped_records: u64,
    dropped_bytes: u64,
}

impl HistoryState {
    fn new() -> Self {
        Self {
            records: VecDeque::new(),
            retained_bytes: 0,
            dropped_records: 0,
            dropped_bytes: 0,
        }
    }

    fn drop_record(&mut self, bytes: usize) {
        self.dropped_records = self.dropped_records.saturating_add(1);
        self.dropped_bytes = self
            .dropped_bytes
            .saturating_add(u64::try_from(bytes).unwrap_or(u64::MAX));
    }
}

/// Thread-safe command history store.
#[derive(Debug, Clone)]
pub struct CommandHistory {
    state: Arc<Mutex<HistoryState>>,
    limits: CommandHistoryLimits,
}

impl CommandHistory {
    /// Create a new empty history with the default retention limits.
    pub fn new() -> Self {
        Self::with_limits(CommandHistoryLimits::default())
    }

    pub(crate) fn with_limits(limits: CommandHistoryLimits) -> Self {
        Self {
            state: Arc::new(Mutex::new(HistoryState::new())),
            limits,
        }
    }

    /// Record a command, evicting the oldest records until all limits hold.
    pub fn record(&self, command_name: String, raw_xml: Vec<u8>, session_id: u64) {
        self.record_inner(command_name, raw_xml, session_id);
    }

    /// Record command bytes without cloning input that cannot fit the byte budget.
    pub(crate) fn record_slice(&self, command_name: String, raw_xml: &[u8], session_id: u64) {
        let mut state = self.state.lock().expect("history lock poisoned");
        if self.record_is_oversized(&mut state, raw_xml.len()) {
            return;
        }
        Self::push_and_evict(
            &mut state,
            self.limits,
            CommandRecord::new(command_name, raw_xml.to_vec(), session_id),
        );
    }

    fn record_inner(&self, command_name: String, raw_xml: Vec<u8>, session_id: u64) {
        let mut state = self.state.lock().expect("history lock poisoned");
        if self.record_is_oversized(&mut state, raw_xml.len()) {
            return;
        }
        Self::push_and_evict(
            &mut state,
            self.limits,
            CommandRecord::new(command_name, raw_xml, session_id),
        );
    }

    fn record_is_oversized(&self, state: &mut HistoryState, bytes: usize) -> bool {
        if self.limits.max_bytes.is_some_and(|limit| bytes > limit) {
            state.drop_record(bytes);
            true
        } else {
            false
        }
    }

    fn push_and_evict(
        state: &mut HistoryState,
        limits: CommandHistoryLimits,
        record: CommandRecord,
    ) {
        state.retained_bytes = state.retained_bytes.saturating_add(record.raw_xml.len());
        state.records.push_back(record);

        while limits
            .max_entries
            .is_some_and(|limit| state.records.len() > limit)
            || limits
                .max_bytes
                .is_some_and(|limit| state.retained_bytes > limit)
        {
            let evicted = state
                .records
                .pop_front()
                .expect("a violated history limit requires a retained record");
            state.retained_bytes = state.retained_bytes.saturating_sub(evicted.raw_xml.len());
            state.drop_record(evicted.raw_xml.len());
        }
    }

    /// Get all recorded commands in oldest-to-newest order.
    pub fn all(&self) -> Vec<CommandRecord> {
        self.state
            .lock()
            .expect("history lock poisoned")
            .records
            .iter()
            .cloned()
            .collect()
    }

    /// Get the number of recorded commands.
    pub fn len(&self) -> usize {
        self.state
            .lock()
            .expect("history lock poisoned")
            .records
            .len()
    }

    /// Check if the history is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return retention and eviction statistics.
    pub fn stats(&self) -> CommandHistoryStats {
        let state = self.state.lock().expect("history lock poisoned");
        CommandHistoryStats {
            retained_records: state.records.len(),
            retained_bytes: state.retained_bytes,
            dropped_records: state.dropped_records,
            dropped_bytes: state.dropped_bytes,
        }
    }

    /// Clear retained records and reset eviction counters.
    pub fn clear(&self) {
        let mut state = self.state.lock().expect("history lock poisoned");
        *state = HistoryState::new();
    }
}

impl Default for CommandHistory {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_new_history_is_empty() {
        let h = CommandHistory::new();
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
        assert!(h.all().is_empty());
        assert_eq!(
            h.stats(),
            CommandHistoryStats {
                retained_records: 0,
                retained_bytes: 0,
                dropped_records: 0,
                dropped_bytes: 0,
            }
        );
    }

    #[test]
    fn test_record_and_retrieve() {
        let h = CommandHistory::new();
        h.record("get_tasks".to_string(), b"<get_tasks/>".to_vec(), 1);
        assert_eq!(h.len(), 1);
        assert!(!h.is_empty());
        let records = h.all();
        assert_eq!(records[0].command_name(), "get_tasks");
        assert_eq!(records[0].raw_xml(), b"<get_tasks/>");
        assert_eq!(records[0].session_id(), 1);
        assert_eq!(h.stats().retained_bytes(), b"<get_tasks/>".len());
    }

    #[test]
    fn test_multiple_records() {
        let h = CommandHistory::new();
        h.record("get_version".to_string(), b"<get_version/>".to_vec(), 1);
        h.record("authenticate".to_string(), b"<authenticate/>".to_vec(), 1);
        h.record("get_tasks".to_string(), b"<get_tasks/>".to_vec(), 2);
        assert_eq!(h.len(), 3);
    }

    #[test]
    fn entry_limit_evicts_oldest_record() {
        let h = CommandHistory::with_limits(CommandHistoryLimits::bounded(Some(2), None));
        h.record("first".to_string(), b"<first/>".to_vec(), 1);
        h.record("second".to_string(), b"<second/>".to_vec(), 1);
        h.record("third".to_string(), b"<third/>".to_vec(), 1);

        let records = h.all();
        assert_eq!(
            records
                .iter()
                .map(CommandRecord::command_name)
                .collect::<Vec<_>>(),
            ["second", "third"]
        );
        assert_eq!(h.stats().dropped_records(), 1);
        assert_eq!(h.stats().dropped_bytes(), b"<first/>".len() as u64);
    }

    #[test]
    fn cumulative_byte_limit_evicts_oldest_records() {
        let h = CommandHistory::with_limits(CommandHistoryLimits::bounded(None, Some(18)));
        h.record("first".to_string(), b"<first/>".to_vec(), 1);
        h.record("second".to_string(), b"<second/>".to_vec(), 1);
        h.record("third".to_string(), b"<third/>".to_vec(), 1);

        let records = h.all();
        assert_eq!(
            records
                .iter()
                .map(CommandRecord::command_name)
                .collect::<Vec<_>>(),
            ["second", "third"]
        );
        assert_eq!(h.stats().retained_bytes(), 17);
        assert_eq!(h.stats().dropped_records(), 1);
    }

    #[test]
    fn individually_oversized_record_is_not_copied_or_retained() {
        let h = CommandHistory::with_limits(CommandHistoryLimits::bounded(None, Some(8)));
        h.record_slice("large".to_string(), b"<get_version/>", 1);

        assert!(h.is_empty());
        assert_eq!(h.stats().retained_bytes(), 0);
        assert_eq!(h.stats().dropped_records(), 1);
        assert_eq!(h.stats().dropped_bytes(), b"<get_version/>".len() as u64);
    }

    #[test]
    fn explicit_unbounded_history_preserves_all_records() {
        let h = CommandHistory::with_limits(CommandHistoryLimits::unbounded());
        for sequence in 0..2_048 {
            h.record("get_version".to_string(), vec![b'x'; sequence], 1);
        }
        assert_eq!(h.len(), 2_048);
        assert_eq!(h.stats().dropped_records(), 0);
    }

    #[test]
    fn test_clear() {
        let h = CommandHistory::with_limits(CommandHistoryLimits::bounded(Some(1), None));
        h.record("first".to_string(), b"<first/>".to_vec(), 1);
        h.record("second".to_string(), b"<second/>".to_vec(), 1);
        assert_eq!(h.stats().dropped_records(), 1);
        h.clear();
        assert!(h.is_empty());
        assert_eq!(h.stats().retained_bytes(), 0);
        assert_eq!(h.stats().dropped_records(), 0);
    }

    #[test]
    fn test_default() {
        let h = CommandHistory::default();
        assert!(h.is_empty());
    }

    #[test]
    fn test_command_record_timestamp() {
        let record = CommandRecord::new("test".to_string(), vec![], 0);
        let _ = record.timestamp();
    }

    #[test]
    fn test_clone() {
        let h = CommandHistory::new();
        h.record("get_tasks".to_string(), b"<get_tasks/>".to_vec(), 1);
        let h2 = h.clone();
        assert_eq!(h2.len(), 1);
    }
}
