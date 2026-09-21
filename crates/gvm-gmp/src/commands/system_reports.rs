// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical system-report discovery request.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::set_optional_bool_attr;
use crate::responses::GetSystemReportsResponse;
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical `get_system_reports` request.
#[derive(Debug, Clone, Default)]
pub struct GetSystemReportsRequest {
    /// Name of a single system report to retrieve.
    pub name: Option<String>,
    /// Number of seconds into the past to include.
    pub duration: Option<u64>,
    /// Start of the requested interval as an ISO timestamp.
    pub start_time: Option<String>,
    /// End of the requested interval as an ISO timestamp.
    pub end_time: Option<String>,
    /// Whether to list report metadata without the report payload.
    pub brief: Option<bool>,
    /// Scanner from which to retrieve the report.
    pub slave_id: Option<EntityId>,
}

impl GetSystemReportsRequest {
    /// Create a system-report discovery request with gvmd defaults.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            name: None,
            duration: None,
            start_time: None,
            end_time: None,
            brief: None,
            slave_id: None,
        }
    }
}

impl GmpRequestCodec for GetSystemReportsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        for (value, field) in [
            (self.name.as_deref(), "name"),
            (self.start_time.as_deref(), "start_time"),
            (self.end_time.as_deref(), "end_time"),
        ] {
            if let Some(value) = value {
                if value.trim().is_empty() {
                    return Err(GmpRequestError::invalid_field(field, "must not be empty"));
                }
                validate_xml(value, field)?;
            }
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_system_reports"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = XmlCommand::new("get_system_reports");
        if let Some(name) = self.name.as_deref() {
            command.set_attribute("name", name);
        }
        if let Some(duration) = self.duration {
            command.set_attribute("duration", &duration.to_string());
        }
        if let Some(start_time) = self.start_time.as_deref() {
            command.set_attribute("start_time", start_time);
        }
        if let Some(end_time) = self.end_time.as_deref() {
            command.set_attribute("end_time", end_time);
        }
        set_optional_bool_attr(&mut command, "brief", self.brief);
        if let Some(slave_id) = self.slave_id.as_ref() {
            command.set_attribute("slave_id", slave_id.as_str());
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetSystemReportsRequest {
    type Response = GetSystemReportsResponse;
}

fn validate_xml(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.chars().all(|character| {
        matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
            || matches!(
                character as u32,
                0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF
            )
    }) {
        Ok(())
    } else {
        Err(GmpRequestError::invalid_field(
            field,
            "must contain only XML 1.0 characters",
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_owns_report_selection_and_interval() {
        let request = GetSystemReportsRequest {
            name: Some("load".into()),
            duration: Some(3600),
            start_time: Some("2026-07-23T12:00:00Z".into()),
            end_time: Some("2026-07-23T13:00:00Z".into()),
            brief: Some(false),
            slave_id: Some(EntityId::new("scanner-1").expect("valid id")),
        };
        assert_eq!(
            request.encode(GmpVersion(22, 4)).expect("valid request"),
            b"<get_system_reports brief=\"0\" duration=\"3600\" end_time=\"2026-07-23T13:00:00Z\" name=\"load\" slave_id=\"scanner-1\" start_time=\"2026-07-23T12:00:00Z\"/>"
        );
    }
}
