// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical requests for scan-result retrieval.

use gvm_protocol::{Request as _, XmlCommand};

use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::responses::GetResultsResponse;
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Request for listing scan results, optionally selecting one result.
#[derive(Debug, Clone, Default)]
pub struct GetResultsRequest {
    /// Optional result identifier selector.
    pub result_id: Option<EntityId>,
    /// Optional task context for note and override rendering.
    ///
    /// This does not restrict the result list. Use a `task_id=...` filter term
    /// when task selection is required.
    pub task_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed result output.
    pub details: Option<bool>,
    /// Whether included note associations should use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included override associations should use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether to include the result count block.
    pub get_counts: Option<bool>,
}

impl GmpRequestCodec for GetResultsRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_result_query(
            self.result_id.as_ref(),
            self.task_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_results"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_results_command(
            self.result_id.as_ref(),
            self.task_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
            self.notes_details,
            self.overrides_details,
            self.get_counts,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetResultsRequest {
    type Response = GetResultsResponse;
}

/// Request for retrieving one scan result through the shared `get_results` root.
#[derive(Debug, Clone)]
pub struct GetResultRequest {
    /// Required result identifier selector.
    pub result_id: EntityId,
    /// Optional task context for note and override rendering.
    pub task_id: Option<EntityId>,
    /// Optional inline GMP filter expression, preserved verbatim.
    pub filter_string: Option<String>,
    /// Optional saved-filter identifier. The `0` and `-2` sentinels are valid.
    pub filter_id: Option<EntityId>,
    /// Whether to request detailed result output. Defaults to `Some(true)`.
    pub details: Option<bool>,
    /// Whether included note associations should use detailed output.
    pub notes_details: Option<bool>,
    /// Whether included override associations should use detailed output.
    pub overrides_details: Option<bool>,
    /// Whether to include the result count block.
    pub get_counts: Option<bool>,
}

impl GetResultRequest {
    /// Create a detailed single-result request.
    #[must_use]
    pub fn new(result_id: EntityId) -> Self {
        Self {
            result_id,
            task_id: None,
            filter_string: None,
            filter_id: None,
            details: Some(true),
            notes_details: None,
            overrides_details: None,
            get_counts: None,
        }
    }
}

impl GmpRequestCodec for GetResultRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_result_query(
            Some(&self.result_id),
            self.task_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
        )
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_results", "get_result"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        Ok(get_results_command(
            Some(&self.result_id),
            self.task_id.as_ref(),
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.details,
            self.notes_details,
            self.overrides_details,
            self.get_counts,
        )
        .to_bytes())
    }
}

impl GmpRequest for GetResultRequest {
    type Response = GetResultsResponse;
}

fn get_results_command(
    result_id: Option<&EntityId>,
    task_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    details: Option<bool>,
    notes_details: Option<bool>,
    overrides_details: Option<bool>,
    get_counts: Option<bool>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_results");
    if let Some(result_id) = result_id {
        command.set_attribute("result_id", result_id.as_str());
    }
    if let Some(task_id) = task_id {
        command.set_attribute("task_id", task_id.as_str());
    }
    add_filter_attrs(&mut command, filter_string, filter_id);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "notes_details", notes_details);
    set_optional_bool_attr(&mut command, "overrides_details", overrides_details);
    set_optional_bool_attr(&mut command, "get_counts", get_counts);
    command
}

fn validate_result_query(
    result_id: Option<&EntityId>,
    task_id: Option<&EntityId>,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
) -> Result<(), GmpRequestError> {
    validate_id(result_id, "result_id")?;
    validate_id(task_id, "task_id")?;
    validate_id(filter_id, "filter_id")?;
    if filter_string.is_some_and(|value| !value.chars().all(is_xml_1_0_character)) {
        return Err(GmpRequestError::invalid_field(
            "filter_string",
            "must contain only XML 1.0 characters",
        ));
    }
    Ok(())
}

fn validate_id(id: Option<&EntityId>, field: &'static str) -> Result<(), GmpRequestError> {
    if id.is_some_and(|id| EntityId::new(id.as_str()).is_err()) {
        Err(GmpRequestError::invalid_field(
            field,
            "must be a valid entity identifier",
        ))
    } else {
        Ok(())
    }
}

const fn is_xml_1_0_character(character: char) -> bool {
    matches!(character, '\u{9}' | '\u{A}' | '\u{D}')
        || matches!(character as u32, 0x20..=0xD7FF | 0xE000..=0xFFFD | 0x10000..=0x10FFFF)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> EntityId {
        EntityId::new(value).expect("valid id")
    }

    fn xml(request: &impl GmpRequestCodec) -> String {
        String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request"))
            .expect("valid UTF-8")
    }

    #[test]
    fn exact_xml_and_response_associations_are_independent() {
        fn response<R: GmpRequest<Response = T>, T: crate::GmpResponse>(_: &R) {}

        let list = GetResultsRequest::default();
        assert_eq!(xml(&list), "<get_results/>");
        response::<_, GetResultsResponse>(&list);

        let detail = GetResultRequest::new(id("result-1"));
        assert_eq!(
            xml(&detail),
            "<get_results details=\"1\" result_id=\"result-1\"/>"
        );
        response::<_, GetResultsResponse>(&detail);
    }

    #[test]
    fn metadata_is_available_without_encoding() {
        assert_eq!(
            GetResultsRequest::default().command(),
            Some(GmpCommand::new("get_results"))
        );
        assert_eq!(
            GetResultRequest::new(id("result-1")).command(),
            Some(GmpCommand::with_semantic_name("get_results", "get_result"))
        );
    }

    #[test]
    fn final_filter_value_is_validated_without_disclosing_it() {
        let request = GetResultsRequest {
            filter_string: Some("severity>5\u{0}secret".into()),
            ..GetResultsRequest::default()
        };
        let error = request.validate().expect_err("forbidden XML character");
        assert_eq!(
            error,
            GmpRequestError::invalid_field("filter_string", "must contain only XML 1.0 characters")
        );
        assert!(!error.to_string().contains("secret"));
        assert_eq!(request.encode(GmpVersion(22, 4)), Err(error));
    }
}
