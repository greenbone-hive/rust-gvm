// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical current and legacy aggregate requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::commands::usage_type::UsageType;
use crate::common::{add_filter_attrs, set_optional_bool_attr};
use crate::enums::SortOrder;
use crate::responses::GetAggregatesResponse;
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// A statistic accepted by current gvmd aggregate sort criteria.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateSortStatistic {
    /// Sort by the minimum value.
    Minimum,
    /// Sort by the maximum value.
    Maximum,
    /// Sort by the arithmetic mean.
    Mean,
    /// Sort by the sum.
    Sum,
    /// Sort by the resource count.
    Count,
    /// Sort by the group value.
    Value,
}

impl AggregateSortStatistic {
    /// Return the current gvmd wire value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::Minimum => "min",
            Self::Maximum => "max",
            Self::Mean => "mean",
            Self::Sum => "sum",
            Self::Count => "count",
            Self::Value => "value",
        }
    }
}

/// One gvmd aggregate sort criterion.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AggregateSort {
    /// Aggregate field to sort by. An empty field is valid when an order is supplied.
    pub field: String,
    /// Optional statistic for the selected field.
    pub statistic: Option<AggregateSortStatistic>,
    /// Optional sort direction.
    pub order: Option<SortOrder>,
}

/// Special aggregate processing modes supported by current gvmd.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AggregateMode {
    /// Count words in the selected group column.
    WordCounts,
}

impl AggregateMode {
    /// Return the current gvmd wire value.
    #[must_use]
    pub const fn as_gmp_str(self) -> &'static str {
        match self {
            Self::WordCounts => "word_counts",
        }
    }
}

/// Canonical current gvmd aggregate request using repeated child elements.
#[derive(Debug, Clone)]
pub struct GetAggregatesRequest {
    /// Required GMP resource type to aggregate.
    pub resource_type: String,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Optional single-resource identifier, encoded with the selected resource type.
    pub resource_id: Option<EntityId>,
    /// Optional filter column whose saved-filter term gvmd replaces.
    pub filter_replace: Option<String>,
    /// Whether to aggregate trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed resource selection.
    pub details: Option<bool>,
    /// Whether pagination embedded in the resource filter is ignored.
    pub ignore_pagination: Option<bool>,
    /// Columns whose numeric statistics should be returned.
    pub data_columns: Vec<String>,
    /// Optional group-by column.
    pub group_column: Option<String>,
    /// Optional subgroup column. A group column is required when this is set.
    pub subgroup_column: Option<String>,
    /// Ordered sort criteria encoded as repeated `<sort>` children.
    pub sorts: Vec<AggregateSort>,
    /// Columns returned as text without calculated statistics.
    pub text_columns: Vec<String>,
    /// One-based index of the first aggregate group to return.
    pub first_group: Option<u32>,
    /// Maximum groups to return. `-1` requests all groups.
    pub max_groups: Option<i32>,
    /// Optional special processing mode.
    pub mode: Option<AggregateMode>,
    /// Optional task or config usage type.
    pub usage_type: Option<UsageType>,
}

impl GetAggregatesRequest {
    /// Create a current aggregate request with only its required resource type.
    #[must_use]
    pub fn new(resource_type: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            filter_string: None,
            filter_id: None,
            resource_id: None,
            filter_replace: None,
            trash: None,
            details: None,
            ignore_pagination: None,
            data_columns: Vec::new(),
            group_column: None,
            subgroup_column: None,
            sorts: Vec::new(),
            text_columns: Vec::new(),
            first_group: None,
            max_groups: None,
            mode: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for GetAggregatesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_common(
            &self.resource_type,
            self.filter_string.as_deref(),
            self.filter_replace.as_deref(),
            self.resource_id.as_ref(),
            self.group_column.as_deref(),
            self.subgroup_column.as_deref(),
            self.first_group,
            self.max_groups,
        )?;
        validate_columns(&self.data_columns, "data_columns")?;
        validate_columns(&self.text_columns, "text_columns")?;
        for sort in &self.sorts {
            validate_sort(sort)?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_aggregates"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = aggregate_command(
            &self.resource_type,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.resource_id.as_ref(),
            self.filter_replace.as_deref(),
            self.trash,
            self.details,
            self.ignore_pagination,
            self.group_column.as_deref(),
            self.subgroup_column.as_deref(),
            self.first_group,
            self.max_groups,
            self.mode,
            self.usage_type,
        );
        for sort in &self.sorts {
            let element = command.add_element("sort");
            if !sort.field.is_empty() {
                element.set_attribute("field", &sort.field);
            }
            if let Some(statistic) = sort.statistic {
                element.set_attribute("stat", statistic.as_gmp_str());
            }
            if let Some(order) = sort.order {
                element.set_attribute("order", order.as_gmp_str());
            }
        }
        for column in &self.data_columns {
            command.add_element("data_column").set_text(column);
        }
        for column in &self.text_columns {
            command.add_element("text_column").set_text(column);
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetAggregatesRequest {
    type Response = GetAggregatesResponse;
}

/// Canonical legacy aggregate request using gvmd's singular root attributes.
///
/// This is intentionally distinct from [`GetAggregatesRequest`]: legacy gvmd
/// clients can express only one data column and one sort criterion at the root.
#[derive(Debug, Clone)]
pub struct GetLegacyAggregatesRequest {
    /// Required GMP resource type to aggregate.
    pub resource_type: String,
    /// Optional inline filter expression.
    pub filter_string: Option<String>,
    /// Optional saved filter identifier.
    pub filter_id: Option<EntityId>,
    /// Optional single-resource identifier, encoded with the selected resource type.
    pub resource_id: Option<EntityId>,
    /// Optional filter column whose saved-filter term gvmd replaces.
    pub filter_replace: Option<String>,
    /// Whether to aggregate trashcan resources.
    pub trash: Option<bool>,
    /// Whether to request detailed resource selection.
    pub details: Option<bool>,
    /// Whether pagination embedded in the resource filter is ignored.
    pub ignore_pagination: Option<bool>,
    /// Optional singular root `data_column`.
    pub data_column: Option<String>,
    /// Optional group-by column.
    pub group_column: Option<String>,
    /// Optional subgroup column. A group column is required when this is set.
    pub subgroup_column: Option<String>,
    /// Optional singular root sort criterion.
    pub sort: Option<AggregateSort>,
    /// One-based index of the first aggregate group to return.
    pub first_group: Option<u32>,
    /// Maximum groups to return. `-1` requests all groups.
    pub max_groups: Option<i32>,
    /// Optional special processing mode.
    pub mode: Option<AggregateMode>,
    /// Optional task or config usage type.
    pub usage_type: Option<UsageType>,
}

impl GetLegacyAggregatesRequest {
    /// Create a legacy aggregate request with only its required resource type.
    #[must_use]
    pub fn new(resource_type: impl Into<String>) -> Self {
        Self {
            resource_type: resource_type.into(),
            filter_string: None,
            filter_id: None,
            resource_id: None,
            filter_replace: None,
            trash: None,
            details: None,
            ignore_pagination: None,
            data_column: None,
            group_column: None,
            subgroup_column: None,
            sort: None,
            first_group: None,
            max_groups: None,
            mode: None,
            usage_type: None,
        }
    }
}

impl GmpRequestCodec for GetLegacyAggregatesRequest {
    fn validate(&self) -> Result<(), GmpRequestError> {
        validate_common(
            &self.resource_type,
            self.filter_string.as_deref(),
            self.filter_replace.as_deref(),
            self.resource_id.as_ref(),
            self.group_column.as_deref(),
            self.subgroup_column.as_deref(),
            self.first_group,
            self.max_groups,
        )?;
        if let Some(column) = self.data_column.as_deref() {
            validate_nonempty_xml(column, "data_column")?;
        }
        if let Some(sort) = &self.sort {
            validate_sort(sort)?;
        }
        Ok(())
    }

    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name(
            "get_aggregates",
            "get_legacy_aggregates",
        ))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        self.validate()?;
        let mut command = aggregate_command(
            &self.resource_type,
            self.filter_string.as_deref(),
            self.filter_id.as_ref(),
            self.resource_id.as_ref(),
            self.filter_replace.as_deref(),
            self.trash,
            self.details,
            self.ignore_pagination,
            self.group_column.as_deref(),
            self.subgroup_column.as_deref(),
            self.first_group,
            self.max_groups,
            self.mode,
            self.usage_type,
        );
        if let Some(column) = self.data_column.as_deref() {
            command.set_attribute("data_column", column);
        }
        if let Some(sort) = &self.sort {
            if !sort.field.is_empty() {
                command.set_attribute("sort_field", &sort.field);
            }
            if let Some(statistic) = sort.statistic {
                command.set_attribute("sort_stat", statistic.as_gmp_str());
            }
            if let Some(order) = sort.order {
                command.set_attribute("sort_order", order.as_gmp_str());
            }
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for GetLegacyAggregatesRequest {
    type Response = GetAggregatesResponse;
}

#[allow(clippy::too_many_arguments)]
fn aggregate_command(
    resource_type: &str,
    filter_string: Option<&str>,
    filter_id: Option<&EntityId>,
    resource_id: Option<&EntityId>,
    filter_replace: Option<&str>,
    trash: Option<bool>,
    details: Option<bool>,
    ignore_pagination: Option<bool>,
    group_column: Option<&str>,
    subgroup_column: Option<&str>,
    first_group: Option<u32>,
    max_groups: Option<i32>,
    mode: Option<AggregateMode>,
    usage_type: Option<UsageType>,
) -> XmlCommand {
    let mut command = XmlCommand::new("get_aggregates");
    command.set_attribute("type", resource_type);
    add_filter_attrs(&mut command, filter_string, filter_id);
    if let Some(resource_id) = resource_id {
        command.set_attribute(&format!("{resource_type}_id"), resource_id.as_str());
    }
    if let Some(filter_replace) = filter_replace {
        command.set_attribute("filter_replace", filter_replace);
    }
    set_optional_bool_attr(&mut command, "trash", trash);
    set_optional_bool_attr(&mut command, "details", details);
    set_optional_bool_attr(&mut command, "ignore_pagination", ignore_pagination);
    if let Some(group_column) = group_column {
        command.set_attribute("group_column", group_column);
    }
    if let Some(subgroup_column) = subgroup_column {
        command.set_attribute("subgroup_column", subgroup_column);
    }
    if let Some(first_group) = first_group {
        command.set_attribute("first_group", &first_group.to_string());
    }
    if let Some(max_groups) = max_groups {
        command.set_attribute("max_groups", &max_groups.to_string());
    }
    if let Some(mode) = mode {
        command.set_attribute("mode", mode.as_gmp_str());
    }
    if let Some(usage_type) = usage_type {
        command.set_attribute("usage_type", usage_type.as_gmp_str());
    }
    command
}

fn validate_common(
    resource_type: &str,
    filter_string: Option<&str>,
    filter_replace: Option<&str>,
    resource_id: Option<&EntityId>,
    group_column: Option<&str>,
    subgroup_column: Option<&str>,
    first_group: Option<u32>,
    max_groups: Option<i32>,
) -> Result<(), GmpRequestError> {
    validate_nonempty_xml(resource_type, "resource_type")?;
    if resource_id.is_some()
        && !resource_type
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return Err(GmpRequestError::invalid_combination(
            &["resource_type", "resource_id"],
            "resource_type must contain only ASCII letters, digits, or underscores when resource_id is set",
        ));
    }
    if let Some(filter) = filter_string {
        validate_xml(filter, "filter_string")?;
    }
    if let Some(filter_replace) = filter_replace {
        validate_nonempty_xml(filter_replace, "filter_replace")?;
    }
    if let Some(group) = group_column {
        validate_nonempty_xml(group, "group_column")?;
    }
    if let Some(subgroup) = subgroup_column {
        validate_nonempty_xml(subgroup, "subgroup_column")?;
        if group_column.is_none() {
            return Err(GmpRequestError::invalid_combination(
                &["group_column", "subgroup_column"],
                "group_column is required when subgroup_column is set",
            ));
        }
    }
    if first_group == Some(0) {
        return Err(GmpRequestError::invalid_field(
            "first_group",
            "must use one-based indexing",
        ));
    }
    if max_groups.is_some_and(|value| value == 0 || value < -1) {
        return Err(GmpRequestError::invalid_field(
            "max_groups",
            "must be positive or -1 for all groups",
        ));
    }
    Ok(())
}

fn validate_sort(sort: &AggregateSort) -> Result<(), GmpRequestError> {
    if sort.field.is_empty() && sort.order.is_none() {
        return Err(GmpRequestError::invalid_combination(
            &["sort.field", "sort.order"],
            "a sort requires a field or explicit order",
        ));
    }
    if !sort.field.is_empty() {
        validate_xml(&sort.field, "sort.field")?;
    }
    Ok(())
}

fn validate_columns(columns: &[String], field: &'static str) -> Result<(), GmpRequestError> {
    for column in columns {
        validate_nonempty_xml(column, field)?;
    }
    Ok(())
}

fn validate_nonempty_xml(value: &str, field: &'static str) -> Result<(), GmpRequestError> {
    if value.trim().is_empty() {
        return Err(GmpRequestError::invalid_field(field, "must not be empty"));
    }
    validate_xml(value, field)
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
    fn current_shape_uses_repeated_children() {
        let mut request = GetAggregatesRequest::new("task");
        request.filter_string = Some("owner=me".into());
        request.filter_id = Some(EntityId::new("filter-1").expect("valid id"));
        request.resource_id = Some(EntityId::new("task-1").expect("valid id"));
        request.filter_replace = Some("owner".into());
        request.trash = Some(false);
        request.details = Some(true);
        request.ignore_pagination = Some(true);
        request.data_columns = vec!["severity".into(), "qod".into()];
        request.text_columns = vec!["name".into()];
        request.group_column = Some("status".into());
        request.subgroup_column = Some("owner".into());
        request.sorts.push(AggregateSort {
            field: "severity".into(),
            statistic: Some(AggregateSortStatistic::Maximum),
            order: Some(SortOrder::Descending),
        });
        request.first_group = Some(2);
        request.max_groups = Some(-1);
        request.usage_type = Some(UsageType::Audit);

        assert_eq!(
            request.encode(GmpVersion(22, 8)).expect("valid request"),
            b"<get_aggregates details=\"1\" filt_id=\"filter-1\" filter=\"owner=me\" filter_replace=\"owner\" first_group=\"2\" group_column=\"status\" ignore_pagination=\"1\" max_groups=\"-1\" subgroup_column=\"owner\" task_id=\"task-1\" trash=\"0\" type=\"task\" usage_type=\"audit\"><sort field=\"severity\" order=\"descending\" stat=\"max\"/><data_column>severity</data_column><data_column>qod</data_column><text_column>name</text_column></get_aggregates>"
        );
    }

    #[test]
    fn legacy_shape_uses_supported_singular_attributes() {
        let mut request = GetLegacyAggregatesRequest::new("task");
        request.data_column = Some("severity".into());
        request.group_column = Some("status".into());
        request.sort = Some(AggregateSort {
            field: "severity".into(),
            statistic: Some(AggregateSortStatistic::Count),
            order: Some(SortOrder::Descending),
        });
        assert_eq!(
            request.encode(GmpVersion(22, 4)).expect("valid request"),
            b"<get_aggregates data_column=\"severity\" group_column=\"status\" sort_field=\"severity\" sort_order=\"descending\" sort_stat=\"count\" type=\"task\"/>"
        );
    }

    #[test]
    fn invalid_aggregate_semantics_fail_before_encoding() {
        let mut request = GetAggregatesRequest::new("task");
        request.subgroup_column = Some("owner".into());
        assert!(matches!(
            request.validate(),
            Err(GmpRequestError::InvalidCombination { .. })
        ));

        let mut request = GetAggregatesRequest::new("task");
        request.first_group = Some(0);
        assert_eq!(
            request.validate(),
            Err(GmpRequestError::invalid_field(
                "first_group",
                "must use one-based indexing"
            ))
        );

        let mut request = GetAggregatesRequest::new("task-id");
        request.resource_id = Some(EntityId::new("task-1").expect("valid id"));
        assert!(matches!(
            request.validate(),
            Err(GmpRequestError::InvalidCombination { .. })
        ));
    }
}
