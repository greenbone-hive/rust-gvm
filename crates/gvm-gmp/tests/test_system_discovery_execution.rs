// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::aggregates::{
    AggregateMode, AggregateSort, AggregateSortStatistic, GetAggregatesRequest,
    GetLegacyAggregatesRequest,
};
use gvm_gmp::commands::authentication::AuthenticateRequest;
use gvm_gmp::commands::features::GetFeaturesRequest;
use gvm_gmp::commands::feed::{GetFeedRequest, GetFeedsRequest};
use gvm_gmp::commands::help::{HelpMode, HelpRequest};
use gvm_gmp::commands::resource_names::{GetResourceNameRequest, GetResourceNamesRequest};
use gvm_gmp::commands::system::{
    DescribeAuthRequest, GetLicenseRequest, GetSettingsRequest, GetTimezonesRequest,
};
use gvm_gmp::commands::system_reports::GetSystemReportsRequest;
use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::enums::{FeedType, HelpFormat, ResourceType, SortOrder};
use gvm_gmp::responses::{
    AuthenticateResponse, DescribeAuthResponse, GetAggregatesResponse, GetFeaturesResponse,
    GetFeedsResponse, GetLicenseResponse, GetResourceNamesResponse, GetSettingsResponse,
    GetSystemReportsResponse, GetTimezonesResponse, GetVersionResponse, HelpResponse,
};
use gvm_gmp::{EntityId, GmpRequest, GmpRequestCodec, GmpResponse, GmpVersion};

fn id(value: &str) -> EntityId {
    EntityId::new(value).expect("valid id")
}

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 8)).expect("request encodes")).unwrap()
}

fn assert_response<R, T>(_request: &R)
where
    R: GmpRequest<Response = T>,
    T: GmpResponse,
{
}

#[test]
fn canonical_requests_have_concrete_response_associations() {
    assert_response::<GetVersionRequest, GetVersionResponse>(&GetVersionRequest::new());
    assert_response::<AuthenticateRequest, AuthenticateResponse>(&AuthenticateRequest::new(
        "admin", "secret",
    ));
    assert_response::<GetFeaturesRequest, GetFeaturesResponse>(&GetFeaturesRequest::new());
    assert_response::<GetFeedsRequest, GetFeedsResponse>(&GetFeedsRequest::new());
    assert_response::<GetFeedRequest, GetFeedsResponse>(&GetFeedRequest::new(FeedType::Nvt));
    assert_response::<HelpRequest, HelpResponse>(&HelpRequest::new(HelpMode::BriefXml));
    assert_response::<GetAggregatesRequest, GetAggregatesResponse>(&GetAggregatesRequest::new(
        "task",
    ));
    assert_response::<GetLegacyAggregatesRequest, GetAggregatesResponse>(
        &GetLegacyAggregatesRequest::new("task"),
    );
    assert_response::<GetSettingsRequest, GetSettingsResponse>(&GetSettingsRequest::new());
    assert_response::<GetTimezonesRequest, GetTimezonesResponse>(&GetTimezonesRequest::new());
    assert_response::<GetSystemReportsRequest, GetSystemReportsResponse>(
        &GetSystemReportsRequest::new(),
    );
    assert_response::<GetResourceNamesRequest, GetResourceNamesResponse>(
        &GetResourceNamesRequest::new(ResourceType::Task),
    );
    assert_response::<GetResourceNameRequest, GetResourceNamesResponse>(
        &GetResourceNameRequest::new(id("task-1"), ResourceType::Task),
    );
    assert_response::<GetLicenseRequest, GetLicenseResponse>(&GetLicenseRequest::new());
    assert_response::<DescribeAuthRequest, DescribeAuthResponse>(&DescribeAuthRequest::new());
}

#[test]
fn canonical_values_own_every_query_control() {
    let mut current = GetAggregatesRequest::new("task");
    current.filter_string = Some("owner=me".into());
    current.filter_id = Some(id("filter-1"));
    current.resource_id = Some(id("task-1"));
    current.filter_replace = Some("owner".into());
    current.trash = Some(false);
    current.details = Some(true);
    current.ignore_pagination = Some(true);
    current.data_columns = vec!["severity".into(), "qod".into()];
    current.text_columns = vec!["name".into()];
    current.group_column = Some("status".into());
    current.subgroup_column = Some("owner".into());
    current.sorts = vec![AggregateSort {
        field: "severity".into(),
        statistic: Some(AggregateSortStatistic::Maximum),
        order: Some(SortOrder::Descending),
    }];
    current.first_group = Some(2);
    current.max_groups = Some(-1);
    assert!(xml(&current).contains("<data_column>severity</data_column>"));

    let mut legacy = GetLegacyAggregatesRequest::new("task");
    legacy.data_column = Some("severity".into());
    legacy.group_column = Some("status".into());
    legacy.sort = Some(AggregateSort {
        field: "severity".into(),
        statistic: Some(AggregateSortStatistic::Count),
        order: Some(SortOrder::Descending),
    });
    legacy.mode = Some(AggregateMode::WordCounts);
    let legacy_xml = xml(&legacy);
    assert!(legacy_xml.contains("sort_stat=\"count\""));
    assert!(!legacy_xml.contains("<sort"));

    let mut names = GetResourceNamesRequest::new(ResourceType::Policy);
    names.filter_string = Some("first=2 rows=10".into());
    names.filter_id = Some(id("filter-2"));
    names.filter_replace = Some("owner".into());
    names.trash = Some(false);
    names.details = Some(true);
    names.ignore_pagination = Some(true);
    assert_eq!(
        xml(&names),
        "<get_resource_names details=\"1\" filt_id=\"filter-2\" filter=\"first=2 rows=10\" filter_replace=\"owner\" ignore_pagination=\"1\" trash=\"0\" type=\"POLICY\"/>"
    );

    let mut reports = GetSystemReportsRequest::new();
    reports.name = Some("load".into());
    reports.duration = Some(3600);
    reports.start_time = Some("2026-09-20T10:00:00Z".into());
    reports.end_time = Some("2026-09-20T11:00:00Z".into());
    reports.brief = Some(false);
    reports.slave_id = Some(id("scanner-1"));
    assert!(xml(&reports).contains("duration=\"3600\""));
}

#[test]
fn help_feed_auth_and_empty_discovery_shapes_are_source_faithful() {
    assert_eq!(xml(&HelpRequest::new(HelpMode::Text)), "<help/>");
    assert_eq!(
        xml(&HelpRequest::new(HelpMode::BriefXml)),
        "<help format=\"xml\" type=\"brief\"/>"
    );
    assert_eq!(
        xml(&HelpRequest::new(HelpMode::Schema(HelpFormat::Rnc))),
        "<help format=\"rnc\"/>"
    );
    assert_eq!(xml(&GetFeedsRequest::new()), "<get_feeds/>");
    assert_eq!(
        xml(&GetFeedRequest::new(FeedType::Gvmd)),
        "<get_feeds type=\"GVMD_DATA\"/>"
    );

    let mut auth = AuthenticateRequest::new("admin", "secret");
    auth.request_token = Some(true);
    let auth_xml = xml(&auth);
    assert!(auth_xml.contains("token=\"1\""));
    assert!(!format!("{auth:?}").contains("admin"));
    assert!(!format!("{auth:?}").contains("secret"));

    assert_eq!(xml(&GetVersionRequest::new()), "<get_version/>");
    assert_eq!(xml(&GetFeaturesRequest::new()), "<get_features/>");
    assert_eq!(xml(&GetTimezonesRequest::new()), "<get_timezones/>");
    assert_eq!(xml(&GetLicenseRequest::new()), "<get_license/>");
    assert_eq!(xml(&DescribeAuthRequest::new()), "<describe_auth/>");
}

#[test]
fn validation_is_semantic_and_secret_free() {
    let mut invalid = GetAggregatesRequest::new("task");
    invalid.subgroup_column = Some("owner".into());
    assert!(invalid.validate().is_err());

    let auth = AuthenticateRequest::new("admin", "do-not-disclose");
    let debug = format!("{auth:?}");
    assert!(!debug.contains("admin"));
    assert!(!debug.contains("do-not-disclose"));
}
