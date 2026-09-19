// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::results::{GetResultRequest, GetResultsRequest};
use gvm_gmp::{GmpCommand, GmpRequestCodec, GmpRequestError, GmpVersion};

fn xml(request: &impl GmpRequestCodec) -> String {
    String::from_utf8(request.encode(GmpVersion(22, 4)).expect("valid request")).unwrap()
}

#[test]
fn default_list_and_detail_encode_exactly() {
    assert_eq!(xml(&GetResultsRequest::default()), "<get_results/>");
    assert_eq!(
        xml(&GetResultRequest::new(id("result-1"))),
        "<get_results details=\"1\" result_id=\"result-1\"/>"
    );
}

#[test]
fn every_field_encodes_in_one_independently_specified_request() {
    let request = GetResultsRequest {
        result_id: Some(id("result-1")),
        task_id: Some(id("task-1")),
        filter_string: Some(
            "severity>5 notes=1 overrides=1 apply_overrides=0 first=2 rows=1".into(),
        ),
        filter_id: Some(id("filter-1")),
        details: Some(false),
        notes_details: Some(true),
        overrides_details: Some(false),
        get_counts: Some(false),
    };
    assert_eq!(
        xml(&request),
        "<get_results details=\"0\" filt_id=\"filter-1\" filter=\"severity&gt;5 notes=1 overrides=1 apply_overrides=0 first=2 rows=1\" get_counts=\"0\" notes_details=\"1\" overrides_details=\"0\" result_id=\"result-1\" task_id=\"task-1\"/>"
    );
}

#[test]
fn booleans_preserve_absent_false_and_true_states() {
    let mut request = GetResultsRequest::default();
    for field in 0..4 {
        for value in [None, Some(false), Some(true)] {
            request.details = None;
            request.notes_details = None;
            request.overrides_details = None;
            request.get_counts = None;
            match field {
                0 => request.details = value,
                1 => request.notes_details = value,
                2 => request.overrides_details = value,
                3 => request.get_counts = value,
                _ => unreachable!(),
            }
            let encoded = xml(&request);
            let attribute = [
                "details",
                "notes_details",
                "overrides_details",
                "get_counts",
            ][field];
            match value {
                None => assert_eq!(encoded, "<get_results/>"),
                Some(false) => assert_eq!(encoded, format!("<get_results {attribute}=\"0\"/>")),
                Some(true) => assert_eq!(encoded, format!("<get_results {attribute}=\"1\"/>")),
            }
        }
    }

    let mut detail = GetResultRequest::new(id("result-1"));
    detail.details = Some(false);
    assert_eq!(
        xml(&detail),
        "<get_results details=\"0\" result_id=\"result-1\"/>"
    );
    detail.details = None;
    assert_eq!(xml(&detail), "<get_results result_id=\"result-1\"/>");

    for field in 0..4 {
        for value in [None, Some(false), Some(true)] {
            let mut detail = GetResultRequest::new(id("result-1"));
            detail.details = None;
            match field {
                0 => detail.details = value,
                1 => detail.notes_details = value,
                2 => detail.overrides_details = value,
                3 => detail.get_counts = value,
                _ => unreachable!(),
            }
            let encoded = xml(&detail);
            let attribute = [
                "details",
                "notes_details",
                "overrides_details",
                "get_counts",
            ][field];
            match value {
                None => assert_eq!(encoded, "<get_results result_id=\"result-1\"/>"),
                Some(false) => assert!(encoded.contains(&format!("{attribute}=\"0\""))),
                Some(true) => assert!(encoded.contains(&format!("{attribute}=\"1\""))),
            }
        }
    }
}

#[test]
fn filters_preserve_sentinels_empty_text_unicode_whitespace_and_escaping() {
    for sentinel in ["0", "-2"] {
        let request = GetResultsRequest {
            filter_id: Some(id(sentinel)),
            ..Default::default()
        };
        assert_eq!(
            xml(&request),
            format!("<get_results filt_id=\"{sentinel}\"/>")
        );
    }

    let mut request = GetResultsRequest {
        filter_string: Some(String::new()),
        ..Default::default()
    };
    assert_eq!(xml(&request), "<get_results filter=\"\"/>");
    request.filter_string = Some("naïve=東京\tline=one\nline=two & <x>".into());
    assert_eq!(
        xml(&request),
        "<get_results filter=\"naïve=東京\tline=one\nline=two &amp; &lt;x&gt;\"/>"
    );
}

#[test]
fn excluded_attributes_and_children_are_not_synthesized() {
    let encoded = xml(&GetResultsRequest {
        task_id: Some(id("task-1")),
        ..Default::default()
    });
    assert_eq!(encoded, "<get_results task_id=\"task-1\"/>");
    for excluded in [
        "trash",
        "ignore_pagination",
        "report_id",
        "lean",
        "delta_report_id",
        "delta_states",
        "notes=",
        "overrides=",
        "apply_overrides",
        "filter_replace",
    ] {
        assert!(!encoded.contains(excluded));
    }
    assert!(!encoded.contains("><"));
}

#[test]
fn mutation_changes_final_encoding_and_invalid_xml_is_rejected() {
    let mut request = GetResultRequest::new(id("result-1"));
    assert_eq!(
        xml(&request),
        "<get_results details=\"1\" result_id=\"result-1\"/>"
    );
    request.result_id = id("result-2");
    request.filter_string = Some("severity>5".into());
    assert_eq!(
        xml(&request),
        "<get_results details=\"1\" filter=\"severity&gt;5\" result_id=\"result-2\"/>"
    );
    request.filter_string = Some("secret\u{1}".into());
    let error = request
        .encode(GmpVersion(22, 4))
        .expect_err("invalid final filter");
    assert!(matches!(
        error,
        GmpRequestError::InvalidField {
            field: "filter_string",
            ..
        }
    ));
    assert!(!error.to_string().contains("secret"));
}

#[test]
fn command_metadata_is_static_and_uses_the_shared_wire_root() {
    assert_eq!(
        GetResultsRequest::default().command(),
        Some(GmpCommand::new("get_results"))
    );
    assert_eq!(
        GetResultRequest::new(id("result-1")).command(),
        Some(GmpCommand::with_semantic_name("get_results", "get_result"))
    );
}

#[cfg(feature = "serde")]
#[test]
fn invalid_deserialized_identifiers_are_revalidated() {
    use serde::de::value::{Error, SeqDeserializer, StrDeserializer};
    use serde::Deserialize;

    let values = std::iter::once(StrDeserializer::<Error>::new("not valid"));
    let invalid = gvm_gmp::EntityId::deserialize(SeqDeserializer::<_, Error>::new(values))
        .expect("derived deserialization preserves the raw newtype value");
    for (request, field) in [
        (
            GetResultsRequest {
                result_id: Some(invalid.clone()),
                ..Default::default()
            },
            "result_id",
        ),
        (
            GetResultsRequest {
                task_id: Some(invalid.clone()),
                ..Default::default()
            },
            "task_id",
        ),
        (
            GetResultsRequest {
                filter_id: Some(invalid.clone()),
                ..Default::default()
            },
            "filter_id",
        ),
    ] {
        assert!(matches!(
            request.encode(GmpVersion(22, 4)),
            Err(GmpRequestError::InvalidField { field: actual, .. }) if actual == field
        ));
    }

    for (request, field) in [
        (
            GetResultRequest {
                result_id: invalid.clone(),
                ..GetResultRequest::new(id("valid"))
            },
            "result_id",
        ),
        (
            GetResultRequest {
                task_id: Some(invalid.clone()),
                ..GetResultRequest::new(id("valid"))
            },
            "task_id",
        ),
        (
            GetResultRequest {
                filter_id: Some(invalid),
                ..GetResultRequest::new(id("valid"))
            },
            "filter_id",
        ),
    ] {
        assert!(matches!(
            request.encode(GmpVersion(22, 4)),
            Err(GmpRequestError::InvalidField { field: actual, .. }) if actual == field
        ));
    }
}
