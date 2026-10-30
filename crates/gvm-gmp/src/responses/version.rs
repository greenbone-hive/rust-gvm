// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Version response models.

use gvm_protocol::Response;

use crate::responses::common::{parse_document, status_from_response, ParseError};
use crate::{GmpResponse, GmpVersion};

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct GetVersionResponse {
    pub status: u16,
    pub status_text: String,
    pub version: String,
}

impl GetVersionResponse {
    pub fn from_response(response: &Response) -> Result<Self, ParseError> {
        let (status, status_text) = status_from_response(response)?;
        let root = parse_document(response.data())?;
        Ok(Self {
            status,
            status_text,
            version: root.required_child_text("version")?,
        })
    }
}

impl GmpResponse for GetVersionResponse {
    fn decode(response: &Response, _version: GmpVersion) -> Result<Self, ParseError> {
        Self::from_response(response)
    }
}

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    fn nested_version_response(depth: usize) -> Response {
        assert!(depth >= 1);
        let mut xml = String::from(r#"<get_version_response status="200" status_text="OK">"#);
        for _ in 1..depth {
            xml.push_str("<nested>");
        }
        for _ in 1..depth {
            xml.push_str("</nested>");
        }
        xml.push_str("<version>22.7</version></get_version_response>");
        Response::from(xml.into_bytes())
    }

    #[test]
    fn parses_version_response() {
        let response = Response::from(
            r#"<get_version_response status="200" status_text="OK"><version>22.7</version></get_version_response>"#,
        );

        let parsed = GetVersionResponse::from_response(&response).expect("version parses");

        assert_eq!(parsed.status, 200);
        assert_eq!(parsed.status_text, "OK");
        assert_eq!(parsed.version, "22.7");
    }

    #[test]
    fn rejects_server_error() {
        let response =
            Response::from(r#"<get_version_response status="500" status_text="Backend down"/>"#);

        let error = GetVersionResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(
            error,
            ParseError::ServerError {
                status: 500,
                message
            } if message == "Backend down"
        ));
    }

    #[test]
    fn rejects_missing_version() {
        let response = Response::from(r#"<get_version_response status="200" status_text="OK"/>"#);

        let error = GetVersionResponse::from_response(&response).expect_err("error expected");

        assert!(matches!(error, ParseError::MissingElement(ref field) if field == "version"));
    }

    #[test]
    fn accepts_response_at_default_nesting_limit() {
        let response = nested_version_response(256);

        let parsed = GetVersionResponse::from_response(&response)
            .expect("response at the default nesting limit should parse");

        assert_eq!(parsed.version, "22.7");
    }

    #[test]
    fn rejects_response_above_default_nesting_limit() {
        let response = nested_version_response(257);

        let error = GetVersionResponse::from_response(&response)
            .expect_err("response above the default nesting limit should fail");

        assert!(matches!(
            error,
            ParseError::NestingLimitExceeded { max_depth: 256 }
        ));
    }

    #[test]
    fn deeply_nested_response_returns_error_on_small_stack() {
        let response = nested_version_response(50_000);
        let result = std::thread::Builder::new()
            .name("typed-response-depth-limit".to_string())
            .stack_size(64 * 1024)
            .spawn(move || GetVersionResponse::from_response(&response))
            .expect("test thread should start")
            .join()
            .expect("typed decoder must not abort or panic");

        assert!(matches!(
            result,
            Err(ParseError::NestingLimitExceeded { max_depth: 256 })
        ));
    }
}
