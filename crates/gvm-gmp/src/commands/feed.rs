// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical feed discovery requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::enums::FeedType;
use crate::responses::GetFeedsResponse;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical request for listing every configured feed.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetFeedsRequest;

impl GetFeedsRequest {
    /// Create an all-feeds request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for GetFeedsRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("get_feeds"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_feeds").to_bytes())
    }
}

impl GmpRequest for GetFeedsRequest {
    type Response = GetFeedsResponse;
}

/// Canonical semantic detail request for one feed type.
#[derive(Debug, Clone, Copy)]
pub struct GetFeedRequest {
    /// Feed type to retrieve.
    pub feed_type: FeedType,
}

impl GetFeedRequest {
    /// Create a type-filtered feed request.
    #[must_use]
    pub const fn new(feed_type: FeedType) -> Self {
        Self { feed_type }
    }
}

impl GmpRequestCodec for GetFeedRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::with_semantic_name("get_feeds", "get_feed"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("get_feeds")
            .attribute("type", self.feed_type.as_gmp_str())
            .to_bytes())
    }
}

impl GmpRequest for GetFeedRequest {
    type Response = GetFeedsResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn feed_list_and_detail_are_distinct_semantic_requests() {
        assert_eq!(
            GetFeedsRequest::new()
                .encode(GmpVersion(22, 4))
                .expect("feeds encode"),
            b"<get_feeds/>"
        );
        let detail = GetFeedRequest::new(FeedType::Gvmd);
        assert_eq!(
            detail.encode(GmpVersion(22, 4)).expect("feed encodes"),
            b"<get_feeds type=\"GVMD_DATA\"/>"
        );
        assert_eq!(
            detail.command().and_then(GmpCommand::semantic_name),
            Some("get_feed")
        );
    }
}
