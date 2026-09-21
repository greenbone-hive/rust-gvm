// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical trashcan cleanup and recovery requests.

use gvm_protocol::{Request as _, XmlCommand};

use crate::responses::{EmptyTrashcanResponse, RestoreResponse};
use crate::types::EntityId;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Canonical request for permanently emptying the authenticated user's trashcan.
#[derive(Debug, Clone, Copy, Default)]
pub struct EmptyTrashcanRequest;

impl EmptyTrashcanRequest {
    /// Create an empty-trashcan request.
    #[must_use]
    pub const fn new() -> Self {
        Self
    }
}

impl GmpRequestCodec for EmptyTrashcanRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("empty_trashcan"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("empty_trashcan").to_bytes())
    }
}

impl GmpRequest for EmptyTrashcanRequest {
    type Response = EmptyTrashcanResponse;
}

/// Canonical request for restoring one resource from the trashcan.
#[derive(Debug, Clone)]
pub struct RestoreRequest {
    /// Required trashed resource identifier.
    pub resource_id: EntityId,
}

impl RestoreRequest {
    /// Create a restore request.
    #[must_use]
    pub fn new(resource_id: EntityId) -> Self {
        Self { resource_id }
    }
}

impl GmpRequestCodec for RestoreRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("restore"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        Ok(XmlCommand::new("restore")
            .attribute("id", self.resource_id.as_str())
            .to_bytes())
    }
}

impl GmpRequest for RestoreRequest {
    type Response = RestoreResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_trashcan_requests_encode_and_associate() {
        fn associated<R, T>(_: &R)
        where
            R: GmpRequest<Response = T>,
            T: crate::GmpResponse,
        {
        }

        let version = GmpVersion(22, 4);
        let empty = EmptyTrashcanRequest::new();
        assert_eq!(empty.encode(version).expect("encode"), b"<empty_trashcan/>");
        associated::<_, EmptyTrashcanResponse>(&empty);

        let restore = RestoreRequest::new(EntityId::new("resource-1").expect("valid id"));
        assert_eq!(
            restore.encode(version).expect("encode"),
            b"<restore id=\"resource-1\"/>"
        );
        associated::<_, RestoreResponse>(&restore);
    }
}
