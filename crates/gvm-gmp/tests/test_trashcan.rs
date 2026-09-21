// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

mod common;

use common::id;
use gvm_gmp::commands::trashcan::{EmptyTrashcanRequest, RestoreRequest};
use gvm_gmp::{GmpRequestCodec, GmpVersion};

#[test]
fn test_empty_trashcan_basic() {
    assert_eq!(
        EmptyTrashcanRequest::new()
            .encode(GmpVersion(22, 4))
            .unwrap(),
        b"<empty_trashcan/>"
    );
}

#[test]
fn test_restore_basic() {
    assert_eq!(
        RestoreRequest::new(id("r1"))
            .encode(GmpVersion(22, 4))
            .unwrap(),
        b"<restore id=\"r1\"/>"
    );
}
