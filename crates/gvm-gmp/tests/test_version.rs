// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::version::GetVersionRequest;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

#[test]
fn test_get_version_basic() {
    assert_eq!(
        GetVersionRequest::new()
            .encode(GmpVersion(22, 4))
            .expect("encode"),
        b"<get_version/>"
    );
}
