// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

#![allow(missing_docs, clippy::unwrap_used)]

use gvm_gmp::commands::features::GetFeaturesRequest;
use gvm_gmp::{GmpRequestCodec, GmpVersion};

#[test]
fn test_get_features() {
    assert_eq!(
        GetFeaturesRequest::new().encode(GmpVersion(22, 6)).unwrap(),
        b"<get_features/>"
    );
}
