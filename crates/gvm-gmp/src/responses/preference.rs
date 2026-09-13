// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Compatibility names for preference response models.

pub use super::scan_config::{
    GetScanConfigPreferencesResponse as GetPreferencesResponse, ScanConfigPreference as Preference,
    ScanConfigPreferenceNvt as PreferenceNvt,
};

#[cfg(test)]
mod tests {
    use gvm_protocol::Response;

    use super::*;

    #[test]
    fn compatibility_response_name_uses_the_scan_config_codec() {
        let response = Response::from(
            r#"<get_preferences_response status="200" status_text="OK">
                <preference>
                    <nvt oid="1.3.6.1"><name>Services</name></nvt>
                    <id>1</id>
                    <name>Timeout</name>
                    <type>entry</type>
                    <value></value>
                    <alt>5</alt>
                    <default>5</default>
                </preference>
            </get_preferences_response>"#,
        );

        let parsed = GetPreferencesResponse::from_response(&response)
            .expect("compatibility response should use the canonical codec");
        let preference: &Preference = &parsed.items[0];
        let nvt: &PreferenceNvt = preference.nvt.as_ref().expect("NVT should parse");
        assert_eq!(nvt.oid, "1.3.6.1");
        assert_eq!(preference.value.as_deref(), Some(""));
        assert_eq!(preference.alternatives, ["5"]);
    }
}
