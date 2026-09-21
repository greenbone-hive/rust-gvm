// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! Canonical help discovery request.

use gvm_protocol::{Request as _, XmlCommand};

use crate::enums::HelpFormat;
use crate::responses::HelpResponse;
use crate::{GmpCommand, GmpRequest, GmpRequestCodec, GmpRequestError, GmpVersion};

/// Valid gvmd help response modes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum HelpMode {
    /// Plain-text command summary.
    #[default]
    Text,
    /// Abbreviated XML command listing used for command discovery.
    BriefXml,
    /// Complete schema in the selected format.
    Schema(HelpFormat),
}

/// Canonical `help` request.
#[derive(Debug, Clone, Copy, Default)]
pub struct HelpRequest {
    /// Requested response mode.
    pub mode: HelpMode,
}

impl HelpRequest {
    /// Create a help request in the selected mode.
    #[must_use]
    pub const fn new(mode: HelpMode) -> Self {
        Self { mode }
    }
}

impl GmpRequestCodec for HelpRequest {
    fn command(&self) -> Option<GmpCommand> {
        Some(GmpCommand::new("help"))
    }

    fn encode(&self, _version: GmpVersion) -> Result<Vec<u8>, GmpRequestError> {
        let mut command = XmlCommand::new("help");
        match self.mode {
            HelpMode::Text => {}
            HelpMode::BriefXml => {
                command.set_attribute("format", HelpFormat::Xml.as_gmp_str());
                command.set_attribute("type", "brief");
            }
            HelpMode::Schema(format) => {
                command.set_attribute("format", format.as_gmp_str());
            }
        }
        Ok(command.to_bytes())
    }
}

impl GmpRequest for HelpRequest {
    type Response = HelpResponse;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_help_modes_build_source_faithful_xml() {
        for (mode, expected) in [
            (HelpMode::Text, "<help/>"),
            (HelpMode::BriefXml, "<help format=\"xml\" type=\"brief\"/>"),
            (
                HelpMode::Schema(HelpFormat::Html),
                "<help format=\"html\"/>",
            ),
            (HelpMode::Schema(HelpFormat::Rnc), "<help format=\"rnc\"/>"),
            (
                HelpMode::Schema(HelpFormat::Text),
                "<help format=\"text\"/>",
            ),
            (HelpMode::Schema(HelpFormat::Xml), "<help format=\"xml\"/>"),
        ] {
            assert_eq!(
                HelpRequest::new(mode)
                    .encode(GmpVersion(22, 4))
                    .expect("help encodes"),
                expected.as_bytes()
            );
        }
    }
}
