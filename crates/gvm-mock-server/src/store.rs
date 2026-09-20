// SPDX-License-Identifier: AGPL-3.0-or-later
// SPDX-FileCopyrightText: 2026 Greenbone AG

//! In-memory resource store for Stateful mode.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::{Arc, RwLock};

use chrono::DateTime;
use gvm_gmp::AliveTest;
use uuid::Uuid;

use crate::util::{now_iso, xml_escape, xml_escape_attr};

/// Input profile for stateful asset commands.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AssetInputProfile {
    /// Require the asset command shapes accepted by current gvmd.
    #[default]
    GvmdStrict,
    /// Accept the historical flat mock inputs (`asset_type`, `<asset_type>`, and `<value>`).
    ///
    /// This profile exists only for consumers that explicitly need compatibility
    /// with the mock's former, non-canonical asset command surface.
    LegacyFlatCompatibility,
}

/// Result of an atomic permanent asset deletion.
pub(crate) enum DeleteAssetResult {
    /// The asset was deleted.
    Deleted,
    /// The operating-system asset is still referenced.
    InUse,
    /// No live asset with the requested ID exists.
    NotFound,
}

pub(crate) const DEFAULT_CONFIG_ID: Uuid =
    Uuid::from_u128(0xdaba_56c8_73ec_11df_a475_0022_6476_4cea);
pub(crate) const SECOND_SCAN_CONFIG_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0300);
pub(crate) const FIRST_POLICY_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0301);
pub(crate) const SECOND_POLICY_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0302);
pub(crate) const PREDEFINED_CONFIG_ID: Uuid = Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0303);
pub(crate) const CONFIG_SAVED_FILTER_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0304);
pub(crate) const DEFAULT_SCANNER_ID: Uuid =
    Uuid::from_u128(0x08b6_9003_5fc2_4037_a479_93b4_4021_1c73);
pub(crate) const DEFAULT_CONTAINER_SCANNER_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0010);
pub(crate) const DEFAULT_WEB_SCANNER_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_4000_8000_0000_0000_0011);
pub(crate) const CONFIGURABLE_REPORT_FORMAT_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0200);
pub(crate) const NONCONFIGURABLE_REPORT_FORMAT_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0201);
pub(crate) const REPORT_CONFIG_SAVED_FILTER_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0202);
pub(crate) const REPORT_FORMAT_SAVED_FILTER_ID: Uuid =
    Uuid::from_u128(0x0000_0000_0000_0000_0000_0000_0000_0203);

/// NVT preference data used by the bounded discovery mock.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPreference {
    /// Stored preference key (`OID:id:type:name`).
    pub key: String,
    /// Seed value used when no explicit default is available.
    pub value: String,
    /// Scanner default value.
    pub default: Option<String>,
    /// Ordered alternatives for radio/select preferences.
    pub alternatives: Vec<String>,
}

/// NVT data used by the bounded discovery mock.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryNvt {
    /// NVT object identifier.
    pub oid: String,
    /// Display name.
    pub name: String,
    /// Family name.
    pub family: String,
    /// CVSS base score.
    pub cvss_base: f64,
    /// Severity string.
    pub severity: String,
    /// Raw NVT tags.
    pub tags: String,
    /// Solution type attribute.
    pub solution_type: String,
    /// Default timeout in seconds.
    pub timeout: u32,
    /// NVT and scanner preferences in stored-key order.
    pub preferences: Vec<DiscoveryPreference>,
}

/// SecInfo record used by the bounded discovery mock.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoverySecInfo {
    /// gvmd SecInfo type token.
    pub info_type: String,
    /// Type-specific identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Optional severity used by bounded filters.
    pub severity: Option<f64>,
}

/// Observed vulnerability summary used by `get_vulns`.
#[derive(Debug, Clone, PartialEq)]
pub struct DiscoveryVulnerability {
    /// Vulnerability identifier.
    pub id: String,
    /// Display name.
    pub name: String,
    /// Vulnerability source/type.
    pub type_: String,
    /// Highest observed severity.
    pub severity: f64,
    /// Minimum quality of detection.
    pub qod: u32,
    /// Number of matching results.
    pub result_count: u32,
    /// Number of matching hosts.
    pub host_count: u32,
    /// Optional task context.
    pub task_id: Option<String>,
    /// Optional report context.
    pub report_id: Option<String>,
    /// Optional host context.
    pub host: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct DiscoverySnapshot {
    pub nvts: BTreeMap<String, DiscoveryNvt>,
    pub scanner_preferences: Vec<DiscoveryPreference>,
    pub config_nvts: BTreeMap<String, BTreeSet<String>>,
    pub config_preferences: BTreeMap<String, BTreeMap<String, String>>,
    pub secinfo: Vec<DiscoverySecInfo>,
    pub vulnerabilities: Vec<DiscoveryVulnerability>,
    pub saved_filters: BTreeMap<String, String>,
    pub user_default_filter: Option<String>,
    pub nvt_feed_available: bool,
    pub scap_available: bool,
    pub cert_available: bool,
    pub secinfo_permitted: bool,
}

fn default_discovery() -> DiscoverySnapshot {
    let nvt_one = DiscoveryNvt {
        oid: "1.3.6.1.4.1.25623.1".to_string(),
        name: "Mock NVT one".to_string(),
        family: "General".to_string(),
        cvss_base: 9.8,
        severity: "9.8".to_string(),
        tags: "solution=Update the affected package|summary=Mock finding".to_string(),
        solution_type: "VendorFix".to_string(),
        timeout: 300,
        preferences: vec![
            DiscoveryPreference {
                key: "1.3.6.1.4.1.25623.1:1:password:Password".to_string(),
                value: "mock-secret".to_string(),
                default: Some("default-secret".to_string()),
                alternatives: Vec::new(),
            },
            DiscoveryPreference {
                key: "1.3.6.1.4.1.25623.1:2:radio:Mode".to_string(),
                value: "safe".to_string(),
                default: Some("safe".to_string()),
                alternatives: vec!["safe".to_string(), "fast".to_string()],
            },
            DiscoveryPreference {
                key: "1.3.6.1.4.1.25623.1:3:entry:Retries:with:suffix".to_string(),
                value: "2".to_string(),
                default: Some("1".to_string()),
                alternatives: Vec::new(),
            },
        ],
    };
    let nvt_two = DiscoveryNvt {
        oid: "1.3.6.1.4.1.25623.2".to_string(),
        name: "Mock NVT two".to_string(),
        family: "Web application abuses".to_string(),
        cvss_base: 5.3,
        severity: "5.3".to_string(),
        tags: "solution=Harden the service|summary=Secondary mock finding".to_string(),
        solution_type: "Mitigation".to_string(),
        timeout: 180,
        preferences: Vec::new(),
    };
    let nvts = [nvt_one, nvt_two]
        .into_iter()
        .map(|nvt| (nvt.oid.clone(), nvt))
        .collect();
    let config_nvts = [
        (
            DEFAULT_CONFIG_ID.to_string(),
            BTreeSet::from(["1.3.6.1.4.1.25623.1".to_string()]),
        ),
        (
            SECOND_SCAN_CONFIG_ID.to_string(),
            BTreeSet::from(["1.3.6.1.4.1.25623.2".to_string()]),
        ),
        (
            FIRST_POLICY_ID.to_string(),
            BTreeSet::from([
                "1.3.6.1.4.1.25623.1".to_string(),
                "1.3.6.1.4.1.25623.2".to_string(),
            ]),
        ),
        (SECOND_POLICY_ID.to_string(), BTreeSet::new()),
    ]
    .into_iter()
    .collect();
    let config_preferences = [
        (
            DEFAULT_CONFIG_ID.to_string(),
            BTreeMap::from([
                (
                    "1.3.6.1.4.1.25623.1:0:entry:timeout".to_string(),
                    "120".to_string(),
                ),
                (
                    "1.3.6.1.4.1.25623.1:2:radio:Mode".to_string(),
                    "fast".to_string(),
                ),
                (
                    "1.3.6.1.4.1.25623.1:1:password:Password".to_string(),
                    "configuration-secret".to_string(),
                ),
            ]),
        ),
        (SECOND_SCAN_CONFIG_ID.to_string(), BTreeMap::new()),
        (
            FIRST_POLICY_ID.to_string(),
            BTreeMap::from([(":0:entry:table_driven_lsc".to_string(), "1".to_string())]),
        ),
        (SECOND_POLICY_ID.to_string(), BTreeMap::new()),
    ]
    .into_iter()
    .collect();
    let secinfo = [
        ("CPE", "cpe:/a:greenbone:gvm", "Greenbone GVM", None),
        ("CPE", "cpe:/o:debian:debian_linux:12", "Debian 12", None),
        ("CVE", "CVE-2026-1000", "Mock CVE one", Some(9.8)),
        ("CVE", "CVE-2026-1001", "Mock CVE two", Some(5.3)),
        (
            "CERT_BUND_ADV",
            "CB-K26/001",
            "CERT-Bund advisory one",
            Some(9.8),
        ),
        (
            "DFN_CERT_ADV",
            "DFN-2026-001",
            "DFN-CERT advisory one",
            Some(5.3),
        ),
        ("NVT", "1.3.6.1.4.1.25623.1", "Mock NVT one", Some(9.8)),
        ("NVT", "1.3.6.1.4.1.25623.2", "Mock NVT two", Some(5.3)),
    ]
    .into_iter()
    .map(|(info_type, id, name, severity)| DiscoverySecInfo {
        info_type: info_type.to_string(),
        id: id.to_string(),
        name: name.to_string(),
        severity,
    })
    .collect();
    let vulnerabilities = vec![
        DiscoveryVulnerability {
            id: "vuln-1".to_string(),
            name: "Outdated package".to_string(),
            type_: "cve".to_string(),
            severity: 9.8,
            qod: 95,
            result_count: 2,
            host_count: 1,
            task_id: Some("task-1".to_string()),
            report_id: Some("report-1".to_string()),
            host: Some("192.0.2.10".to_string()),
        },
        DiscoveryVulnerability {
            id: "vuln-2".to_string(),
            name: "Weak configuration".to_string(),
            type_: "nvt".to_string(),
            severity: 5.3,
            qod: 70,
            result_count: 1,
            host_count: 1,
            task_id: Some("task-2".to_string()),
            report_id: Some("report-2".to_string()),
            host: Some("192.0.2.20".to_string()),
        },
    ];
    DiscoverySnapshot {
        nvts,
        scanner_preferences: vec![DiscoveryPreference {
            key: ":4:entry:Scanner option".to_string(),
            value: "enabled".to_string(),
            default: Some("enabled".to_string()),
            alternatives: Vec::new(),
        }],
        config_nvts,
        config_preferences,
        secinfo,
        vulnerabilities,
        saved_filters: BTreeMap::new(),
        user_default_filter: None,
        nvt_feed_available: true,
        scap_available: true,
        cert_available: true,
        secinfo_permitted: true,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum StoreError {
    NotFound(String),
    InUse(&'static str),
    InvalidArgument(&'static str),
    InvalidState(&'static str),
    Inconsistent(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigPreferenceUpdate {
    pub nvt_oid: Option<String>,
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigNvtSelectionUpdate {
    pub family: String,
    pub nvt_oids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigFamilySelectionEntry {
    pub name: String,
    pub growing: bool,
    pub all: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ConfigFamilySelectionUpdate {
    pub families: Vec<ConfigFamilySelectionEntry>,
    pub auto_add_new_families: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ConfigMutationAction {
    Preference(ConfigPreferenceUpdate),
    NvtSelection(ConfigNvtSelectionUpdate),
    FamilySelection(ConfigFamilySelectionUpdate),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub(crate) struct ConfigMutation {
    pub name: Option<String>,
    pub comment: Option<String>,
    pub actions: Vec<ConfigMutationAction>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReportConfigParamUpdate {
    Value { name: String, value: String },
    UseDefault { name: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SpecializedTaskTarget {
    AgentGroup(Uuid),
    OciImageTarget(Uuid),
    WebApplicationTarget(Uuid),
}

impl SpecializedTaskTarget {
    fn resource_type(self) -> &'static str {
        match self {
            Self::AgentGroup(_) => "agent_group",
            Self::OciImageTarget(_) => "oci_image_target",
            Self::WebApplicationTarget(_) => "web_application_target",
        }
    }

    fn attr_name(self) -> &'static str {
        match self {
            Self::AgentGroup(_) => "agent_group_id",
            Self::OciImageTarget(_) => "oci_image_target_id",
            Self::WebApplicationTarget(_) => "web_application_target_id",
        }
    }

    fn id(self) -> Uuid {
        match self {
            Self::AgentGroup(id) | Self::OciImageTarget(id) | Self::WebApplicationTarget(id) => id,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TaskReferences {
    pub target: Option<Uuid>,
    pub specialized_target: Option<SpecializedTaskTarget>,
    pub config: Option<Uuid>,
    pub scanner: Option<Uuid>,
    pub schedule: Option<Uuid>,
    pub schedule_periods: Option<u32>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) enum TaskScheduleUpdate {
    #[default]
    Omitted,
    Set(Uuid),
    Clear,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct TaskReferenceUpdates {
    pub target: Option<Uuid>,
    pub specialized_target: Option<SpecializedTaskTarget>,
    pub config: Option<Uuid>,
    pub scanner: Option<Uuid>,
    pub schedule: TaskScheduleUpdate,
    pub schedule_periods: Option<u32>,
}

impl TaskReferenceUpdates {
    fn changes_scan_definition(self) -> bool {
        self.target.is_some()
            || self.specialized_target.is_some()
            || self.config.is_some()
            || self.scanner.is_some()
    }
}

/// Task status in the lifecycle state machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    /// Newly created, not yet started.
    New,
    /// Start requested.
    Requested,
    /// Waiting for scanner capacity.
    Queued,
    /// Currently running.
    Running,
    /// Stop requested.
    StopRequested,
    /// Delete requested while processing is still active.
    DeleteRequested,
    /// Ultimate deletion requested while processing is still active.
    UltimateDeleteRequested,
    /// Stopped by user.
    Stopped,
    /// Completed successfully.
    Done,
    /// Interrupted before completion and eligible for resumption.
    Interrupted,
    /// Report data is being processed.
    Processing,
}

impl TaskStatus {
    /// Return the GMP status string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::New => "New",
            Self::Requested => "Requested",
            Self::Queued => "Queued",
            Self::Running => "Running",
            Self::StopRequested => "Stop Requested",
            Self::DeleteRequested => "Delete Requested",
            Self::UltimateDeleteRequested => "Ultimate Delete Requested",
            Self::Stopped => "Stopped",
            Self::Done => "Done",
            Self::Interrupted => "Interrupted",
            Self::Processing => "Processing",
        }
    }
}

/// A stored GMP resource (generic for all resource types).
#[derive(Debug, Clone)]
pub struct Resource {
    /// Resource UUID.
    pub id: Uuid,
    /// Resource type name (e.g., "task", "target").
    pub resource_type: String,
    /// Resource name.
    pub name: String,
    /// Optional comment.
    pub comment: String,
    /// Creation timestamp (ISO 8601).
    pub creation_time: String,
    /// Modification timestamp (ISO 8601).
    pub modification_time: String,
    /// Additional type-specific attributes.
    pub attrs: BTreeMap<String, String>,
    /// Whether this resource is in the trashcan.
    pub trashed: bool,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AuditComplianceCounts {
    pub(crate) yes: usize,
    pub(crate) no: usize,
    pub(crate) incomplete: usize,
    pub(crate) undefined: usize,
}

impl AuditComplianceCounts {
    pub(crate) fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
        let mut counts = Self::default();
        for result in results {
            match result
                .attr("compliance")
                .unwrap_or("undefined")
                .to_ascii_lowercase()
                .as_str()
            {
                "yes" => counts.yes += 1,
                "no" => counts.no += 1,
                "incomplete" => counts.incomplete += 1,
                _ => counts.undefined += 1,
            }
        }
        counts
    }

    pub(crate) fn total(self) -> usize {
        self.yes + self.no + self.incomplete + self.undefined
    }

    pub(crate) fn compliance(self) -> &'static str {
        if self.no > 0 {
            "no"
        } else if self.incomplete > 0 {
            "incomplete"
        } else if self.yes > 0 {
            "yes"
        } else {
            "undefined"
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct ScanReportResultCounts {
    pub(crate) total: usize,
    pub(crate) critical: usize,
    pub(crate) high: usize,
    pub(crate) medium: usize,
    pub(crate) low: usize,
    pub(crate) log: usize,
    pub(crate) false_positive: usize,
    pub(crate) errors: usize,
    pub(crate) hosts: usize,
    pub(crate) ports: usize,
    pub(crate) max_severity: f64,
}

impl ScanReportResultCounts {
    pub(crate) fn from_results<'a>(results: impl Iterator<Item = &'a Resource>) -> Self {
        let mut counts = Self::default();
        let mut hosts = BTreeSet::new();
        let mut ports = BTreeSet::new();
        for result in results {
            counts.total += 1;
            let severity = scan_report_result_severity(result);
            counts.max_severity = counts.max_severity.max(severity);
            if result.attr("false_positive") == Some("1") {
                counts.false_positive += 1;
            } else if severity >= 9.0 {
                counts.critical += 1;
            } else if severity >= 7.0 {
                counts.high += 1;
            } else if severity >= 4.0 {
                counts.medium += 1;
            } else if severity > 0.0 {
                counts.low += 1;
            } else {
                counts.log += 1;
            }
            if result.attr("threat") == Some("Error") {
                counts.errors += 1;
            }
            if let Some(host) = result.attr("host") {
                hosts.insert(host);
            }
            if let Some(port) = result.attr("port") {
                ports.insert(port);
            }
        }
        counts.hosts = hosts.len();
        counts.ports = ports.len();
        counts
    }
}

pub(crate) fn scan_report_result_severity(result: &Resource) -> f64 {
    result
        .attr("severity")
        .and_then(|severity| severity.parse().ok())
        .unwrap_or_default()
}

impl Resource {
    /// Create a new resource with auto-generated UUID and timestamps.
    pub fn new(resource_type: &str, name: &str) -> Self {
        let now = now_iso();
        Self {
            id: Uuid::new_v4(),
            resource_type: resource_type.to_string(),
            name: name.to_string(),
            comment: String::new(),
            creation_time: now.clone(),
            modification_time: now,
            attrs: BTreeMap::new(),
            trashed: false,
        }
    }

    /// Create with a specific UUID.
    pub fn with_id(resource_type: &str, name: &str, id: Uuid) -> Self {
        let mut r = Self::new(resource_type, name);
        r.id = id;
        r
    }

    /// Set an attribute.
    pub fn set_attr(&mut self, key: &str, value: &str) {
        self.attrs.insert(key.to_string(), value.to_string());
    }

    /// Remove an attribute.
    pub fn remove_attr(&mut self, key: &str) {
        self.attrs.remove(key);
    }

    /// Get an attribute.
    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    /// Return the canonical asset type, including legacy seeded resources.
    pub(crate) fn asset_type(&self) -> Option<&str> {
        self.attr("type").or_else(|| self.attr("asset_type"))
    }

    /// Generate the canonical gvmd asset representation used by `get_assets`.
    pub(crate) fn to_asset_xml(&self) -> String {
        let asset_type = self.asset_type().unwrap_or_default();
        let writable = if asset_type == "os" { "0" } else { "1" };
        let in_use = if asset_type == "os" && self.operating_system_asset_is_referenced() {
            "1"
        } else {
            "0"
        };
        let common = format!(
            "<asset id=\"{id}\">\
             <owner><name>admin</name></owner>\
             <name>{name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>\
             <writable>{writable}</writable>\
             <in_use>{in_use}</in_use>\
             <permissions><permission><name>Everything</name></permission></permissions>",
            id = self.id,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
            writable = writable,
            in_use = in_use,
        );

        match asset_type {
            "host" => {
                let severity = self.attr("severity").unwrap_or_default();
                format!(
                    "{common}\
                     <identifiers><identifier id=\"{id}\">\
                     <name>ip</name><value>{name}</value>\
                     <creation_time>{ct}</creation_time>\
                     <modification_time>{mt}</modification_time>\
                     <source><type>User</type><data></data><deleted>0</deleted><name>admin</name></source>\
                     </identifier></identifiers>\
                     <type>host</type>\
                     <host><severity><value>{severity}</value></severity></host>\
                     </asset>",
                    id = self.id,
                    name = xml_escape(&self.name),
                    ct = self.creation_time,
                    mt = self.modification_time,
                    severity = xml_escape(severity),
                )
            }
            "os" => {
                let title = self.attr("title").unwrap_or(&self.name);
                let installs = self.attr("installs").unwrap_or("0");
                let all_installs = self.attr("all_installs").unwrap_or(installs);
                let latest = self.attr("latest_severity").unwrap_or_default();
                let highest = self.attr("highest_severity").unwrap_or_default();
                let average = self.attr("average_severity").unwrap_or_default();
                format!(
                    "{common}\
                     <type>os</type>\
                     <os>\
                     <latest_severity><value>{latest}</value></latest_severity>\
                     <highest_severity><value>{highest}</value></highest_severity>\
                     <average_severity><value>{average}</value></average_severity>\
                     <title>{title}</title>\
                     <installs>{installs}</installs>\
                     <all_installs>{all_installs}</all_installs>\
                     <hosts>{installs}</hosts>\
                     </os>\
                     </asset>",
                    latest = xml_escape(latest),
                    highest = xml_escape(highest),
                    average = xml_escape(average),
                    title = xml_escape(title),
                    installs = xml_escape(installs),
                    all_installs = xml_escape(all_installs),
                )
            }
            _ => format!("{common}<type>{}</type></asset>", xml_escape(asset_type)),
        }
    }

    /// Approximate gvmd's `host_oss` reference guard from seeded aggregate
    /// counts. `all_installs` includes non-best matches; older seeds that omit
    /// it fall back to the best-match `installs` count.
    fn operating_system_asset_is_referenced(&self) -> bool {
        self.attr("all_installs")
            .or_else(|| self.attr("installs"))
            .and_then(|value| value.parse::<u32>().ok())
            .is_some_and(|count| count > 0)
    }

    /// Generate XML representation for get responses.
    pub fn to_xml(&self) -> String {
        self.to_xml_with_details(false)
    }

    /// Generate XML representation for get responses with command detail semantics.
    pub(crate) fn to_xml_with_details(&self, details: bool) -> String {
        self.to_xml_with_task_reports(None, None, &[], details)
    }

    fn to_xml_with_task_reports(
        &self,
        current_report: Option<&Resource>,
        last_report: Option<&Resource>,
        last_report_results: &[&Resource],
        details: bool,
    ) -> String {
        // Notes and overrides use <text> instead of <name>
        let name_tag = if self.resource_type == "note" || self.resource_type == "override" {
            "text"
        } else {
            "name"
        };
        let oid_attr = if self.resource_type == "nvt" {
            self.attr("oid")
                .or_else(|| self.attr("nvt_oid"))
                .map(|oid| format!(" oid=\"{}\"", xml_escape_attr(oid)))
                .unwrap_or_default()
        } else {
            String::new()
        };
        let mut xml = format!(
            "<{type} id=\"{id}\"{oid_attr}>\
             <{name_tag}>{name}</{name_tag}>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>",
            type = self.resource_type,
            id = self.id,
            oid_attr = oid_attr,
            name_tag = name_tag,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
        );
        if self.resource_type == "permission" {
            for (element, id_key, type_key) in [
                ("subject", "subject_id", "subject_type"),
                ("resource", "resource_id", "resource_type"),
            ] {
                if let Some(id) = self.attr(id_key).filter(|value| !value.is_empty()) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name>",
                        xml_escape_attr(id),
                    ));
                    if let Some(reference_type) =
                        self.attr(type_key).filter(|value| !value.is_empty())
                    {
                        xml.push_str(&format!("<type>{}</type>", xml_escape(reference_type)));
                    }
                    xml.push_str(&format!("</{element}>"));
                }
            }
        }
        if self.resource_type == "task" {
            if let Some(alterable) = self.attr("alterable") {
                xml.push_str(&format!("<alterable>{}</alterable>", xml_escape(alterable)));
            }
            if let Some(alert_ids) = self.attr("alert_ids") {
                for alert_id in alert_ids.split(',').filter(|id| !id.is_empty()) {
                    xml.push_str(&format!(
                        "<alert id=\"{}\"><name>{}</name></alert>",
                        xml_escape_attr(alert_id),
                        xml_escape(alert_id),
                    ));
                }
            }
            if self.attr("observers").is_some() || self.attr("observer_group_ids").is_some() {
                xml.push_str("<observers>");
                if let Some(observers) = self.attr("observers") {
                    xml.push_str(&xml_escape(observers));
                }
                if let Some(group_ids) = self.attr("observer_group_ids") {
                    for group_id in group_ids.split(',').filter(|id| !id.is_empty()) {
                        xml.push_str(&format!(
                            "<group id=\"{}\"><name>{}</name></group>",
                            xml_escape_attr(group_id),
                            xml_escape(group_id),
                        ));
                    }
                }
                xml.push_str("</observers>");
            }
            let preferences = self
                .attrs
                .iter()
                .filter_map(|(key, value)| {
                    key.strip_prefix("task_preference:")
                        .map(|name| (name, value))
                })
                .collect::<Vec<_>>();
            if !preferences.is_empty() {
                xml.push_str("<preferences>");
                for (name, value) in preferences {
                    xml.push_str(&format!(
                        "<preference><scanner_name>{}</scanner_name><value>{}</value></preference>",
                        xml_escape(name),
                        xml_escape(value),
                    ));
                }
                xml.push_str("</preferences>");
            }
            if self.attr("target_id").is_none() {
                xml.push_str("<target id=\"\"><name></name></target>");
            }
            for (attribute, element) in [
                ("target_id", "target"),
                ("agent_group_id", "agent_group"),
                ("oci_image_target_id", "oci_image_target"),
                ("web_application_target_id", "web_application_target"),
                ("config_id", "config"),
                ("scanner_id", "scanner"),
                ("schedule_id", "schedule"),
            ] {
                if let Some(id) = self.attr(attribute) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                }
            }
            xml.push_str(&format!(
                "<schedule_periods>{}</schedule_periods>",
                xml_escape(self.attr("schedule_periods").unwrap_or("0")),
            ));
            if let Some(report) = current_report {
                xml.push_str(&task_report_reference_xml("current_report", report, &[]));
            }
            if let Some(report) = last_report {
                xml.push_str(&task_report_reference_xml(
                    "last_report",
                    report,
                    last_report_results,
                ));
            }
        }
        if self.resource_type == "user" {
            if let Some(role_ids) = self.attr("role_ids") {
                for role_id in role_ids.split(',').filter(|role_id| !role_id.is_empty()) {
                    let role_id_attr = xml_escape_attr(role_id);
                    let role_id = xml_escape(role_id);
                    xml.push_str(&format!(
                        "<role id=\"{role_id_attr}\"><name>{role_id}</name></role>"
                    ));
                }
            }
            if let Some(group_ids) = self.attr("group_ids") {
                xml.push_str("<groups>");
                for group_id in group_ids.split(',').filter(|group_id| !group_id.is_empty()) {
                    let group_id_attr = xml_escape_attr(group_id);
                    let group_id = xml_escape(group_id);
                    xml.push_str(&format!(
                        "<group id=\"{group_id_attr}\"><name>{group_id}</name></group>"
                    ));
                }
                xml.push_str("</groups>");
            }
            if let Some(hosts) = self.attr("hosts") {
                xml.push_str(&format!(
                    "<hosts allow=\"{}\">{}</hosts>",
                    xml_escape_attr(self.attr("hosts_allow").unwrap_or("1")),
                    xml_escape(hosts),
                ));
            }
            if let Some(source) = self.attr("auth_source") {
                xml.push_str(&format!(
                    "<sources><source>{}</source></sources>",
                    xml_escape(source),
                ));
            }
        }
        if matches!(self.resource_type.as_str(), "group" | "role") {
            xml.push_str(&format!(
                "<users>{}</users>",
                xml_escape(self.attr("users").unwrap_or_default()),
            ));
        }
        if self.resource_type == "target" {
            let alive_test = self
                .attr("alive_test")
                .unwrap_or(AliveTest::ScanConfigDefault.as_target_name());
            xml.push_str(&format!(
                "<alive_tests>{}</alive_tests>",
                xml_escape(alive_test),
            ));
            if let Some(port_list_id) = self.attr("port_list_id") {
                xml.push_str(&format!(
                    "<port_list id=\"{}\"><name></name></port_list>",
                    xml_escape_attr(port_list_id),
                ));
            }
            if details {
                if let Some(port_range) = self.attr("port_range") {
                    xml.push_str(&format!(
                        "<port_range>{}</port_range>",
                        xml_escape(port_range),
                    ));
                }
            }
            if let Some(id) = self.attr("ssh_credential_id") {
                xml.push_str(&format!(
                    "<ssh_credential id=\"{}\"><name></name>",
                    xml_escape_attr(id),
                ));
                if let Some(port) = self.attr("ssh_credential_port") {
                    xml.push_str(&format!("<port>{}</port>", xml_escape(port)));
                }
                xml.push_str("</ssh_credential>");
            } else {
                xml.push_str("<ssh_credential id=\"\"><name></name><port></port></ssh_credential>");
            }
            if let Some(id) = self.attr("smb_credential_id") {
                xml.push_str(&format!(
                    "<smb_credential id=\"{}\"><name></name></smb_credential>",
                    xml_escape_attr(id),
                ));
            } else {
                xml.push_str("<smb_credential id=\"\"><name></name></smb_credential>");
            }
            for (attribute, element) in [
                ("ssh_elevate_credential_id", "ssh_elevate_credential"),
                ("krb5_credential_id", "krb5_credential"),
                ("esxi_credential_id", "esxi_credential"),
                ("snmp_credential_id", "snmp_credential"),
            ] {
                if let Some(id) = self.attr(attribute) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                } else {
                    xml.push_str(&format!("<{element} id=\"\"><name></name></{element}>"));
                }
            }
        }
        // Add type-specific attributes
        if self.resource_type == "alert" {
            for field in ["event", "condition", "method"] {
                if let Some(value) = self.attr(field) {
                    xml.push_str(&format!("<{field}>{}", xml_escape(value)));
                    let data_prefix = format!("{field}_data:");
                    for (key, data_value) in self.attrs.iter().filter_map(|(key, value)| {
                        key.strip_prefix(&data_prefix).map(|name| (name, value))
                    }) {
                        xml.push_str(&format!(
                            "<data>{}<name>{}</name></data>",
                            xml_escape(data_value),
                            xml_escape(key),
                        ));
                    }
                    xml.push_str(&format!("</{field}>"));
                }
            }
            if let Some(filter_id) = self.attr("filter_id") {
                xml.push_str(&format!(
                    "<filter id=\"{}\"><name></name></filter>",
                    xml_escape_attr(filter_id),
                ));
            }
        }
        if self.resource_type == "ticket" {
            for (field, element) in [
                ("assigned_to_id", "assigned_to"),
                ("result_id", "result"),
                ("task_id", "task"),
            ] {
                if let Some(id) = self.attr(field) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                }
            }
        }
        if self.resource_type == "tag" {
            if let Some(value) = self.attr("value") {
                xml.push_str(&format!("<value>{}</value>", xml_escape(value)));
            }
            if let Some(resource_type) = self.attr("tag_resource_type") {
                let resource_count = self
                    .attr("tag_resource_ids")
                    .unwrap_or_default()
                    .split(',')
                    .filter(|id| !id.is_empty())
                    .count();
                xml.push_str(&format!(
                    "<resources><type>{}</type><count><total>{resource_count}</total></count></resources>",
                    xml_escape(resource_type),
                ));
            }
            if let Some(active) = self.attr("active") {
                xml.push_str(&format!("<active>{}</active>", xml_escape(active)));
            }
        }
        if matches!(self.resource_type.as_str(), "note" | "override") {
            if let Some(nvt_oid) = self.attr("nvt_oid") {
                xml.push_str(&format!(
                    "<nvt oid=\"{}\"><name></name></nvt>",
                    xml_escape_attr(nvt_oid),
                ));
            }
            for attribute in ["hosts", "port", "severity", "new_severity"] {
                if let Some(value) = self.attr(attribute) {
                    xml.push_str(&format!("<{attribute}>{}</{attribute}>", xml_escape(value),));
                }
            }
            for (attribute, element) in [("task_id", "task"), ("result_id", "result")] {
                if let Some(id) = self.attr(attribute) {
                    xml.push_str(&format!(
                        "<{element} id=\"{}\"><name></name></{element}>",
                        xml_escape_attr(id),
                    ));
                }
            }
            if let Some(active) = self.attr("active") {
                let active = if active == "0" { "0" } else { "1" };
                xml.push_str(&format!("<active>{active}</active>"));
            }
        }
        for (k, v) in &self.attrs {
            if self.resource_type == "scanner" && k == "credential_id" {
                xml.push_str(&format!(
                    "<credential id=\"{}\"><name></name></credential>",
                    xml_escape_attr(v),
                ));
                continue;
            }
            if self.resource_type == "alert"
                && (matches!(k.as_str(), "event" | "condition" | "method" | "filter_id")
                    || k.starts_with("event_data:")
                    || k.starts_with("condition_data:")
                    || k.starts_with("method_data:"))
            {
                continue;
            }
            if self.resource_type == "ticket"
                && matches!(k.as_str(), "assigned_to_id" | "result_id" | "task_id")
            {
                continue;
            }
            if self.resource_type == "tag"
                && matches!(
                    k.as_str(),
                    "value"
                        | "tag_resource_type"
                        | "tag_resource_ids"
                        | "tag_resources_filter"
                        | "active"
                )
            {
                continue;
            }
            if matches!(self.resource_type.as_str(), "note" | "override")
                && matches!(
                    k.as_str(),
                    "nvt_oid"
                        | "hosts"
                        | "port"
                        | "severity"
                        | "new_severity"
                        | "task_id"
                        | "result_id"
                        | "active"
                )
            {
                continue;
            }
            if self.resource_type == "permission"
                && matches!(
                    k.as_str(),
                    "subject_id" | "subject_type" | "resource_id" | "resource_type"
                )
            {
                continue;
            }
            if self.resource_type == "user"
                && matches!(
                    k.as_str(),
                    "role_ids" | "group_ids" | "hosts" | "hosts_allow" | "auth_source"
                )
            {
                continue;
            }
            if matches!(self.resource_type.as_str(), "group" | "role")
                && matches!(k.as_str(), "users" | "special_full")
            {
                continue;
            }
            if self.resource_type == "target"
                && matches!(
                    k.as_str(),
                    "port_list_id"
                        | "alive_test"
                        | "port_range"
                        | "asset_hosts_filter"
                        | "ssh_credential_id"
                        | "ssh_credential_port"
                        | "smb_credential_id"
                        | "ssh_elevate_credential_id"
                        | "krb5_credential_id"
                        | "esxi_credential_id"
                        | "snmp_credential_id"
                )
            {
                continue;
            }
            if self.resource_type == "nvt"
                && matches!(
                    k.as_str(),
                    "oid" | "nvt_oid" | "config_id" | "preferences_config_id"
                )
            {
                continue;
            }
            if self.resource_type == "task"
                && (matches!(
                    k.as_str(),
                    "alterable"
                        | "alert_ids"
                        | "observers"
                        | "observer_group_ids"
                        | "target_id"
                        | "agent_group_id"
                        | "oci_image_target_id"
                        | "web_application_target_id"
                        | "config_id"
                        | "scanner_id"
                        | "schedule_id"
                        | "schedule_periods"
                        | "report_id"
                ) || k.starts_with("task_preference:"))
            {
                continue;
            }
            xml.push_str(&format!("<{k}>{}</{k}>", xml_escape(v)));
        }
        xml.push_str(&format!("</{}>", self.resource_type));
        xml
    }

    /// Generate the canonical gvmd representation for an integration configuration.
    pub(crate) fn to_integration_config_xml(&self, details: bool) -> String {
        let mut xml = format!(
            "<integration_config id=\"{id}\">\
             <owner><name>admin</name></owner>\
             <name>{name}</name>\
             <comment>{comment}</comment>\
             <creation_time>{ct}</creation_time>\
             <modification_time>{mt}</modification_time>\
             <writable>1</writable>\
             <in_use>0</in_use>\
             <permissions><permission><name>Everything</name></permission></permissions>",
            id = self.id,
            name = xml_escape(&self.name),
            comment = xml_escape(&self.comment),
            ct = self.creation_time,
            mt = self.modification_time,
        );
        if details {
            xml.push_str(&format!(
                "<service><url>{service_url}</url></service>\
                 <oidc><url>{oidc_url}</url><client><id>{client_id}</id></client></oidc>",
                service_url = xml_escape(self.attr("service_url").unwrap_or_default()),
                oidc_url = xml_escape(self.attr("oidc_provider_url").unwrap_or_default()),
                client_id = xml_escape(self.attr("oidc_provider_client_id").unwrap_or_default()),
            ));
        }
        xml.push_str("</integration_config>");
        xml
    }
}

fn task_report_reference_xml(field: &str, report: &Resource, results: &[&Resource]) -> String {
    let timestamp = report.attr("timestamp").unwrap_or(&report.creation_time);
    let scan_start = report.attr("scan_start").unwrap_or(&report.creation_time);
    let scan_end = report.attr("scan_end").unwrap_or_else(|| {
        if report.attr("status") == Some(TaskStatus::Done.as_str()) {
            &report.modification_time
        } else {
            ""
        }
    });
    let mut xml = format!(
        "<{field}><report id=\"{}\"><timestamp>{}</timestamp>\
         <scan_start>{}</scan_start><scan_end>{}</scan_end>",
        xml_escape_attr(&report.id.to_string()),
        xml_escape(timestamp),
        xml_escape(scan_start),
        xml_escape(scan_end),
    );
    if field == "last_report" {
        if report.attr("usage_type") == Some("audit") {
            let counts = AuditComplianceCounts::from_results(results.iter().copied());
            xml.push_str(&format!(
                "<compliance_count><yes>{}</yes><no>{}</no><incomplete>{}</incomplete>\
                 </compliance_count>",
                counts.yes, counts.no, counts.incomplete,
            ));
        } else {
            let counts = ScanReportResultCounts::from_results(results.iter().copied());
            xml.push_str(&format!(
                "<result_count><critical>{critical}</critical>\
                 <hole deprecated=\"1\">{high}</hole><high>{high}</high>\
                 <info deprecated=\"1\">{low}</info><low>{low}</low><log>{log}</log>\
                 <warning deprecated=\"1\">{medium}</warning><medium>{medium}</medium>\
                 <false_positive>{false_positive}</false_positive></result_count>\
                 <severity>{severity:.1}</severity>",
                critical = counts.critical,
                high = counts.high,
                low = counts.low,
                log = counts.log,
                medium = counts.medium,
                false_positive = counts.false_positive,
                severity = counts.max_severity,
            ));
        }
    }
    xml.push_str(&format!("</report></{field}>"));
    xml
}

/// Thread-safe resource store.
#[derive(Clone)]
pub struct ResourceStore {
    inner: Arc<RwLock<StoreInner>>,
}

impl std::fmt::Debug for ResourceStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let inner = self.inner.read().map_err(|_| std::fmt::Error)?;
        formatter
            .debug_struct("ResourceStore")
            .field("resource_count", &inner.resources.len())
            .field(
                "authenticated_session_count",
                &inner.authenticated_sessions.len(),
            )
            .field("asset_input_profile", &inner.asset_input_profile)
            .field("system_administration", &inner.system_administration)
            .finish()
    }
}

#[derive(Debug)]
struct StoreInner {
    resources: HashMap<Uuid, Resource>,
    insertion_order: HashMap<Uuid, u64>,
    next_insertion_order: u64,
    /// Stateful asset request parsing profile.
    asset_input_profile: AssetInputProfile,
    /// Authenticated session principals.
    authenticated_sessions: HashMap<u64, String>,
    /// Configured credentials.
    username: String,
    password: String,
    system_administration: SystemAdministrationState,
    discovery: DiscoverySnapshot,
}

#[derive(Clone, Default)]
struct SystemAdministrationState {
    auth_groups: BTreeMap<String, BTreeMap<String, String>>,
    license_file: Option<String>,
    wizard_runs: Vec<WizardRun>,
}

impl std::fmt::Debug for SystemAdministrationState {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SystemAdministrationState")
            .field("auth_group_count", &self.auth_groups.len())
            .field("license_installed", &self.license_file.is_some())
            .field("wizard_run_count", &self.wizard_runs.len())
            .finish()
    }
}

#[derive(Clone)]
struct WizardRun {
    name: String,
    mode: Option<String>,
    read_only: Option<bool>,
    params: Vec<(String, String)>,
}

impl std::fmt::Debug for WizardRun {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WizardRun")
            .field("name", &self.name)
            .field("mode", &self.mode)
            .field("read_only", &self.read_only)
            .field("parameter_count", &self.params.len())
            .finish()
    }
}

fn default_resources() -> HashMap<Uuid, Resource> {
    let mut resources = HashMap::new();

    let mut timezone = Resource::with_id(
        "setting",
        "timezone",
        Uuid::parse_str("00000000-0000-0000-0000-000000000001").expect("valid uuid"),
    );
    timezone.comment = "User timezone".to_string();
    timezone.set_attr("value", "UTC");
    resources.insert(timezone.id, timezone);

    let mut rows_per_page = Resource::with_id(
        "setting",
        "rows_per_page",
        Uuid::parse_str("00000000-0000-0000-0000-000000000002").expect("valid uuid"),
    );
    rows_per_page.comment = "Default rows per page".to_string();
    rows_per_page.set_attr("value", "100");
    resources.insert(rows_per_page.id, rows_per_page);

    let mut integration_config = Resource::with_id(
        "integration_config",
        "Default Integration Config",
        Uuid::parse_str("00000000-0000-0000-0000-000000000100").expect("valid uuid"),
    );
    integration_config.comment = "Mock integration config".to_string();
    integration_config.set_attr("service_url", "https://service.example.invalid");
    integration_config.set_attr("service_cacert", "MOCK-CA-CERT");
    integration_config.set_attr("oidc_provider_url", "https://oidc.example.invalid");
    integration_config.set_attr("oidc_provider_client_id", "mock-client-id");
    integration_config.set_attr("oidc_provider_client_secret", "mock-client-secret");
    resources.insert(integration_config.id, integration_config);

    let mut config = Resource::with_id("config", "Full and fast", DEFAULT_CONFIG_ID);
    config.comment = "Mock default scan config".to_string();
    config.set_attr("usage_type", "scan");
    resources.insert(config.id, config);

    let mut scan_config = Resource::with_id("config", "Discovery scan", SECOND_SCAN_CONFIG_ID);
    scan_config.comment = "Second seeded scan configuration".to_string();
    scan_config.set_attr("usage_type", "scan");
    scan_config.set_attr("predefined", "0");
    resources.insert(scan_config.id, scan_config);

    let mut first_policy = Resource::with_id("config", "Baseline policy", FIRST_POLICY_ID);
    first_policy.comment = "Seeded policy with selectors".to_string();
    first_policy.set_attr("usage_type", "policy");
    first_policy.set_attr("predefined", "0");
    resources.insert(first_policy.id, first_policy);

    let mut second_policy = Resource::with_id("config", "Empty policy", SECOND_POLICY_ID);
    second_policy.comment = "Seeded empty policy".to_string();
    second_policy.set_attr("usage_type", "policy");
    second_policy.set_attr("predefined", "0");
    resources.insert(second_policy.id, second_policy);

    let mut predefined = Resource::with_id("config", "Predefined scan", PREDEFINED_CONFIG_ID);
    predefined.comment = "Read-only seeded configuration".to_string();
    predefined.set_attr("usage_type", "scan");
    predefined.set_attr("predefined", "1");
    resources.insert(predefined.id, predefined);

    let mut config_filter = Resource::with_id(
        "filter",
        "Mock configuration filter",
        CONFIG_SAVED_FILTER_ID,
    );
    config_filter.set_attr("term", "usage_type=policy sort=name rows=1");
    resources.insert(config_filter.id, config_filter);

    let mut scanner = Resource::with_id("scanner", "OpenVAS Default", DEFAULT_SCANNER_ID);
    scanner.comment = "Mock default scanner".to_string();
    scanner.set_attr("type", "OpenVAS");
    resources.insert(scanner.id, scanner);

    let mut container_scanner = Resource::with_id(
        "scanner",
        "Container Image Default",
        DEFAULT_CONTAINER_SCANNER_ID,
    );
    container_scanner.set_attr("type", "10");
    resources.insert(container_scanner.id, container_scanner);

    let mut web_scanner =
        Resource::with_id("scanner", "Web Application Default", DEFAULT_WEB_SCANNER_ID);
    web_scanner.set_attr("type", "11");
    resources.insert(web_scanner.id, web_scanner);

    let mut configurable_format = Resource::with_id(
        "report_format",
        "Mock configurable format",
        CONFIGURABLE_REPORT_FORMAT_ID,
    );
    configurable_format.set_attr("configurable", "1");
    configurable_format.set_attr("report_config_param:Label", "string:12");
    configurable_format.set_attr("report_config_default:Label", "Default label");
    configurable_format.set_attr("report_config_param:Graph Type", "selection:bar,line");
    configurable_format.set_attr("report_config_default:Graph Type", "bar");
    configurable_format.set_attr("content_type", "text/plain");
    configurable_format.set_attr("extension", "txt");
    configurable_format.set_attr("summary", "Mock configurable report format");
    configurable_format.set_attr("active", "1");
    configurable_format.set_attr("predefined", "0");
    configurable_format.set_attr("trust", "unknown");
    configurable_format.set_attr("report_type", "all");
    configurable_format.set_attr("report_format_param_type:Label", "string");
    configurable_format.set_attr("report_format_param_value:Label", "Default label");
    configurable_format.set_attr("report_format_param_default:Label", "Default label");
    configurable_format.set_attr("report_format_param_max:Label", "12");
    configurable_format.set_attr("report_format_param_type:Graph Type", "selection");
    configurable_format.set_attr("report_format_param_value:Graph Type", "bar");
    configurable_format.set_attr("report_format_param_default:Graph Type", "bar");
    configurable_format.set_attr("report_format_param_option:Graph Type\u{1f}0", "bar");
    configurable_format.set_attr("report_format_param_option:Graph Type\u{1f}1", "line");
    configurable_format.set_attr("report_format_file:template.txt", "bW9jayB0ZW1wbGF0ZQ==");
    resources.insert(configurable_format.id, configurable_format);

    let mut nonconfigurable_format = Resource::with_id(
        "report_format",
        "Mock nonconfigurable format",
        NONCONFIGURABLE_REPORT_FORMAT_ID,
    );
    nonconfigurable_format.set_attr("configurable", "0");
    nonconfigurable_format.set_attr("content_type", "application/pdf");
    nonconfigurable_format.set_attr("extension", "pdf");
    nonconfigurable_format.set_attr("summary", "Mock predefined report format");
    nonconfigurable_format.set_attr("active", "1");
    nonconfigurable_format.set_attr("predefined", "1");
    nonconfigurable_format.set_attr("trust", "yes");
    nonconfigurable_format.set_attr("report_type", "all");
    resources.insert(nonconfigurable_format.id, nonconfigurable_format);

    let mut report_config_filter = Resource::with_id(
        "filter",
        "Mock report configuration filter",
        REPORT_CONFIG_SAVED_FILTER_ID,
    );
    report_config_filter.set_attr("term", "name~Saved sort=name rows=1");
    resources.insert(report_config_filter.id, report_config_filter);

    let mut report_format_filter = Resource::with_id(
        "filter",
        "Mock report format filter",
        REPORT_FORMAT_SAVED_FILTER_ID,
    );
    report_format_filter.set_attr("term", "name~Mock sort=name rows=1");
    resources.insert(report_format_filter.id, report_format_filter);

    resources
}

fn active_typed_resource<'a>(
    inner: &'a StoreInner,
    id: &Uuid,
    resource_type: &'static str,
) -> Result<&'a Resource, StoreError> {
    inner
        .resources
        .get(id)
        .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
        .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))
}

fn unique_clone_name(inner: &StoreInner, resource_type: &str, original_name: &str) -> String {
    let mut number = 1_u64;
    loop {
        let candidate = format!("{original_name} Clone {number}");
        let exists = inner.resources.values().any(|resource| {
            !resource.trashed
                && resource.resource_type == resource_type
                && resource.name == candidate
        });
        if !exists {
            return candidate;
        }
        number += 1;
    }
}

fn active_name_exists(
    inner: &StoreInner,
    resource_type: &str,
    name: &str,
    except: Option<&Uuid>,
) -> bool {
    inner.resources.values().any(|resource| {
        !resource.trashed
            && resource.resource_type == resource_type
            && resource.name == name
            && except != Some(&resource.id)
    })
}

fn config_preference_type(name: &str) -> Option<&str> {
    let mut parts = name.splitn(4, ':');
    let _oid = parts.next()?;
    let _id = parts.next()?;
    parts.next()
}

fn add_config_family_order(config: &mut Resource, family: &str) {
    let mut order = config
        .attr("config_family_order")
        .map(|value| {
            value
                .split('\u{1f}')
                .filter(|name| !name.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if !order.iter().any(|name| name == family) {
        order.push(family.to_string());
    }
    config.set_attr("config_family_order", &order.join("\u{1f}"));
}

fn tls_visible_to(resource: &Resource, principal: &str) -> bool {
    resource.attr("owner") == Some(principal)
        || resource
            .attr("visible_to")
            .is_some_and(|principals| principals.split(',').any(|value| value == principal))
}

fn tls_fingerprint_collision(inner: &StoreInner, owner: &str, candidate: &Resource) -> bool {
    let sha256 = candidate.attr("sha256_fingerprint").unwrap_or_default();
    let md5 = candidate.attr("md5_fingerprint").unwrap_or_default();
    inner.resources.values().any(|resource| {
        !resource.trashed
            && resource.resource_type == "tls_certificate"
            && resource.attr("owner") == Some(owner)
            && ((!sha256.is_empty() && resource.attr("sha256_fingerprint") == Some(sha256))
                || (!md5.is_empty() && resource.attr("md5_fingerprint") == Some(md5)))
    })
}

fn validate_report_config_updates(
    report_format: &Resource,
    params: &[ReportConfigParamUpdate],
    reset_removes: bool,
) -> Result<Vec<(String, Option<String>)>, StoreError> {
    let mut updates = Vec::new();
    for param in params {
        match param {
            ReportConfigParamUpdate::UseDefault { name } => {
                if reset_removes {
                    updates.push((normalize_report_config_param_name(name), None));
                }
            }
            ReportConfigParamUpdate::Value { name, value } => {
                let name = normalize_report_config_param_name(name);
                let definition = report_format
                    .attr(&format!("report_config_param:{name}"))
                    .ok_or(StoreError::InvalidArgument(
                        "Unknown report configuration parameter",
                    ))?;
                validate_seeded_report_config_value(definition, value)?;
                updates.push((name, Some(value.clone())));
            }
        }
    }
    Ok(updates)
}

fn normalize_report_config_param_name(name: &str) -> String {
    name.trim_matches(|character: char| character.is_ascii_whitespace())
        .to_string()
}

fn validate_seeded_report_config_value(definition: &str, value: &str) -> Result<(), StoreError> {
    if let Some(maximum) = definition.strip_prefix("string:") {
        let maximum = maximum.parse::<usize>().unwrap_or(usize::MAX);
        if value.len() <= maximum {
            return Ok(());
        }
    } else if let Some(choices) = definition.strip_prefix("selection:") {
        if choices.split(',').any(|choice| choice == value) {
            return Ok(());
        }
    }
    Err(StoreError::InvalidArgument(
        "Invalid report configuration parameter value",
    ))
}

pub(crate) fn validate_seeded_report_format_value(
    report_format: &Resource,
    name: &str,
    value: &str,
) -> Result<(), StoreError> {
    let parameter_type = report_format
        .attr(&format!("report_format_param_type:{name}"))
        .ok_or(StoreError::InvalidArgument(
            "Unknown report format parameter",
        ))?;
    let minimum = report_format
        .attr(&format!("report_format_param_min:{name}"))
        .and_then(|value| value.parse::<i64>().ok());
    let maximum = report_format
        .attr(&format!("report_format_param_max:{name}"))
        .and_then(|value| value.parse::<i64>().ok());

    let valid = match parameter_type {
        "string" => {
            let length = value.len() as i64;
            minimum.is_none_or(|minimum| length >= minimum)
                && maximum.is_none_or(|maximum| length <= maximum)
        }
        "integer" => value.parse::<i64>().is_ok_and(|value| {
            minimum.is_none_or(|minimum| value >= minimum)
                && maximum.is_none_or(|maximum| value <= maximum)
        }),
        "selection" => report_format.attrs.iter().any(|(key, option)| {
            key.starts_with(&format!("report_format_param_option:{name}\u{1f}")) && option == value
        }),
        "multi_selection" => value.starts_with('[') && value.ends_with(']'),
        "report_format_list" => value
            .split(',')
            .filter(|item| !item.is_empty())
            .all(|item| Uuid::parse_str(item).is_ok()),
        // The pinned validator has no separate boolean validation branch.
        "boolean" => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(StoreError::InvalidArgument(
            "Invalid report format parameter value",
        ))
    }
}

fn validate_task_reference(
    inner: &StoreInner,
    id: &Uuid,
    resource_type: &'static str,
) -> Result<(), StoreError> {
    active_typed_resource(inner, id, resource_type).map(|_| ())
}

fn scanner_has_type(scanner: &Resource, accepted: &[&str]) -> bool {
    scanner
        .attr("type")
        .is_some_and(|scanner_type| accepted.contains(&scanner_type))
}

fn validate_openvas_scanner(
    inner: &StoreInner,
    id: &Uuid,
    message: &'static str,
) -> Result<(), StoreError> {
    let scanner = active_typed_resource(inner, id, "scanner")?;
    if scanner_has_type(scanner, &["2", "OpenVAS"]) {
        Ok(())
    } else {
        Err(StoreError::InvalidArgument(message))
    }
}

fn validate_task_attributes(inner: &StoreInner, task: &Resource) -> Result<(), StoreError> {
    for (attribute, resource_type) in [("alert_ids", "alert"), ("observer_group_ids", "group")] {
        for id in task
            .attr(attribute)
            .unwrap_or_default()
            .split(',')
            .filter(|id| !id.is_empty())
        {
            // Older mock fixtures use readable non-UUID identifiers. Preserve
            // those fixtures while enforcing real gvmd relationships whenever
            // the command carries a production-shaped UUID.
            if let Ok(id) = Uuid::parse_str(id) {
                validate_task_reference(inner, &id, resource_type)?;
            }
        }
    }
    if task
        .attr("alterable")
        .is_some_and(|value| !matches!(value, "0" | "1"))
    {
        return Err(StoreError::InvalidArgument("Invalid task alterable value"));
    }
    for (key, value) in task
        .attrs
        .iter()
        .filter(|(key, _)| key.starts_with("task_preference:"))
    {
        let name = key.trim_start_matches("task_preference:");
        if name == "auto_delete" && !matches!(value.as_str(), "keep" | "no") {
            return Err(StoreError::InvalidArgument("Invalid auto_delete value"));
        }
        if name == "auto_delete_data"
            && value
                .parse::<u32>()
                .map_or(true, |value| !(2..=1200).contains(&value))
        {
            return Err(StoreError::InvalidArgument(
                "Auto Delete count out of range",
            ));
        }
        let container = task.attr("oci_image_target_id").is_some();
        let web = task.attr("web_application_target_id").is_some();
        if name == "in_assets" && (container || web) {
            return Err(StoreError::InvalidArgument(
                "in_assets cannot be set for specialized task scanners",
            ));
        }
        if web && name == "scan_mode" && !matches!(value.as_str(), "active" | "safe") {
            return Err(StoreError::InvalidArgument("Invalid web scan_mode value"));
        }
        if web
            && name == "ajax_spider_timeout"
            && value.parse::<i64>().map_or(true, |timeout| timeout < 0)
        {
            return Err(StoreError::InvalidArgument(
                "Invalid web ajax_spider_timeout value",
            ));
        }
    }

    let scanner = task
        .attr("scanner_id")
        .and_then(|id| Uuid::parse_str(id).ok())
        .and_then(|id| inner.resources.get(&id));
    if let Some(group_id) = task
        .attr("agent_group_id")
        .and_then(|id| Uuid::parse_str(id).ok())
    {
        let group = active_typed_resource(inner, &group_id, "agent_group")?;
        let group_scanner = group
            .attr("scanner_id")
            .and_then(|id| Uuid::parse_str(id).ok())
            .unwrap_or(DEFAULT_SCANNER_ID);
        if task.attr("scanner_id") != Some(group_scanner.to_string().as_str()) {
            return Err(StoreError::InvalidArgument(
                "Scanner ID does not match agent group's scanner",
            ));
        }
    } else if task.attr("oci_image_target_id").is_some() {
        if scanner.is_none_or(|scanner| !scanner_has_type(scanner, &["10"])) {
            return Err(StoreError::InvalidArgument(
                "OCI image target requires a Container Image scanner",
            ));
        }
    } else if task.attr("web_application_target_id").is_some() {
        if scanner.is_none_or(|scanner| !scanner_has_type(scanner, &["11"])) {
            return Err(StoreError::InvalidArgument(
                "Web application target requires a Web Application scanner",
            ));
        }
    } else if task.attr("import_task") != Some("1")
        && scanner.is_some_and(|scanner| scanner_has_type(scanner, &["7", "9", "10", "11"]))
    {
        return Err(StoreError::InvalidArgument(
            "Target and scanner types mismatch",
        ));
    }
    Ok(())
}

fn stored_task_reference(
    task: &Resource,
    key: &'static str,
    resource_type: &'static str,
) -> Result<Uuid, StoreError> {
    task.attr(key)
        .and_then(|value| Uuid::parse_str(value).ok())
        .ok_or(StoreError::Inconsistent(resource_type))
}

fn validate_stored_task_references(inner: &StoreInner, task: &Resource) -> Result<(), StoreError> {
    if let Some(schedule_id) = task.attr("schedule_id") {
        let schedule_id =
            Uuid::parse_str(schedule_id).map_err(|_| StoreError::Inconsistent("schedule"))?;
        validate_task_reference(inner, &schedule_id, "schedule")?;
    }
    if task.attr("import_task") == Some("1") {
        return Ok(());
    }

    let specialized: Vec<_> = [
        ("agent_group_id", "agent_group"),
        ("oci_image_target_id", "oci_image_target"),
        ("web_application_target_id", "web_application_target"),
    ]
    .into_iter()
    .filter(|(key, _)| task.attr(key).is_some())
    .collect();
    if specialized.len() > 1 {
        return Err(StoreError::Inconsistent("task target"));
    }
    let mut required = if let Some(reference) = specialized.first() {
        vec![*reference, ("scanner_id", "scanner")]
    } else {
        vec![
            ("target_id", "target"),
            ("config_id", "config"),
            ("scanner_id", "scanner"),
        ]
    };
    if !specialized.is_empty() && task.attr("config_id").is_some() {
        required.push(("config_id", "config"));
    }
    for (key, resource_type) in required {
        let id = stored_task_reference(task, key, resource_type)?;
        validate_task_reference(inner, &id, resource_type)?;
    }
    Ok(())
}

fn task_is_active(task: &Resource) -> bool {
    matches!(
        task.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Processing"
        )
    )
}

fn task_has_current_report(task: &Resource) -> bool {
    matches!(
        task.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Stopped"
                | "Interrupted"
                | "Processing"
        )
    )
}

fn report_is_current(report: &Resource) -> bool {
    matches!(
        report.attr("status"),
        Some(
            "Requested"
                | "Queued"
                | "Running"
                | "Stop Requested"
                | "Delete Requested"
                | "Ultimate Delete Requested"
                | "Stopped"
                | "Interrupted"
                | "Processing"
        )
    )
}

fn insert_resource(inner: &mut StoreInner, resource: Resource) -> Uuid {
    let id = resource.id;
    inner.next_insertion_order = inner.next_insertion_order.saturating_add(1);
    inner.insertion_order.insert(id, inner.next_insertion_order);
    inner.resources.insert(id, resource);
    id
}

fn remove_resource(inner: &mut StoreInner, id: &Uuid) -> Option<Resource> {
    inner.insertion_order.remove(id);
    inner.resources.remove(id)
}

fn insertion_order(inner: &StoreInner, report: &Resource) -> u64 {
    inner.insertion_order.get(&report.id).copied().unwrap_or(0)
}

fn report_creation_instant(report: &Resource) -> i64 {
    DateTime::parse_from_rfc3339(&report.creation_time)
        .map(|timestamp| timestamp.timestamp())
        .unwrap_or(i64::MIN)
}

fn latest_current_report<'a>(
    inner: &StoreInner,
    reports: impl Iterator<Item = &'a Resource>,
) -> Option<&'a Resource> {
    reports.max_by_key(|report| insertion_order(inner, report))
}

fn latest_completed_report<'a>(
    inner: &StoreInner,
    reports: impl Iterator<Item = &'a Resource>,
) -> Option<&'a Resource> {
    reports.max_by_key(|report| {
        (
            report_creation_instant(report),
            insertion_order(inner, report),
        )
    })
}

fn resolve_task_reports(inner: &StoreInner, task: &Resource) -> (Option<Uuid>, Option<Uuid>) {
    let task_id = task.id.to_string();
    let linked = || {
        inner.resources.values().filter(|report| {
            report.trashed == task.trashed
                && report.resource_type == "report"
                && report.attr("task_id") == Some(task_id.as_str())
        })
    };

    let current = if task_has_current_report(task) {
        task.attr("report_id")
            .and_then(|id| Uuid::parse_str(id).ok())
            .and_then(|id| inner.resources.get(&id))
            .filter(|report| {
                report.trashed == task.trashed
                    && report.resource_type == "report"
                    && report.attr("task_id") == Some(task_id.as_str())
                    && report_is_current(report)
            })
            .or_else(|| {
                latest_current_report(inner, linked().filter(|report| report_is_current(report)))
            })
            .map(|report| report.id)
    } else {
        None
    };
    let last = latest_completed_report(
        inner,
        linked().filter(|report| report.attr("status") == Some("Done")),
    )
    .map(|report| report.id);
    (current, last)
}

fn resolve_current_report_id(inner: &StoreInner, task: &Resource) -> Result<Uuid, StoreError> {
    resolve_task_reports(inner, task)
        .0
        .ok_or(StoreError::Inconsistent("task report"))
}

impl ResourceStore {
    const AUTH_TOKEN: &'static str = "mock-token";

    /// Create a new empty store with default credentials.
    pub fn new() -> Self {
        Self::with_credentials("admin", "admin")
    }

    /// Create a store with specific credentials.
    pub fn with_credentials(username: &str, password: &str) -> Self {
        let resources = default_resources();
        let insertion_order = resources
            .keys()
            .copied()
            .enumerate()
            .map(|(index, id)| (id, index as u64 + 1))
            .collect();
        let next_insertion_order = resources.len() as u64;
        Self {
            inner: Arc::new(RwLock::new(StoreInner {
                resources,
                insertion_order,
                next_insertion_order,
                asset_input_profile: AssetInputProfile::GvmdStrict,
                authenticated_sessions: HashMap::new(),
                username: username.to_string(),
                password: password.to_string(),
                system_administration: SystemAdministrationState::default(),
                discovery: default_discovery(),
            })),
        }
    }

    /// Add or replace a mock NVT by its textual OID.
    pub fn seed_discovery_nvt(&self, nvt: DiscoveryNvt) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .nvts
            .insert(nvt.oid.clone(), nvt);
    }

    /// Add a non-NVT scanner preference with an empty OID component.
    pub fn seed_discovery_scanner_preference(&self, preference: DiscoveryPreference) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .scanner_preferences
            .push(preference);
    }

    /// Add or replace a mock SecInfo record.
    pub fn seed_discovery_secinfo(&self, info: DiscoverySecInfo) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner
            .discovery
            .secinfo
            .retain(|entry| entry.info_type != info.info_type || entry.id != info.id);
        inner.discovery.secinfo.push(info);
    }

    /// Add or replace an observed vulnerability summary.
    pub fn seed_discovery_vulnerability(&self, vulnerability: DiscoveryVulnerability) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner
            .discovery
            .vulnerabilities
            .retain(|entry| entry.id != vulnerability.id);
        inner.discovery.vulnerabilities.push(vulnerability);
    }

    /// Set the NVT membership of a scan configuration.
    pub fn seed_discovery_config_nvts(
        &self,
        config_id: impl Into<String>,
        nvt_oids: impl IntoIterator<Item = String>,
    ) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .config_nvts
            .insert(config_id.into(), nvt_oids.into_iter().collect());
    }

    /// Set one scan-config preference override by its full stored key.
    pub fn seed_discovery_config_preference(
        &self,
        config_id: impl Into<String>,
        key: impl Into<String>,
        value: impl Into<String>,
    ) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .config_preferences
            .entry(config_id.into())
            .or_default()
            .insert(key.into(), value.into());
    }

    /// Seed a saved filter referenced by `filt_id`.
    pub fn seed_discovery_filter(&self, id: impl Into<String>, term: impl Into<String>) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .saved_filters
            .insert(id.into(), term.into());
    }

    /// Set or clear the explicitly modeled user-default discovery filter (`filt_id=-2`).
    pub fn set_discovery_user_default_filter(&self, term: Option<String>) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .user_default_filter = term;
    }

    /// Configure discovery database/feed availability for negative-path tests.
    pub fn set_discovery_availability(&self, nvt_feed: bool, scap: bool, cert: bool) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.discovery.nvt_feed_available = nvt_feed;
        inner.discovery.scap_available = scap;
        inner.discovery.cert_available = cert;
    }

    /// Configure whether the authenticated principal may read SecInfo.
    pub fn set_secinfo_permitted(&self, permitted: bool) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .discovery
            .secinfo_permitted = permitted;
    }

    pub(crate) fn discovery_snapshot(&self) -> DiscoverySnapshot {
        let inner = self.inner.read().expect("store lock poisoned");
        let mut discovery = inner.discovery.clone();
        let seeded_nvts: Vec<_> = inner
            .resources
            .values()
            .filter(|resource| resource.resource_type == "nvt" && !resource.trashed)
            .collect();

        // Keep the long-standing generic `Resource::new("nvt", ...)` seed path
        // useful for MCP-style tests.  An explicitly seeded generic catalogue
        // replaces the built-in discovery catalogue, just as it did before the
        // bounded NVT handler was introduced.
        if !seeded_nvts.is_empty() {
            discovery.nvts = seeded_nvts
                .into_iter()
                .map(|resource| {
                    let oid = resource
                        .attr("oid")
                        .or_else(|| resource.attr("nvt_oid"))
                        .map_or_else(|| resource.id.to_string(), str::to_string);
                    let severity = resource.attr("severity").unwrap_or("0.0").to_string();
                    let nvt = DiscoveryNvt {
                        oid: oid.clone(),
                        name: resource.name.clone(),
                        family: resource.attr("family").unwrap_or_default().to_string(),
                        cvss_base: resource
                            .attr("cvss_base")
                            .or_else(|| resource.attr("severity"))
                            .and_then(|value| value.parse().ok())
                            .unwrap_or(0.0),
                        severity,
                        tags: resource.attr("tags").unwrap_or_default().to_string(),
                        solution_type: resource
                            .attr("solution_type")
                            .unwrap_or("Unknown")
                            .to_string(),
                        timeout: resource
                            .attr("timeout")
                            .and_then(|value| value.parse().ok())
                            .unwrap_or_default(),
                        preferences: Vec::new(),
                    };
                    (oid, nvt)
                })
                .collect();
        }
        discovery
    }

    /// Authenticate a session. Returns true if credentials are valid.
    pub fn authenticate(&self, session_id: u64, username: &str, password: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if inner.username == username && inner.password == password {
            inner
                .authenticated_sessions
                .insert(session_id, username.to_string());
            true
        } else {
            false
        }
    }

    /// Authenticate a session with the deterministic token issued by the mock.
    pub fn authenticate_token(&self, session_id: u64, token: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if token == Self::AUTH_TOKEN {
            let username = inner.username.clone();
            inner.authenticated_sessions.insert(session_id, username);
            true
        } else {
            false
        }
    }

    /// Return the deterministic token used by stateful authentication.
    #[must_use]
    pub fn authentication_token() -> &'static str {
        Self::AUTH_TOKEN
    }

    /// Check if a session is authenticated.
    pub fn is_authenticated(&self, session_id: u64) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.authenticated_sessions.contains_key(&session_id)
    }

    /// Return the principal recorded for an authenticated session.
    pub(crate) fn authenticated_principal(&self, session_id: u64) -> Option<String> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.authenticated_sessions.get(&session_id).cloned()
    }

    pub(crate) fn apply_auth_groups(&self, groups: BTreeMap<String, BTreeMap<String, String>>) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        for (name, settings) in groups {
            if settings.is_empty() {
                continue;
            }
            let group = inner
                .system_administration
                .auth_groups
                .entry(name)
                .or_default();
            group.extend(settings);
        }
    }

    pub(crate) fn auth_groups(&self) -> BTreeMap<String, BTreeMap<String, String>> {
        self.inner
            .read()
            .expect("store lock poisoned")
            .system_administration
            .auth_groups
            .clone()
    }

    pub(crate) fn replace_license(&self, file: String) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .system_administration
            .license_file = (!file.is_empty()).then_some(file);
    }

    pub(crate) fn license_installed(&self) -> bool {
        self.inner
            .read()
            .expect("store lock poisoned")
            .system_administration
            .license_file
            .is_some()
    }

    pub(crate) fn record_wizard_run(
        &self,
        name: String,
        mode: Option<String>,
        read_only: Option<bool>,
        params: Vec<(String, String)>,
    ) {
        self.inner
            .write()
            .expect("store lock poisoned")
            .system_administration
            .wizard_runs
            .push(WizardRun {
                name,
                mode,
                read_only,
                params,
            });
    }

    /// Returns the number of wizard executions accepted by the stateful store.
    ///
    /// Parameter values remain deliberately unavailable because they may contain
    /// confidential administration data.
    pub fn wizard_run_count(&self) -> usize {
        self.inner
            .read()
            .expect("store lock poisoned")
            .system_administration
            .wizard_runs
            .len()
    }

    pub(crate) fn modify_setting_by_name(&self, name: &str, value: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if name == "Password" {
            value.clone_into(&mut inner.password);
            return true;
        }
        if name != "Timezone" {
            return false;
        }
        let Some(setting) = inner.resources.values_mut().find(|resource| {
            !resource.trashed
                && resource.resource_type == "setting"
                && resource.name.eq_ignore_ascii_case("timezone")
        }) else {
            return false;
        };
        setting.set_attr("value", value);
        setting.modification_time = now_iso();
        true
    }

    /// Set the asset request parsing profile before the server starts.
    pub(crate) fn set_asset_input_profile(&self, profile: AssetInputProfile) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        inner.asset_input_profile = profile;
    }

    /// Return the configured asset request parsing profile.
    pub(crate) fn asset_input_profile(&self) -> AssetInputProfile {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.asset_input_profile
    }

    /// Check whether the provided credentials match the configured SSH credentials.
    #[cfg(feature = "ssh")]
    pub(crate) fn credentials_match(&self, username: &str, password: &str) -> bool {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.username == username && inner.password == password
    }

    /// Create a resource. Returns the generated UUID.
    pub fn create(&self, mut resource: Resource) -> Uuid {
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        insert_resource(&mut inner, resource)
    }

    pub(crate) fn create_tls_certificate(
        &self,
        mut resource: Resource,
        owner: &str,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if tls_fingerprint_collision(&inner, owner, &resource) {
            return Err(StoreError::InvalidArgument(
                "TLS certificate exists already",
            ));
        }
        resource.set_attr("owner", owner);
        resource.modification_time = now_iso();
        Ok(insert_resource(&mut inner, resource))
    }

    pub(crate) fn clone_tls_certificate(
        &self,
        id: &Uuid,
        owner: &str,
        requested_name: Option<&str>,
        requested_comment: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let source = inner
            .resources
            .get(id)
            .filter(|resource| {
                !resource.trashed
                    && resource.resource_type == "tls_certificate"
                    && tls_visible_to(resource, owner)
            })
            .cloned()
            .ok_or_else(|| StoreError::NotFound("TLS certificate".to_string()))?;
        if tls_fingerprint_collision(&inner, owner, &source) {
            return Err(StoreError::InvalidArgument(
                "TLS certificate exists already",
            ));
        }

        if let Some(name) = requested_name.filter(|name| !name.is_empty()) {
            if inner.resources.values().any(|resource| {
                !resource.trashed
                    && resource.resource_type == "tls_certificate"
                    && resource.attr("owner") == Some(owner)
                    && resource.name == name
            }) {
                return Err(StoreError::InvalidArgument(
                    "TLS certificate name exists already",
                ));
            }
        }

        let mut copy = source;
        copy.id = Uuid::new_v4();
        if let Some(name) = requested_name.filter(|name| !name.is_empty()) {
            copy.name = name.to_string();
        }
        if let Some(comment) = requested_comment.filter(|comment| !comment.is_empty()) {
            copy.comment = comment.to_string();
        }
        copy.attrs.retain(|key, _| {
            !key.starts_with("source_") && !matches!(key.as_str(), "last_seen" | "visible_to")
        });
        copy.set_attr("owner", owner);
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        Ok(insert_resource(&mut inner, copy))
    }

    pub(crate) fn modify_tls_certificate(
        &self,
        id: &Uuid,
        owner: &str,
        name: Option<&str>,
        comment: Option<&str>,
        trust: Option<bool>,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get_mut(id)
            .filter(|resource| {
                !resource.trashed
                    && resource.resource_type == "tls_certificate"
                    && resource.attr("owner") == Some(owner)
            })
            .ok_or_else(|| StoreError::NotFound("TLS certificate".to_string()))?;
        let changed = name.is_some() || comment.is_some() || trust.is_some();
        if let Some(name) = name {
            resource.name = name.to_string();
        }
        if let Some(comment) = comment {
            resource.comment = comment.to_string();
        }
        if let Some(trust) = trust {
            resource.set_attr("trust", if trust { "1" } else { "0" });
        }
        if changed {
            resource.modification_time = now_iso();
        }
        Ok(())
    }

    pub(crate) fn delete_tls_certificate(&self, id: &Uuid, owner: &str) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let exists = inner.resources.get(id).is_some_and(|resource| {
            !resource.trashed
                && resource.resource_type == "tls_certificate"
                && resource.attr("owner") == Some(owner)
        });
        if !exists {
            return Err(StoreError::NotFound("TLS certificate".to_string()));
        }
        remove_resource(&mut inner, id);
        Ok(())
    }

    pub(crate) fn import_report_format(
        &self,
        mut resource: Resource,
        exported_id: Uuid,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let id_collision = inner.resources.values().any(|candidate| {
            candidate.id == exported_id
                || candidate.attr("original_uuid") == Some(exported_id.to_string().as_str())
        });
        resource.id = if id_collision {
            Uuid::new_v4()
        } else {
            exported_id
        };
        if id_collision {
            resource.set_attr("original_uuid", &exported_id.to_string());
        }

        if active_name_exists(&inner, "report_format", &resource.name, None) {
            let original_name = resource.name.clone();
            let mut number = 2_u64;
            loop {
                let candidate = format!("{original_name} {number}");
                if !active_name_exists(&inner, "report_format", &candidate, None) {
                    resource.name = candidate;
                    break;
                }
                number += 1;
            }
        }
        resource.trashed = false;
        resource.set_attr("active", "0");
        resource.set_attr("predefined", "0");
        resource.set_attr("trust", "unknown");
        let now = now_iso();
        resource.creation_time = now.clone();
        resource.modification_time = now;
        Ok(insert_resource(&mut inner, resource))
    }

    pub(crate) fn clone_report_format(
        &self,
        id: &Uuid,
        requested_name: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = active_typed_resource(&inner, id, "report_format")?.clone();
        let name = requested_name.filter(|name| !name.is_empty()).map_or_else(
            || unique_clone_name(&inner, "report_format", &original.name),
            str::to_string,
        );
        if active_name_exists(&inner, "report_format", &name, None) {
            return Err(StoreError::InvalidArgument("Report format exists already"));
        }

        let source_predefined = original.attr("predefined") == Some("1");
        let mut copy = original;
        copy.id = Uuid::new_v4();
        copy.name = name;
        copy.trashed = false;
        copy.set_attr("predefined", "0");
        if source_predefined {
            copy.set_attr("trust", "yes");
        }
        copy.attrs
            .retain(|key, _| !key.starts_with("report_format_param_option:"));
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        Ok(insert_resource(&mut inner, copy))
    }

    pub(crate) fn modify_report_format(
        &self,
        id: &Uuid,
        name: Option<&str>,
        summary: Option<&str>,
        active: Option<bool>,
        param: Option<(&str, &str)>,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = active_typed_resource(&inner, id, "report_format")?.clone();
        if original.attr("predefined") == Some("1") {
            return Err(StoreError::InvalidArgument(
                "Predefined report formats cannot be modified",
            ));
        }
        if let Some(name) = name {
            if active_name_exists(&inner, "report_format", name, Some(id)) {
                return Err(StoreError::InvalidArgument("Report format exists already"));
            }
        }

        // The pinned implementation commits metadata before attempting the
        // parameter update. Keep this intentionally non-atomic ordering.
        let resource = inner
            .resources
            .get_mut(id)
            .expect("validated report format remains present while locked");
        if let Some(name) = name {
            resource.name = name.to_string();
        }
        if let Some(summary) = summary {
            resource.set_attr("summary", summary);
        }
        if let Some(active) = active {
            resource.set_attr("active", if active { "1" } else { "0" });
        }
        resource.modification_time = now_iso();

        if let Some((name, value)) = param {
            let resource = inner
                .resources
                .get(id)
                .expect("validated report format remains present while locked");
            validate_seeded_report_format_value(resource, name, value)?;
            let resource = inner
                .resources
                .get_mut(id)
                .expect("validated report format remains present while locked");
            resource.set_attr(&format!("report_format_param_value:{name}"), value);
            resource.modification_time = now_iso();
        }
        Ok(())
    }

    pub(crate) fn delete_report_format(&self, id: &Uuid, ultimate: bool) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get(id)
            .filter(|resource| resource.resource_type == "report_format")
            .cloned()
            .ok_or_else(|| StoreError::NotFound("report format".to_string()))?;

        let fields = [
            "notice_attach_format",
            "notice_report_format",
            "scp_report_format",
            "send_report_format",
            "smb_report_format",
            "verinice_server_report_format",
        ];
        let notice_fields = ["notice_attach_format", "notice_report_format"];
        let id_text = id.to_string();
        let used_by = |candidate: &Resource, fields: &[&str]| {
            fields
                .iter()
                .any(|field| candidate.attr(field) == Some(id_text.as_str()))
        };
        let referenced = inner.resources.values().any(|candidate| {
            candidate.resource_type == "alert"
                && if resource.trashed {
                    candidate.trashed && used_by(candidate, &fields)
                } else if candidate.trashed {
                    ultimate && used_by(candidate, &notice_fields)
                } else {
                    used_by(candidate, &fields)
                }
        });
        if referenced {
            return Err(StoreError::InUse("report format"));
        }

        if ultimate {
            remove_resource(&mut inner, id);
            return Ok(());
        }
        if resource.trashed {
            return Ok(());
        }
        if resource.attr("predefined") == Some("1") {
            let stored = inner
                .resources
                .get_mut(id)
                .expect("validated report format remains present while locked");
            stored.trashed = true;
            stored.modification_time = now_iso();
            return Ok(());
        }

        let mut trashed = remove_resource(&mut inner, id)
            .expect("validated report format remains present while locked");
        trashed.set_attr("original_uuid", &id_text);
        trashed.id = Uuid::new_v4();
        trashed.trashed = true;
        trashed.modification_time = now_iso();
        insert_resource(&mut inner, trashed);
        Ok(())
    }

    pub(crate) fn verify_report_format(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get_mut(id)
            .filter(|resource| !resource.trashed && resource.resource_type == "report_format")
            .ok_or_else(|| StoreError::NotFound("report format".to_string()))?;
        let trust = if resource.attr("signature").is_none_or(str::is_empty) {
            "unknown"
        } else {
            resource.attr("verification_outcome").unwrap_or("unknown")
        }
        .to_string();
        resource.set_attr("trust", &trust);
        let now = now_iso();
        resource.set_attr("trust_time", &now);
        resource.modification_time = now;
        Ok(())
    }

    pub(crate) fn create_report_config(
        &self,
        name: &str,
        comment: &str,
        report_format_id: Uuid,
        params: &[ReportConfigParamUpdate],
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let report_format = active_typed_resource(&inner, &report_format_id, "report_format")?;
        if report_format.attr("configurable") != Some("1") {
            return Err(StoreError::InvalidArgument(
                "Report format is not configurable",
            ));
        }
        if active_name_exists(&inner, "report_config", name, None) {
            return Err(StoreError::InvalidArgument(
                "Report configuration exists already",
            ));
        }
        let overrides = validate_report_config_updates(report_format, params, false)?;

        let mut resource = Resource::new("report_config", name);
        resource.comment = comment.to_string();
        resource.set_attr("report_format_id", &report_format_id.to_string());
        for (name, value) in overrides {
            if let Some(value) = value {
                resource.set_attr(&format!("report_config_value:{name}"), &value);
            }
        }
        Ok(insert_resource(&mut inner, resource))
    }

    pub(crate) fn clone_report_config(
        &self,
        id: &Uuid,
        requested_name: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = active_typed_resource(&inner, id, "report_config")?.clone();
        let name = requested_name.filter(|name| !name.is_empty()).map_or_else(
            || unique_clone_name(&inner, "report_config", &original.name),
            str::to_string,
        );
        if active_name_exists(&inner, "report_config", &name, None) {
            return Err(StoreError::InvalidArgument(
                "Report configuration exists already",
            ));
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        copy.name = name;
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        Ok(insert_resource(&mut inner, copy))
    }

    pub(crate) fn modify_report_config(
        &self,
        id: &Uuid,
        name: Option<&str>,
        comment: Option<&str>,
        params: &[ReportConfigParamUpdate],
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = active_typed_resource(&inner, id, "report_config")?.clone();
        let report_format_id = original
            .attr("report_format_id")
            .and_then(|id| Uuid::parse_str(id).ok())
            .ok_or(StoreError::NotFound("report format".to_string()))?;
        // The pinned gvmd path resolves the format even for a metadata-only
        // request because the terminated parameter array is non-empty.
        let report_format = active_typed_resource(&inner, &report_format_id, "report_format")?;
        if name.is_some_and(str::is_empty) {
            return Err(StoreError::InvalidArgument("Name must not be empty"));
        }
        if let Some(name) = name {
            if active_name_exists(&inner, "report_config", name, Some(id)) {
                return Err(StoreError::InvalidArgument(
                    "Report configuration exists already",
                ));
            }
        }
        let updates = validate_report_config_updates(report_format, params, true)?;

        let resource = inner
            .resources
            .get_mut(id)
            .expect("validated report configuration remains present while locked");
        if let Some(name) = name {
            resource.name = name.to_string();
        }
        if let Some(comment) = comment {
            resource.comment = comment.to_string();
        }
        for (name, value) in updates {
            let key = format!("report_config_value:{name}");
            if let Some(value) = value {
                resource.set_attr(&key, &value);
            } else {
                resource.remove_attr(&key);
            }
        }
        resource.modification_time = now_iso();
        Ok(())
    }

    pub(crate) fn create_task(
        &self,
        mut task: Resource,
        mut references: TaskReferences,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(target) = references.target {
            validate_task_reference(&inner, &target, "target")?;
            task.set_attr("target_id", &target.to_string());
        }
        if let Some(target) = references.specialized_target {
            validate_task_reference(&inner, &target.id(), target.resource_type())?;
            task.set_attr(target.attr_name(), &target.id().to_string());
            if let SpecializedTaskTarget::AgentGroup(group_id) = target {
                let group = active_typed_resource(&inner, &group_id, "agent_group")?;
                let group_scanner = group
                    .attr("scanner_id")
                    .and_then(|id| Uuid::parse_str(id).ok())
                    .unwrap_or(DEFAULT_SCANNER_ID);
                if references
                    .scanner
                    .is_some_and(|scanner| scanner != group_scanner)
                {
                    return Err(StoreError::InvalidArgument(
                        "Scanner ID does not match agent group's scanner",
                    ));
                }
                references.scanner = Some(group_scanner);
            }
        }
        if let Some(config) = references.config {
            validate_task_reference(&inner, &config, "config")?;
            task.set_attr("config_id", &config.to_string());
        }
        if let Some(scanner) = references.scanner {
            validate_task_reference(&inner, &scanner, "scanner")?;
            task.set_attr("scanner_id", &scanner.to_string());
        }
        if let Some(schedule) = references.schedule {
            validate_task_reference(&inner, &schedule, "schedule")?;
            task.set_attr("schedule_id", &schedule.to_string());
        }
        task.set_attr(
            "schedule_periods",
            &references.schedule_periods.unwrap_or(0).to_string(),
        );
        if references.target.is_none() && references.specialized_target.is_none() {
            task.attrs.remove("target_id");
            task.set_attr("import_task", "1");
            task.set_attr("status", TaskStatus::Done.as_str());
        } else {
            task.set_attr("status", TaskStatus::New.as_str());
        }
        if task.attr("usage_type").is_none() {
            task.set_attr("usage_type", "scan");
        }
        validate_task_attributes(&inner, &task)?;
        task.modification_time = now_iso();
        Ok(insert_resource(&mut inner, task))
    }

    pub(crate) fn create_linked_report(
        &self,
        mut report: Resource,
        task_id: Option<Uuid>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(task_id) = task_id {
            active_typed_resource(&inner, &task_id, "task")?;
            report.set_attr("task_id", &task_id.to_string());
        }
        report.modification_time = now_iso();
        Ok(insert_resource(&mut inner, report))
    }

    /// Atomically import a scan report, its bounded result projection, and any
    /// requested host assets.
    pub(crate) fn import_report(
        &self,
        mut report: Resource,
        task_id: Uuid,
        in_assets: bool,
        hosts: &[String],
        mut results: Vec<Resource>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, &task_id, "task")?;
        if task.attr("import_task") != Some("1") {
            return Err(StoreError::InvalidArgument(
                "Report import requires an import task",
            ));
        }
        if task.attr("usage_type").unwrap_or("scan") != "scan" {
            return Err(StoreError::InvalidArgument(
                "Only scan reports can be imported",
            ));
        }

        if in_assets
            && hosts
                .iter()
                .any(|host| host.parse::<std::net::IpAddr>().is_err())
        {
            return Err(StoreError::InvalidArgument(
                "Imported report contains an invalid host address",
            ));
        }

        let report_id = report.id;
        report.set_attr("task_id", &task_id.to_string());
        report.set_attr("usage_type", "scan");
        report.set_attr("status", "Done");
        report.set_attr("in_assets", if in_assets { "1" } else { "0" });
        report.modification_time = now_iso();

        for result in &mut results {
            result.set_attr("report_id", &report_id.to_string());
            result.modification_time = now_iso();
        }

        // All validation is complete before the first mutation. Keep the
        // insertion sequence under the same write lock so callers never
        // observe a partial report graph.
        insert_resource(&mut inner, report);
        for result in results {
            insert_resource(&mut inner, result);
        }
        if in_assets {
            for host in hosts {
                let existing = inner
                    .resources
                    .values()
                    .find(|resource| {
                        resource.resource_type == "asset"
                            && !resource.trashed
                            && resource.asset_type() == Some("host")
                            && resource.name == *host
                    })
                    .map(|resource| resource.id);
                if let Some(asset_id) = existing {
                    let asset = inner
                        .resources
                        .get_mut(&asset_id)
                        .expect("selected host asset remains present while locked");
                    asset.set_attr("source_report_id", &report_id.to_string());
                    asset.modification_time = now_iso();
                } else {
                    let mut asset = Resource::new("asset", host);
                    asset.set_attr("type", "host");
                    asset.set_attr("source_report_id", &report_id.to_string());
                    insert_resource(&mut inner, asset);
                }
            }
        }
        Ok(report_id)
    }

    /// Get a resource by UUID.
    pub fn get(&self, id: &Uuid) -> Option<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner.resources.get(id).filter(|r| !r.trashed).cloned()
    }

    pub(crate) fn get_typed(&self, id: &Uuid, resource_type: &str) -> Option<Resource> {
        self.get(id)
            .filter(|resource| resource.resource_type == resource_type)
    }

    pub(crate) fn copy_config(
        &self,
        source_id: &Uuid,
        requested_name: Option<&str>,
        requested_comment: Option<&str>,
        usage_override: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let source = inner
            .resources
            .get(source_id)
            .filter(|resource| {
                resource.resource_type == "config"
                    && !resource.trashed
                    && resource.attr("accessible") != Some("0")
            })
            .cloned()
            .ok_or_else(|| StoreError::NotFound("config".to_string()))?;

        let name = requested_name.filter(|name| !name.is_empty()).map_or_else(
            || unique_clone_name(&inner, "config", &source.name),
            str::to_string,
        );
        if active_name_exists(&inner, "config", &name, None) {
            return Err(StoreError::InvalidArgument(
                "Configuration name exists already",
            ));
        }

        let mut copy = source.clone();
        copy.id = Uuid::new_v4();
        copy.name = name;
        if let Some(comment) = requested_comment.filter(|comment| !comment.is_empty()) {
            copy.comment = comment.to_string();
        }
        if let Some(usage) = usage_override.filter(|usage| !usage.is_empty()) {
            copy.set_attr(
                "usage_type",
                if usage.eq_ignore_ascii_case("policy") {
                    "policy"
                } else {
                    "scan"
                },
            );
        }
        copy.set_attr("predefined", "0");
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let copy_id = copy.id;
        let source_key = source_id.to_string();
        let copy_key = copy_id.to_string();
        if let Some(nvts) = inner.discovery.config_nvts.get(&source_key).cloned() {
            inner.discovery.config_nvts.insert(copy_key.clone(), nvts);
        }
        let mut preferences = inner
            .discovery
            .config_preferences
            .get(&source_key)
            .cloned()
            .unwrap_or_default();
        if copy.attr("usage_type") == Some("policy") {
            preferences
                .entry(":0:entry:table_driven_lsc".to_string())
                .or_insert_with(|| "0".to_string());
        }
        inner
            .discovery
            .config_preferences
            .insert(copy_key, preferences);
        insert_resource(&mut inner, copy);
        Ok(copy_id)
    }

    pub(crate) fn import_config(
        &self,
        requested_name: &str,
        comment: &str,
        usage: &str,
        nvts: BTreeSet<String>,
        mut preferences: BTreeMap<String, String>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let mut name = requested_name.to_string();
        let mut suffix = 1_u64;
        while active_name_exists(&inner, "config", &name, None) {
            name = format!("{requested_name} {suffix}");
            suffix += 1;
        }
        let usage = if usage.eq_ignore_ascii_case("policy") {
            "policy"
        } else {
            "scan"
        };
        if usage == "policy" {
            preferences
                .entry(":0:entry:table_driven_lsc".to_string())
                .or_insert_with(|| "0".to_string());
        }
        let mut config = Resource::new("config", &name);
        config.comment = comment.to_string();
        config.set_attr("usage_type", usage);
        config.set_attr("predefined", "0");
        let id = config.id;
        let key = id.to_string();
        inner.discovery.config_nvts.insert(key.clone(), nvts);
        inner.discovery.config_preferences.insert(key, preferences);
        insert_resource(&mut inner, config);
        Ok(id)
    }

    pub(crate) fn modify_config_atomic(
        &self,
        id: &Uuid,
        mutation: ConfigMutation,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let mut config = inner
            .resources
            .get(id)
            .filter(|resource| resource.resource_type == "config" && !resource.trashed)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("config".to_string()))?;
        if config.attr("predefined") == Some("1") {
            return Err(StoreError::InvalidState(
                "Predefined configuration cannot be modified",
            ));
        }
        if let Some(name) = mutation.name.as_deref().filter(|name| !name.is_empty()) {
            if active_name_exists(&inner, "config", name, Some(id)) {
                return Err(StoreError::InvalidArgument(
                    "Configuration name exists already",
                ));
            }
        }

        let config_key = id.to_string();
        if !mutation.actions.is_empty()
            && inner.resources.values().any(|task| {
                task.resource_type == "task"
                    && !task.trashed
                    && task.attr("config_id") == Some(config_key.as_str())
                    && task.attr("config_location").unwrap_or("active") == "active"
                    && task.attr("visible") != Some("0")
            })
        {
            return Err(StoreError::InUse("config"));
        }

        if let Some(name) = mutation.name.as_deref().filter(|name| !name.is_empty()) {
            config.name = name.to_string();
        }
        if let Some(comment) = mutation
            .comment
            .as_deref()
            .filter(|comment| !comment.is_empty())
        {
            config.comment = comment.to_string();
        }

        let mut nvts = inner
            .discovery
            .config_nvts
            .get(&config_key)
            .cloned()
            .unwrap_or_default();
        let mut preferences = inner
            .discovery
            .config_preferences
            .get(&config_key)
            .cloned()
            .unwrap_or_default();
        let known_families = inner
            .discovery
            .nvts
            .values()
            .map(|nvt| nvt.family.clone())
            .collect::<BTreeSet<_>>();

        for action in mutation.actions {
            match action {
                ConfigMutationAction::Preference(update) => {
                    if let Some(nvt_oid) = update.nvt_oid.as_deref() {
                        if !inner.discovery.nvts.contains_key(nvt_oid) {
                            return Err(StoreError::InvalidArgument(
                                "Mock limitation: preference references an unseeded NVT",
                            ));
                        }
                    }
                    if update.value.as_deref() == Some("")
                        && config_preference_type(&update.name) == Some("radio")
                    {
                        return Err(StoreError::InvalidArgument(
                            "Empty radio preference values are invalid",
                        ));
                    }
                    if let Some(value) = update.value {
                        preferences.insert(update.name, value);
                    } else {
                        preferences.remove(&update.name);
                    }
                }
                ConfigMutationAction::NvtSelection(update) => {
                    if !known_families.contains(&update.family) {
                        return Err(StoreError::InvalidArgument(
                            "Mock limitation: selection references an unseeded family",
                        ));
                    }
                    for oid in &update.nvt_oids {
                        if inner
                            .discovery
                            .nvts
                            .get(oid)
                            .is_none_or(|nvt| nvt.family != update.family)
                        {
                            return Err(StoreError::InvalidArgument(
                                "Mock limitation: selection references an unseeded family NVT",
                            ));
                        }
                    }
                    nvts.retain(|oid| {
                        inner
                            .discovery
                            .nvts
                            .get(oid)
                            .is_none_or(|nvt| nvt.family != update.family)
                    });
                    nvts.extend(update.nvt_oids);
                    add_config_family_order(&mut config, &update.family);
                }
                ConfigMutationAction::FamilySelection(update) => {
                    for family in &update.families {
                        if !known_families.contains(&family.name) {
                            return Err(StoreError::InvalidArgument(
                                "Mock limitation: selection references an unseeded family",
                            ));
                        }
                    }
                    nvts.clear();
                    config.attrs.retain(|key, _| {
                        !key.starts_with("config_family_growing:")
                            && key != "config_family_order"
                            && key != "config_families_growing"
                    });
                    let mut ordered_families = Vec::new();
                    for family in update.families {
                        if !ordered_families.contains(&family.name) {
                            ordered_families.push(family.name.clone());
                        }
                        config.set_attr(
                            &format!("config_family_growing:{}", family.name),
                            if family.growing { "1" } else { "0" },
                        );
                        if family.all {
                            nvts.extend(
                                inner
                                    .discovery
                                    .nvts
                                    .values()
                                    .filter(|nvt| nvt.family == family.name)
                                    .map(|nvt| nvt.oid.clone()),
                            );
                        }
                    }
                    config.set_attr("config_family_order", &ordered_families.join("\u{1f}"));
                    config.set_attr(
                        "config_families_growing",
                        if update.auto_add_new_families {
                            "1"
                        } else {
                            "0"
                        },
                    );
                }
            }
        }

        config.modification_time = now_iso();
        *inner
            .resources
            .get_mut(id)
            .expect("configuration remained present while locked") = config;
        inner.discovery.config_nvts.insert(config_key.clone(), nvts);
        inner
            .discovery
            .config_preferences
            .insert(config_key, preferences);
        Ok(())
    }

    pub(crate) fn config_observation(
        &self,
        id: &Uuid,
    ) -> (BTreeSet<String>, BTreeMap<String, String>) {
        let inner = self.inner.read().expect("store lock poisoned");
        let key = id.to_string();
        (
            inner
                .discovery
                .config_nvts
                .get(&key)
                .cloned()
                .unwrap_or_default(),
            inner
                .discovery
                .config_preferences
                .get(&key)
                .cloned()
                .unwrap_or_default(),
        )
    }

    pub(crate) fn config_tasks(&self, id: &Uuid, trash_location: bool) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        let id = id.to_string();
        let expected_location = if trash_location { "trash" } else { "active" };
        inner
            .resources
            .values()
            .filter(|resource| {
                resource.resource_type == "task"
                    && resource.attr("config_id") == Some(id.as_str())
                    && resource.attr("config_location").unwrap_or("active") == expected_location
            })
            .cloned()
            .collect()
    }

    pub(crate) fn delete_config_lifecycle(
        &self,
        id: &Uuid,
        ultimate: bool,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let config = inner
            .resources
            .get(id)
            .filter(|resource| resource.resource_type == "config")
            .cloned()
            .ok_or_else(|| StoreError::NotFound("config".to_string()))?;
        if config.trashed && !ultimate {
            return Ok(());
        }
        let id_text = id.to_string();
        let location = if config.trashed { "trash" } else { "active" };
        let referenced = inner.resources.values().any(|task| {
            task.resource_type == "task"
                && task.attr("config_id") == Some(id_text.as_str())
                && task.attr("config_location").unwrap_or("active") == location
                && (ultimate || (!task.trashed && task.attr("visible") != Some("0")))
        });
        if referenced {
            return Err(StoreError::InUse("config"));
        }
        if ultimate {
            remove_resource(&mut inner, id);
            inner.discovery.config_nvts.remove(&id_text);
            inner.discovery.config_preferences.remove(&id_text);
        } else {
            if let Some(config) = inner.resources.get_mut(id) {
                config.trashed = true;
                config.modification_time = now_iso();
            }
            for task in inner.resources.values_mut().filter(|task| {
                task.resource_type == "task"
                    && !task.trashed
                    && task.attr("config_id") == Some(id_text.as_str())
                    && task.attr("visible") == Some("0")
                    && task.attr("config_location").unwrap_or("active") == "active"
            }) {
                task.set_attr("config_location", "trash");
            }
        }
        Ok(())
    }

    pub(crate) fn render_resource_xml(&self, resource: &Resource) -> String {
        if resource.resource_type != "task" {
            return resource.to_xml();
        }
        let inner = self.inner.read().expect("store lock poisoned");
        let (current_report, last_report) = resolve_task_reports(&inner, resource);
        let current_report = current_report.and_then(|id| inner.resources.get(&id));
        let last_report = last_report.and_then(|id| inner.resources.get(&id));
        let last_report_results = last_report.map_or_else(Vec::new, |report| {
            let report_id = report.id.to_string();
            inner
                .resources
                .values()
                .filter(|result| {
                    result.resource_type == "result"
                        && result.trashed == report.trashed
                        && result.attr("report_id") == Some(report_id.as_str())
                })
                .collect()
        });
        resource.to_xml_with_task_reports(current_report, last_report, &last_report_results, false)
    }

    /// Return the configured user timezone, falling back as gvmd does.
    pub(crate) fn user_timezone(&self) -> String {
        self.list("setting")
            .into_iter()
            .find(|resource| resource.name == "timezone")
            .and_then(|resource| resource.attr("value").map(str::to_string))
            .filter(|timezone| !timezone.trim().is_empty())
            .unwrap_or_else(|| "UTC".to_string())
    }

    /// Get all resources of a given type (non-trashed).
    pub fn list(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect()
    }

    /// Get all trashed resources of a given type.
    pub fn list_trashed(&self, resource_type: &str) -> Vec<Resource> {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && r.trashed)
            .cloned()
            .collect()
    }

    /// Modify a resource. Returns true if found and updated.
    pub fn modify<F>(&self, id: &Uuid, f: F) -> bool
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                return false;
            }
            f(resource);
            resource.modification_time = now_iso();
            true
        } else {
            false
        }
    }

    /// Modify the comment of a non-trashed host asset.
    pub(crate) fn modify_host_asset_comment(&self, id: &Uuid, comment: &str) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner.resources.get_mut(id) else {
            return false;
        };
        if resource.trashed
            || resource.resource_type != "asset"
            || resource.asset_type() != Some("host")
        {
            return false;
        }
        comment.clone_into(&mut resource.comment);
        resource.modification_time = now_iso();
        true
    }

    pub(crate) fn modify_typed<F>(&self, id: &Uuid, resource_type: &str, f: F) -> bool
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner
            .resources
            .get_mut(id)
            .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
        else {
            return false;
        };
        f(resource);
        resource.modification_time = now_iso();
        true
    }

    pub(crate) fn modify_target<F>(
        &self,
        id: &Uuid,
        changes_scan_settings: bool,
        f: F,
    ) -> Result<(), StoreError>
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        active_typed_resource(&inner, id, "target")?;

        if changes_scan_settings {
            let id_text = id.to_string();
            let referenced = inner.resources.values().any(|candidate| {
                candidate.resource_type == "task"
                    && !candidate.trashed
                    && candidate.attr("target_id") == Some(id_text.as_str())
            });
            if referenced {
                return Err(StoreError::InUse("target"));
            }
        }

        let target = inner
            .resources
            .get_mut(id)
            .expect("validated target should remain present while locked");
        f(target);
        target.modification_time = now_iso();
        Ok(())
    }

    pub(crate) fn modify_task<F>(
        &self,
        id: &Uuid,
        references: TaskReferenceUpdates,
        f: F,
    ) -> Result<(), StoreError>
    where
        F: FnOnce(&mut Resource),
    {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?;
        let status = task
            .attr("status")
            .ok_or(StoreError::Inconsistent("task status"))?
            .to_string();
        let import_task = task.attr("import_task") == Some("1");

        if import_task && references.schedule != TaskScheduleUpdate::Omitted {
            return Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule",
            ));
        }

        if references.changes_scan_definition() && status != TaskStatus::New.as_str() {
            return Err(StoreError::InvalidState(
                "Task references can only be changed while the task is New",
            ));
        }
        if let Some(target) = references.target {
            validate_task_reference(&inner, &target, "target")?;
        }
        if let Some(target) = references.specialized_target {
            validate_task_reference(&inner, &target.id(), target.resource_type())?;
        }
        if let Some(config) = references.config {
            validate_task_reference(&inner, &config, "config")?;
        }
        if let Some(scanner) = references.scanner {
            validate_task_reference(&inner, &scanner, "scanner")?;
        }
        if let TaskScheduleUpdate::Set(schedule) = references.schedule {
            validate_task_reference(&inner, &schedule, "schedule")?;
        }

        let mut candidate = task.clone();
        let original_alterable = candidate.attr("alterable").map(str::to_string);
        if let Some(target) = references.target {
            candidate.set_attr("target_id", &target.to_string());
            for key in [
                "agent_group_id",
                "oci_image_target_id",
                "web_application_target_id",
            ] {
                candidate.attrs.remove(key);
            }
        }
        if let Some(target) = references.specialized_target {
            candidate.attrs.remove("target_id");
            for key in [
                "agent_group_id",
                "oci_image_target_id",
                "web_application_target_id",
            ] {
                candidate.attrs.remove(key);
            }
            candidate.set_attr(target.attr_name(), &target.id().to_string());
        }
        if let Some(config) = references.config {
            candidate.set_attr("config_id", &config.to_string());
        }
        if let Some(scanner) = references.scanner {
            candidate.set_attr("scanner_id", &scanner.to_string());
        }
        match references.schedule {
            TaskScheduleUpdate::Omitted => {
                if let Some(schedule_periods) = references.schedule_periods {
                    candidate.set_attr("schedule_periods", &schedule_periods.to_string());
                }
            }
            TaskScheduleUpdate::Set(schedule) => {
                candidate.set_attr("schedule_id", &schedule.to_string());
                candidate.set_attr(
                    "schedule_periods",
                    &references.schedule_periods.unwrap_or(0).to_string(),
                );
            }
            TaskScheduleUpdate::Clear => {
                candidate.attrs.remove("schedule_id");
                candidate.set_attr(
                    "schedule_periods",
                    &references.schedule_periods.unwrap_or(0).to_string(),
                );
            }
        }
        f(&mut candidate);
        if candidate.attr("alterable").map(str::to_string) != original_alterable
            && status != TaskStatus::New.as_str()
        {
            return Err(StoreError::InvalidState(
                "Task must be New to modify Alterable state",
            ));
        }
        validate_task_attributes(&inner, &candidate)?;
        candidate.modification_time = now_iso();
        inner.resources.insert(*id, candidate);
        Ok(())
    }

    pub(crate) fn move_task(&self, id: &Uuid, destination: Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?;
        let current_scanner = stored_task_reference(task, "scanner_id", "scanner")?;
        validate_openvas_scanner(&inner, &current_scanner, "Task must use an OpenVAS scanner")?;
        validate_openvas_scanner(
            &inner,
            &destination,
            "Destination scanner does not support slaves",
        )?;

        let mut candidate = task.clone();
        candidate.set_attr("scanner_id", &destination.to_string());
        validate_task_attributes(&inner, &candidate)?;
        candidate.modification_time = now_iso();
        inner.resources.insert(*id, candidate);
        Ok(())
    }

    /// Delete a resource (move to trash or permanently).
    pub fn delete(&self, id: &Uuid, ultimate: bool) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if ultimate {
            remove_resource(&mut inner, id).is_some()
        } else if let Some(resource) = inner.resources.get_mut(id) {
            resource.trashed = true;
            true
        } else {
            false
        }
    }

    /// Permanently delete an asset while checking its lifecycle atomically.
    pub(crate) fn delete_asset_permanently(&self, id: &Uuid) -> DeleteAssetResult {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let Some(resource) = inner.resources.get(id) else {
            return DeleteAssetResult::NotFound;
        };
        if resource.resource_type != "asset" || resource.trashed {
            return DeleteAssetResult::NotFound;
        }
        if resource.asset_type() == Some("os") && resource.operating_system_asset_is_referenced() {
            return DeleteAssetResult::InUse;
        }
        remove_resource(&mut inner, id);
        DeleteAssetResult::Deleted
    }

    pub(crate) fn delete_typed(
        &self,
        id: &Uuid,
        resource_type: &str,
        ultimate: bool,
    ) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get(id)
            .filter(|resource| resource.resource_type == resource_type)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))?;

        if resource.trashed && !ultimate {
            return Ok(());
        }

        let task_reference = match resource_type {
            "target" => Some(("target_id", "target")),
            "agent_group" => Some(("agent_group_id", "agent_group")),
            "oci_image_target" => Some(("oci_image_target_id", "oci_image_target")),
            "web_application_target" => {
                Some(("web_application_target_id", "web_application_target"))
            }
            "config" => Some(("config_id", "config")),
            "scanner" => Some(("scanner_id", "scanner")),
            "schedule" => Some(("schedule_id", "schedule")),
            _ => None,
        };
        if let Some((reference_key, referenced_type)) = task_reference {
            let id = id.to_string();
            let referenced = inner.resources.values().any(|candidate| {
                candidate.resource_type == "task"
                    && candidate.attr(reference_key) == Some(id.as_str())
                    && (!candidate.trashed || (resource_type == "schedule" && ultimate))
            });
            if referenced {
                return Err(StoreError::InUse(referenced_type));
            }
        }

        if resource_type == "task" && !resource.trashed && task_is_active(&resource) {
            if let Ok(report_id) = resolve_current_report_id(&inner, &resource) {
                if let Some(report) = inner.resources.get_mut(&report_id) {
                    report.set_attr("status", TaskStatus::Stopped.as_str());
                    report.modification_time = now_iso();
                }
            }
            if let Some(task) = inner.resources.get_mut(id) {
                task.set_attr("status", TaskStatus::Stopped.as_str());
                task.modification_time = now_iso();
            }
        }

        if resource_type == "report" {
            let report_id = id.to_string();
            let task_links: Vec<(Uuid, bool, Option<Uuid>)> = inner
                .resources
                .values()
                .filter(|candidate| candidate.resource_type == "task")
                .map(|task| {
                    let stored_reference = task.attr("report_id") == Some(report_id.as_str());
                    let resolved_current = (!task.trashed && task_is_active(task))
                        .then(|| resolve_task_reports(&inner, task).0)
                        .flatten();
                    (task.id, stored_reference, resolved_current)
                })
                .collect();
            if task_links
                .iter()
                .any(|(_, _, resolved_current)| *resolved_current == Some(*id))
            {
                return Err(StoreError::InUse("report"));
            }
            for (task_id, stored_reference, resolved_current) in task_links {
                if !stored_reference {
                    continue;
                }
                if let Some(task) = inner.resources.get_mut(&task_id) {
                    if let Some(current_id) = resolved_current {
                        task.set_attr("report_id", &current_id.to_string());
                    } else {
                        task.attrs.remove("report_id");
                        task.set_attr("status", TaskStatus::New.as_str());
                    }
                    task.modification_time = now_iso();
                }
            }
        }

        if resource_type == "task" {
            let task_id = id.to_string();
            let report_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "report"
                        && candidate.attr("task_id") == Some(task_id.as_str())
                })
                .map(|candidate| candidate.id)
                .collect();
            let report_id_strings: Vec<String> = report_ids.iter().map(Uuid::to_string).collect();
            let result_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "result"
                        && candidate.attr("report_id").is_some_and(|candidate_id| {
                            report_id_strings
                                .iter()
                                .any(|report_id| report_id == candidate_id)
                        })
                })
                .map(|candidate| candidate.id)
                .collect();

            if ultimate {
                for dependent_id in report_ids.into_iter().chain(result_ids) {
                    remove_resource(&mut inner, &dependent_id);
                }
            } else {
                for dependent_id in report_ids.into_iter().chain(result_ids) {
                    if let Some(dependent) = inner.resources.get_mut(&dependent_id) {
                        dependent.trashed = true;
                        dependent.modification_time = now_iso();
                    }
                }
            }
        }

        if ultimate {
            remove_resource(&mut inner, id);
        } else if let Some(resource) = inner.resources.get_mut(id) {
            resource.trashed = true;
            resource.modification_time = now_iso();
        }
        Ok(())
    }

    /// Restore a trashed resource.
    pub fn restore(&self, id: &Uuid) -> bool {
        let mut inner = self.inner.write().expect("store lock poisoned");
        if let Some(resource) = inner.resources.get_mut(id) {
            if resource.trashed {
                resource.trashed = false;
                return true;
            }
        }
        false
    }

    pub(crate) fn restore_checked(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let resource = inner
            .resources
            .get(id)
            .filter(|resource| resource.trashed)
            .cloned()
            .ok_or_else(|| StoreError::NotFound("resource".to_string()))?;

        if resource.resource_type == "task" {
            validate_stored_task_references(&inner, &resource)?;
            let task_id = id.to_string();
            let report_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "report"
                        && candidate.attr("task_id") == Some(task_id.as_str())
                })
                .map(|candidate| candidate.id)
                .collect();
            let report_id_strings: Vec<String> = report_ids.iter().map(Uuid::to_string).collect();
            let result_ids: Vec<Uuid> = inner
                .resources
                .values()
                .filter(|candidate| {
                    candidate.resource_type == "result"
                        && candidate.attr("report_id").is_some_and(|report_id| {
                            report_id_strings
                                .iter()
                                .any(|candidate_id| candidate_id == report_id)
                        })
                })
                .map(|candidate| candidate.id)
                .collect();
            for dependent_id in report_ids.into_iter().chain(result_ids) {
                if let Some(dependent) = inner.resources.get_mut(&dependent_id) {
                    dependent.trashed = false;
                    dependent.modification_time = now_iso();
                }
            }
        }

        let resource = inner
            .resources
            .get_mut(id)
            .expect("validated resource should remain present while locked");
        resource.trashed = false;
        resource.modification_time = now_iso();
        Ok(())
    }

    /// Empty the trashcan (permanently remove all trashed resources).
    pub fn empty_trashcan(&self) {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let trashed: Vec<Uuid> = inner
            .resources
            .values()
            .filter(|resource| resource.trashed)
            .map(|resource| resource.id)
            .collect();
        for id in trashed {
            remove_resource(&mut inner, &id);
        }
    }

    /// Clone a resource (create a copy with a new UUID).
    pub fn clone_resource(&self, id: &Uuid) -> Option<Uuid> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = inner.resources.get(id)?.clone();
        if original.trashed {
            return None;
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let new_id = copy.id;
        insert_resource(&mut inner, copy);
        Some(new_id)
    }

    pub(crate) fn clone_typed(
        &self,
        id: &Uuid,
        resource_type: &str,
        clone_name: Option<&str>,
    ) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let original = inner
            .resources
            .get(id)
            .filter(|resource| !resource.trashed && resource.resource_type == resource_type)
            .cloned()
            .ok_or_else(|| StoreError::NotFound(resource_type.to_string()))?;
        if resource_type == "task" {
            validate_stored_task_references(&inner, &original)?;
        }
        if let Some(task_id) = original
            .attr("task_id")
            .filter(|_| resource_type == "report")
        {
            let task_id =
                Uuid::parse_str(task_id).map_err(|_| StoreError::Inconsistent("report task"))?;
            active_typed_resource(&inner, &task_id, "task")?;
        }

        let mut copy = original;
        copy.id = Uuid::new_v4();
        if resource_type == "task" {
            let status = if copy.attr("import_task") == Some("1") {
                TaskStatus::Done
            } else {
                TaskStatus::New
            };
            copy.set_attr("status", status.as_str());
            copy.attrs.remove("report_id");
        }
        if resource_type == "role" {
            copy.name = if let Some(name) = clone_name.filter(|name| !name.is_empty()) {
                let name_exists = inner.resources.values().any(|resource| {
                    !resource.trashed
                        && resource.resource_type == resource_type
                        && resource.name == name
                });
                if name_exists {
                    return Err(StoreError::InvalidArgument("Role exists already"));
                }
                name.to_string()
            } else {
                unique_clone_name(&inner, resource_type, &copy.name)
            };
            // gvmd copies role permissions, but not role_users membership.
            copy.set_attr("users", "");
            let source_id = id.to_string();
            let copied_id = copy.id.to_string();
            let permissions = inner
                .resources
                .values()
                .filter(|permission| {
                    !permission.trashed
                        && permission.resource_type == "permission"
                        && permission.attr("subject_type") == Some("role")
                        && permission.attr("subject_id") == Some(source_id.as_str())
                        && permission.attr("resource_id").is_none_or(str::is_empty)
                })
                .cloned()
                .collect::<Vec<_>>();
            // The mock has no ownerless built-in permissions. Its command-level
            // permissions model the other branch of gvmd's role-copy predicate.
            for mut permission in permissions {
                permission.id = Uuid::new_v4();
                permission.set_attr("subject_id", &copied_id);
                let now = now_iso();
                permission.creation_time = now.clone();
                permission.modification_time = now;
                insert_resource(&mut inner, permission);
            }
        }
        let now = now_iso();
        copy.creation_time = now.clone();
        copy.modification_time = now;
        let new_id = copy.id;
        insert_resource(&mut inner, copy);
        Ok(new_id)
    }

    pub(crate) fn start_task(&self, id: &Uuid) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        if task.attr("import_task") == Some("1") {
            return Err(StoreError::InvalidState("Import tasks cannot be started"));
        }
        validate_stored_task_references(&inner, &task)?;

        match task.attr("status") {
            Some("New" | "Stopped" | "Done" | "Interrupted") => {}
            Some("Running" | "Requested") => {
                return Err(StoreError::InvalidState("Task is already running"));
            }
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task cannot be started in current state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = Uuid::new_v4();
        let mut report =
            Resource::with_id("report", &format!("Report for {}", task.name), report_id);
        report.set_attr("task_id", &id.to_string());
        report.set_attr("status", TaskStatus::Running.as_str());
        if let Some(usage_type) = task.attr("usage_type") {
            report.set_attr("usage_type", usage_type);
        }
        insert_resource(&mut inner, report);

        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Running.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(report_id)
    }

    pub(crate) fn stop_task(&self, id: &Uuid) -> Result<(), StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        match task.attr("status") {
            Some("Running" | "Requested") => {}
            Some("Stopped") => return Err(StoreError::InvalidState("Task is already stopped")),
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task cannot be stopped in current state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = resolve_current_report_id(&inner, &task)?;

        let report = inner
            .resources
            .get_mut(&report_id)
            .expect("validated report should remain present while locked");
        report.set_attr("status", TaskStatus::Stopped.as_str());
        report.modification_time = now_iso();
        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Stopped.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(())
    }

    pub(crate) fn resume_task(&self, id: &Uuid) -> Result<Uuid, StoreError> {
        let mut inner = self.inner.write().expect("store lock poisoned");
        let task = active_typed_resource(&inner, id, "task")?.clone();
        validate_stored_task_references(&inner, &task)?;
        match task.attr("status") {
            Some("Stopped" | "Interrupted") => {}
            Some("Running" | "Requested") => {
                return Err(StoreError::InvalidState("Task is already running"));
            }
            Some(_) => {
                return Err(StoreError::InvalidState(
                    "Task can only be resumed from Stopped or Interrupted state",
                ));
            }
            None => return Err(StoreError::Inconsistent("task status")),
        }

        let report_id = resolve_current_report_id(&inner, &task)?;

        let report = inner
            .resources
            .get_mut(&report_id)
            .expect("validated report should remain present while locked");
        report.set_attr("status", TaskStatus::Running.as_str());
        report.modification_time = now_iso();
        let task = inner
            .resources
            .get_mut(id)
            .expect("validated task should remain present while locked");
        task.set_attr("status", TaskStatus::Running.as_str());
        task.set_attr("report_id", &report_id.to_string());
        task.modification_time = now_iso();
        Ok(report_id)
    }

    /// List resources of a type, filtered by a simple `name=value` filter string.
    pub fn list_filtered(&self, resource_type: &str, filter: &str) -> Vec<Resource> {
        // Parse simple "name=value" filters (GMP filter syntax subset)
        let inner = self.inner.read().expect("store lock poisoned");
        let mut results: Vec<Resource> = inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .cloned()
            .collect();

        // Apply filter predicates
        for part in filter.split_whitespace() {
            if let Some((key, value)) = part.split_once('=') {
                match key {
                    "name" => {
                        results.retain(|r| r.name == value);
                    }
                    "type" => {
                        results.retain(|r| r.resource_type == value);
                    }
                    _ => {
                        // Check attrs
                        let key = key.to_string();
                        let value = value.to_string();
                        results.retain(|r| r.attr(&key) == Some(value.as_str()));
                    }
                }
            }
        }

        results
    }

    /// Count resources of a type (non-trashed).
    pub fn count(&self, resource_type: &str) -> usize {
        let inner = self.inner.read().expect("store lock poisoned");
        inner
            .resources
            .values()
            .filter(|r| r.resource_type == resource_type && !r.trashed)
            .count()
    }

    /// Seed a resource for testing.
    pub fn seed(&self, resource: Resource) {
        let mut resource = resource;
        resource.modification_time = now_iso();
        let mut inner = self.inner.write().expect("store lock poisoned");
        insert_resource(&mut inner, resource);
    }
}

impl Default for ResourceStore {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use std::thread;

    fn create_valid_task(store: &ResourceStore, name: &str) -> Uuid {
        let target_id = store.create(Resource::new("target", &format!("{name} Target")));
        store
            .create_task(
                Resource::new("task", name),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("valid task graph")
    }

    #[test]
    fn test_create_and_get() {
        let store = ResourceStore::new();
        let resource = Resource::new("task", "My Task");
        let id = store.create(resource);
        let fetched = store.get(&id).expect("should exist");
        assert_eq!(fetched.name, "My Task");
        assert_eq!(fetched.resource_type, "task");
    }

    #[test]
    fn test_list() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Task 1"));
        store.create(Resource::new("task", "Task 2"));
        store.create(Resource::new("target", "Target 1"));

        assert_eq!(store.list("task").len(), 2);
        assert_eq!(store.list("target").len(), 1);
        assert_eq!(store.list("config").len(), 5);
    }

    #[test]
    fn test_modify() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Old Name"));
        let modified = store.modify(&id, |r| {
            r.name = "New Name".to_string();
        });
        assert!(modified);
        assert_eq!(store.get(&id).unwrap().name, "New Name");
    }

    #[test]
    fn asset_helpers_cover_unknown_rendering_and_missing_modification() {
        let store = ResourceStore::new();
        let missing = Uuid::new_v4();
        assert!(!store.modify_host_asset_comment(&missing, "unused"));
        assert!(matches!(
            store.delete_asset_permanently(&missing),
            DeleteAssetResult::NotFound
        ));

        let mut unknown = Resource::new("asset", "mystery");
        unknown.set_attr("type", "firmware");
        assert!(unknown
            .to_asset_xml()
            .contains("<type>firmware</type></asset>"));
    }

    #[test]
    fn atomic_asset_delete_has_exactly_one_winner() {
        let store = ResourceStore::new();
        let mut host = Resource::new("asset", "192.0.2.10");
        host.set_attr("type", "host");
        let id = store.create(host);
        let barrier = Arc::new(Barrier::new(3));

        let handles: Vec<_> = (0..2)
            .map(|_| {
                let store = store.clone();
                let barrier = Arc::clone(&barrier);
                thread::spawn(move || {
                    barrier.wait();
                    store.delete_asset_permanently(&id)
                })
            })
            .collect();
        barrier.wait();
        let results: Vec<_> = handles
            .into_iter()
            .map(|handle| handle.join().expect("delete thread panicked"))
            .collect();

        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, DeleteAssetResult::Deleted))
                .count(),
            1
        );
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, DeleteAssetResult::NotFound))
                .count(),
            1
        );
    }

    #[test]
    fn test_delete_to_trash() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Doomed"));
        assert!(store.delete(&id, false));
        assert!(store.get(&id).is_none()); // hidden from normal get
        assert_eq!(store.list_trashed("task").len(), 1);
    }

    #[test]
    fn test_delete_ultimate() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Gone"));
        assert!(store.delete(&id, true));
        assert!(store.get(&id).is_none());
        assert_eq!(store.list_trashed("task").len(), 0);
        let inner = store.inner.read().expect("store lock");
        assert!(!inner.insertion_order.contains_key(&id));
    }

    #[test]
    fn test_restore() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Restored"));
        store.delete(&id, false);
        assert!(store.get(&id).is_none());
        assert!(store.restore(&id));
        assert!(store.get(&id).is_some());
    }

    #[test]
    fn test_empty_trashcan() {
        let store = ResourceStore::new();
        let id1 = store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id1, false);
        store.delete(&id2, false);
        store.empty_trashcan();
        assert_eq!(store.list_trashed("task").len(), 0);
        let inner = store.inner.read().expect("store lock");
        assert!(!inner.insertion_order.contains_key(&id1));
        assert!(!inner.insertion_order.contains_key(&id2));
    }

    #[test]
    fn report_format_trash_preserves_definitions_and_options_until_ultimate_delete() {
        let store = ResourceStore::new();
        let mut format = Resource::new("report_format", "Trash option fixture");
        format.set_attr("active", "1");
        format.set_attr("predefined", "0");
        format.set_attr("report_format_param_type:Choice", "selection");
        format.set_attr("report_format_param_value:Choice", "red");
        format.set_attr("report_format_param_default:Choice", "blue");
        format.set_attr("report_format_param_option:Choice\u{1f}0", "red");
        format.set_attr("report_format_param_option:Choice\u{1f}1", "blue");
        let active_id = store.create(format);

        store
            .delete_report_format(&active_id, false)
            .expect("move to trash");
        let trashed = store
            .list_trashed("report_format")
            .into_iter()
            .find(|resource| resource.name == "Trash option fixture")
            .expect("trashed format remains stored");
        assert_ne!(trashed.id, active_id);
        assert_eq!(
            trashed.attr("report_format_param_type:Choice"),
            Some("selection")
        );
        assert_eq!(
            trashed.attr("report_format_param_option:Choice\u{1f}0"),
            Some("red")
        );
        assert_eq!(
            trashed.attr("report_format_param_option:Choice\u{1f}1"),
            Some("blue")
        );

        store
            .delete_report_format(&trashed.id, true)
            .expect("ultimate deletion");
        assert!(store
            .list_trashed("report_format")
            .into_iter()
            .all(|resource| resource.name != "Trash option fixture"));
    }

    #[test]
    fn test_clone_resource() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let cloned_id = store.clone_resource(&id).expect("clone should work");
        assert_ne!(id, cloned_id);
        let original = store.get(&id).unwrap();
        let clone = store.get(&cloned_id).unwrap();
        assert_eq!(original.name, clone.name);
    }

    #[test]
    fn test_auth() {
        let store = ResourceStore::with_credentials("user", "pass");
        assert!(!store.is_authenticated(1));
        assert!(store.authenticate(1, "user", "pass"));
        assert!(store.is_authenticated(1));
        assert!(!store.authenticate(2, "user", "wrong"));
        assert!(!store.is_authenticated(2));
        assert!(store.authenticate_token(3, ResourceStore::authentication_token()));
        assert!(store.is_authenticated(3));
        assert!(!store.authenticate_token(4, "wrong-token"));
        assert!(!store.is_authenticated(4));
    }

    #[test]
    fn test_get_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.get(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_delete_nonexistent() {
        let store = ResourceStore::new();
        assert!(!store.delete(&Uuid::new_v4(), false));
    }

    #[test]
    fn test_list_filtered_by_name() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        store.create(Resource::new("task", "Beta"));
        store.create(Resource::new("task", "Alpha"));

        let filtered = store.list_filtered("task", "name=Alpha");
        assert_eq!(filtered.len(), 2);
        assert!(filtered.iter().all(|r| r.name == "Alpha"));
    }

    #[test]
    fn test_list_filtered_no_match() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "Alpha"));
        let filtered = store.list_filtered("task", "name=Nonexistent");
        assert_eq!(filtered.len(), 0);
    }

    #[test]
    fn test_list_filtered_by_attr() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "T1");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "T2");
        r2.set_attr("status", "New");
        store.create(r2);

        let filtered = store.list_filtered("task", "status=Running");
        assert_eq!(filtered.len(), 1);
        assert_eq!(filtered[0].name, "T1");
    }

    #[test]
    fn test_count() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        store.create(Resource::new("task", "T2"));
        assert_eq!(store.count("task"), 2);
        assert_eq!(store.count("target"), 0);
    }

    #[test]
    fn test_modify_trashed_returns_false() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Trashed"));
        store.delete(&id, false);
        assert!(!store.modify(&id, |r| r.name = "New".to_string()));
    }

    #[test]
    fn test_clone_nonexistent() {
        let store = ResourceStore::new();
        assert!(store.clone_resource(&Uuid::new_v4()).is_none());
    }

    #[test]
    fn test_count_excludes_trashed() {
        let store = ResourceStore::new();
        store.create(Resource::new("task", "T1"));
        let id2 = store.create(Resource::new("task", "T2"));
        store.delete(&id2, false);
        assert_eq!(store.count("task"), 1);
    }

    #[test]
    fn test_list_filtered_multi_term() {
        let store = ResourceStore::new();
        let mut r = Resource::new("task", "Alpha");
        r.set_attr("status", "Running");
        store.create(r);
        let mut r2 = Resource::new("task", "Alpha");
        r2.set_attr("status", "New");
        store.create(r2);
        let filtered = store.list_filtered("task", "name=Alpha status=Running");
        assert_eq!(filtered.len(), 1);
    }

    #[test]
    fn test_to_xml_sorts_attributes_deterministically() {
        let mut resource = Resource::new("task", "Ordered");
        resource.set_attr("zeta", "last");
        resource.set_attr("alpha", "first");

        let xml = resource.to_xml();

        assert!(xml.find("<alpha>").unwrap() < xml.find("<zeta>").unwrap());
    }

    #[test]
    fn task_report_references_are_selected_independently_from_linked_history() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Lifecycle task");
        let task_id = task.id;
        let target_id = store.create(Resource::new("target", "Lifecycle target"));
        task.set_attr("target_id", &target_id.to_string());
        task.set_attr("config_id", &DEFAULT_CONFIG_ID.to_string());
        task.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        task.set_attr("status", TaskStatus::Running.as_str());
        let active_id = Uuid::new_v4();
        task.set_attr("report_id", &active_id.to_string());
        store.seed(task);

        let mut older_done = Resource::new("report", "Older completed report");
        older_done.creation_time = "2026-01-01T00:00:00Z".to_string();
        older_done.set_attr("task_id", &task_id.to_string());
        older_done.set_attr("status", TaskStatus::Done.as_str());
        let older_done_id = older_done.id;
        store.seed(older_done);

        let mut last_done = Resource::new("report", "Latest completed report");
        last_done.creation_time = "2026-02-01T00:00:00Z".to_string();
        last_done.set_attr("task_id", &task_id.to_string());
        last_done.set_attr("status", TaskStatus::Done.as_str());
        let last_done_id = last_done.id;
        store.seed(last_done);

        let mut active = Resource::with_id("report", "Active report", active_id);
        active.creation_time = "2026-03-01T00:00:00Z".to_string();
        active.set_attr("task_id", &task_id.to_string());
        active.set_attr("status", TaskStatus::Running.as_str());
        store.seed(active);

        let mut mismatched = Resource::new("report", "Another task's report");
        let mismatched_id = mismatched.id;
        mismatched.set_attr("task_id", &Uuid::new_v4().to_string());
        mismatched.set_attr("status", TaskStatus::Running.as_str());
        store.seed(mismatched);

        let task = store.get(&task_id).expect("seeded task");
        let running = store.render_resource_xml(&task);
        assert!(running.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(running.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
        assert!(running.contains("<timestamp>2026-03-01T00:00:00Z</timestamp>"));
        assert!(running.contains("<result_count><critical>0</critical>"));
        assert!(!running.contains(&older_done_id.to_string()));
        assert!(!running.contains("<report_id>"));

        assert!(store.modify(&task_id, |task| task
            .set_attr("report_id", &mismatched_id.to_string())));
        store
            .stop_task(&task_id)
            .expect("recover linked current report");
        let task = store.get(&task_id).expect("seeded task");
        assert_eq!(task.attr("report_id"), Some(active_id.to_string().as_str()));
        let stopped = store.render_resource_xml(&task);
        assert!(stopped.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(stopped.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
        assert!(!stopped.contains(&mismatched_id.to_string()));

        assert_eq!(store.resume_task(&task_id), Ok(active_id));

        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Interrupted.as_str());
            task.set_attr("report_id", &active_id.to_string());
        }));
        assert!(store.modify(&active_id, |report| {
            report.set_attr("status", TaskStatus::Interrupted.as_str());
        }));
        let task = store.get(&task_id).expect("seeded task");
        let interrupted = store.render_resource_xml(&task);
        assert!(interrupted.contains(&format!("<current_report><report id=\"{active_id}\">")));
        assert!(interrupted.contains(&format!("<last_report><report id=\"{last_done_id}\">")));

        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Done.as_str());
        }));
        let task = store.get(&task_id).expect("seeded task");
        let done = store.render_resource_xml(&task);
        assert!(!done.contains("<current_report>"));
        assert!(done.contains(&format!("<last_report><report id=\"{last_done_id}\">")));
    }

    #[test]
    fn task_last_report_summaries_use_linked_scan_and_audit_results() {
        let scan_store = ResourceStore::new();
        let mut scan_task = Resource::new("task", "Scan summary");
        let scan_task_id = scan_task.id;
        scan_task.set_attr("status", TaskStatus::Done.as_str());
        scan_store.seed(scan_task);
        let mut scan_report = Resource::new("report", "Completed scan");
        let scan_report_id = scan_report.id;
        scan_report.set_attr("task_id", &scan_task_id.to_string());
        scan_report.set_attr("status", TaskStatus::Done.as_str());
        scan_report.set_attr("usage_type", "scan");
        scan_store.seed(scan_report);
        for severity in ["9.8", "7.5", "5.0", "2.0", "0.0"] {
            let mut result = Resource::new("result", "Scan result");
            result.set_attr("report_id", &scan_report_id.to_string());
            result.set_attr("severity", severity);
            scan_store.seed(result);
        }
        let mut false_positive = Resource::new("result", "False positive");
        false_positive.set_attr("report_id", &scan_report_id.to_string());
        false_positive.set_attr("severity", "10.0");
        false_positive.set_attr("false_positive", "1");
        scan_store.seed(false_positive);
        let mut trashed_result = Resource::new("result", "Trashed critical result");
        trashed_result.set_attr("report_id", &scan_report_id.to_string());
        trashed_result.set_attr("severity", "9.9");
        trashed_result.trashed = true;
        scan_store.seed(trashed_result);

        let scan_xml = scan_store
            .render_resource_xml(&scan_store.get(&scan_task_id).expect("seeded scan task"));
        for expected in [
            "<critical>1</critical>",
            "<high>1</high>",
            "<medium>1</medium>",
            "<low>1</low>",
            "<log>1</log>",
            "<false_positive>1</false_positive>",
            "<severity>10.0</severity>",
        ] {
            assert!(
                scan_xml.contains(expected),
                "missing {expected}: {scan_xml}"
            );
        }

        let audit_store = ResourceStore::new();
        let mut audit_task = Resource::new("task", "Audit summary");
        let audit_task_id = audit_task.id;
        audit_task.set_attr("status", TaskStatus::Done.as_str());
        audit_store.seed(audit_task);
        let mut audit_report = Resource::new("report", "Completed audit");
        let audit_report_id = audit_report.id;
        audit_report.set_attr("task_id", &audit_task_id.to_string());
        audit_report.set_attr("status", TaskStatus::Done.as_str());
        audit_report.set_attr("usage_type", "audit");
        audit_store.seed(audit_report);
        for compliance in ["yes", "yes", "no", "incomplete", "undefined"] {
            let mut result = Resource::new("result", "Audit result");
            result.set_attr("report_id", &audit_report_id.to_string());
            result.set_attr("compliance", compliance);
            audit_store.seed(result);
        }

        let audit_xml = audit_store
            .render_resource_xml(&audit_store.get(&audit_task_id).expect("seeded audit task"));
        assert!(audit_xml
            .contains("<compliance_count><yes>2</yes><no>1</no><incomplete>1</incomplete>"));
    }

    #[test]
    fn permanent_task_deletion_prunes_dependent_insertion_order() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Disposable history");
        let task_id = task.id;
        task.set_attr("status", TaskStatus::Done.as_str());
        store.seed(task);
        let mut report = Resource::new("report", "Disposable report");
        let report_id = report.id;
        report.set_attr("task_id", &task_id.to_string());
        report.set_attr("status", TaskStatus::Done.as_str());
        store.seed(report);
        let mut result = Resource::new("result", "Disposable result");
        let result_id = result.id;
        result.set_attr("report_id", &report_id.to_string());
        store.seed(result);

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete task graph");

        let inner = store.inner.read().expect("store lock");
        for id in [task_id, report_id, result_id] {
            assert!(!inner.resources.contains_key(&id));
            assert!(!inner.insertion_order.contains_key(&id));
        }
    }

    #[test]
    fn task_report_ordering_uses_instants_and_insertion_order() {
        let store = ResourceStore::new();
        let mut task = Resource::new("task", "Ordered reports");
        let task_id = task.id;
        task.set_attr("status", TaskStatus::Running.as_str());
        store.seed(task);

        let mut later_text_earlier_instant = Resource::new("report", "Earlier instant");
        later_text_earlier_instant.creation_time = "2026-03-01T01:30:00+02:00".to_string();
        later_text_earlier_instant.set_attr("task_id", &task_id.to_string());
        later_text_earlier_instant.set_attr("status", TaskStatus::Done.as_str());
        store.seed(later_text_earlier_instant);

        let mut earlier_text_later_instant = Resource::new("report", "Later instant");
        earlier_text_later_instant.creation_time = "2026-03-01T00:00:00Z".to_string();
        earlier_text_later_instant.set_attr("task_id", &task_id.to_string());
        earlier_text_later_instant.set_attr("status", TaskStatus::Done.as_str());
        let expected_last = earlier_text_later_instant.id;
        store.seed(earlier_text_later_instant);

        let mut first_current = Resource::new("report", "First current");
        first_current.creation_time = "2026-03-01T01:00:00Z".to_string();
        first_current.set_attr("task_id", &task_id.to_string());
        first_current.set_attr("status", TaskStatus::Running.as_str());
        store.seed(first_current);

        let mut second_current = Resource::new("report", "Second current");
        second_current.creation_time = "2026-03-01T01:00:00Z".to_string();
        second_current.set_attr("task_id", &task_id.to_string());
        second_current.set_attr("status", TaskStatus::Processing.as_str());
        let expected_current = second_current.id;
        store.seed(second_current);

        let task = store.get(&task_id).expect("seeded task");
        let (current, last) = {
            let inner = store.inner.read().expect("store lock");
            resolve_task_reports(&inner, &task)
        };
        assert_eq!(current, Some(expected_current));
        assert_eq!(last, Some(expected_last));
    }

    #[test]
    fn every_gvmd_current_report_task_state_is_rendered() {
        for status in [
            TaskStatus::Requested,
            TaskStatus::Queued,
            TaskStatus::Running,
            TaskStatus::StopRequested,
            TaskStatus::DeleteRequested,
            TaskStatus::UltimateDeleteRequested,
            TaskStatus::Stopped,
            TaskStatus::Interrupted,
            TaskStatus::Processing,
        ] {
            let store = ResourceStore::new();
            let mut task = Resource::new("task", "State coverage");
            let task_id = task.id;
            task.set_attr("status", status.as_str());
            store.seed(task);
            let mut report = Resource::new("report", "Current report");
            let report_id = report.id;
            report.set_attr("task_id", &task_id.to_string());
            report.set_attr("status", status.as_str());
            store.seed(report);

            let task = store.get(&task_id).expect("seeded task");
            assert!(store
                .render_resource_xml(&task)
                .contains(&format!("<current_report><report id=\"{report_id}\">")));
        }
    }

    #[test]
    fn target_xml_always_observes_an_alive_test() {
        let default_target = Resource::new("target", "Default");
        assert!(default_target
            .to_xml()
            .contains("<alive_tests>Scan Config Default</alive_tests>"));

        let mut explicit_target = Resource::new("target", "Explicit");
        explicit_target.set_attr("alive_test", AliveTest::IcmpPing.as_target_name());
        assert!(explicit_target
            .to_xml()
            .contains("<alive_tests>ICMP Ping</alive_tests>"));

        assert!(!Resource::new("task", "Task")
            .to_xml()
            .contains("<alive_tests>"));
    }

    #[test]
    fn task_xml_uses_typed_report_reference_vocabulary() {
        let store = ResourceStore::new();
        let mut running = Resource::new("task", "Running Task");
        let task_id = running.id;
        running.set_attr("status", TaskStatus::Running.as_str());
        let mut report = Resource::new("report", "Running Report");
        let report_id = report.id;
        running.set_attr("report_id", &report_id.to_string());
        report.set_attr("task_id", &task_id.to_string());
        report.set_attr("status", TaskStatus::Running.as_str());
        store.seed(running);
        store.seed(report);

        let running_xml = store.render_resource_xml(&store.get(&task_id).expect("running task"));
        assert!(running_xml.contains(&format!("<current_report><report id=\"{report_id}\">")));
        assert!(!running_xml.contains("<report_id>"));

        assert!(store.modify(&task_id, |task| task.set_attr("status", "Done")));
        assert!(store.modify(&report_id, |report| report.set_attr("status", "Done")));
        let done_xml = store.render_resource_xml(&store.get(&task_id).expect("done task"));
        assert!(done_xml.contains(&format!("<last_report><report id=\"{report_id}\">")));
        assert!(!done_xml.contains("<report_id>"));
    }

    #[test]
    fn test_clone_resource_stress_with_concurrent_deletes() {
        let store = ResourceStore::new();
        let id = store.create(Resource::new("task", "Original"));
        let barrier = Arc::new(Barrier::new(3));

        let clone_store = store.clone();
        let clone_barrier = Arc::clone(&barrier);
        let clone_thread = thread::spawn(move || {
            clone_barrier.wait();
            for _ in 0..250 {
                let _ = clone_store.clone_resource(&id);
                thread::yield_now();
            }
        });

        let delete_store = store.clone();
        let delete_barrier = Arc::clone(&barrier);
        let delete_thread = thread::spawn(move || {
            delete_barrier.wait();
            for _ in 0..250 {
                let _ = delete_store.delete(&id, false);
                let _ = delete_store.restore(&id);
                thread::yield_now();
            }
        });

        barrier.wait();
        clone_thread.join().expect("clone thread");
        delete_thread.join().expect("delete thread");

        let tasks = store.list("task");
        assert!(tasks
            .iter()
            .all(|resource| resource.resource_type == "task"));
        assert!(tasks.iter().any(|resource| resource.id == id));
    }

    #[test]
    fn typed_task_modification_updates_and_validates_every_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Mutable");
        let target_id = store.create(Resource::new("target", "Replacement Target"));
        let config_id = store.create(Resource::new("config", "Replacement Config"));
        let scanner_id = store.create(Resource::new("scanner", "Replacement Scanner"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(config_id),
                    scanner: Some(scanner_id),
                    schedule: TaskScheduleUpdate::Omitted,
                    schedule_periods: None,
                },
                |_| {},
            )
            .expect("New task references should be replaceable");

        let task = store.get(&task_id).expect("task");
        assert_eq!(task.attr("target_id"), Some(target_id.to_string().as_str()));
        assert_eq!(task.attr("config_id"), Some(config_id.to_string().as_str()));
        assert_eq!(
            task.attr("scanner_id"),
            Some(scanner_id.to_string().as_str())
        );
        assert!(!store.modify_typed(&target_id, "task", |_| {}));
    }

    #[test]
    fn task_schedule_periods_follow_gvmd_update_semantics_in_any_task_state() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Scheduled Target"));
        let first_schedule = store.create(Resource::new("schedule", "First Schedule"));
        let second_schedule = store.create(Resource::new("schedule", "Second Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Scheduled Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: Some(first_schedule),
                    schedule_periods: Some(5),
                },
            )
            .expect("create scheduled task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
        }));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule_periods: Some(4),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("period-only update should preserve the schedule");
        let task = store.get(&task_id).expect("task");
        assert_eq!(
            task.attr("schedule_id"),
            Some(first_schedule.to_string().as_str())
        );
        assert_eq!(task.attr("schedule_periods"), Some("4"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Set(second_schedule),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("schedule replacement should reset omitted periods");
        let task = store.get(&task_id).expect("task");
        assert_eq!(
            task.attr("schedule_id"),
            Some(second_schedule.to_string().as_str())
        );
        assert_eq!(task.attr("schedule_periods"), Some("0"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Clear,
                    schedule_periods: Some(2),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("schedule clearing should apply supplied periods");
        let task = store.get(&task_id).expect("task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("2"));
    }

    #[test]
    fn import_task_schedule_updates_are_rejected_atomically() {
        let store = ResourceStore::new();
        let schedule_id = store.create(Resource::new("schedule", "Ignored Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Imported"),
                TaskReferences {
                    target: None,
                    specialized_target: None,
                    config: None,
                    scanner: None,
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("create import task");

        assert_eq!(
            store.modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Set(schedule_id),
                    schedule_periods: Some(4),
                    ..Default::default()
                },
                |_| {},
            ),
            Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule"
            ))
        );
        let task = store.get(&task_id).expect("import task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("0"));

        store
            .modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule_periods: Some(7),
                    ..Default::default()
                },
                |_| {},
            )
            .expect("period-only import task update");

        assert_eq!(
            store.modify_task(
                &task_id,
                TaskReferenceUpdates {
                    schedule: TaskScheduleUpdate::Clear,
                    schedule_periods: Some(3),
                    ..Default::default()
                },
                |_| {},
            ),
            Err(StoreError::InvalidArgument(
                "Import tasks cannot have a schedule"
            ))
        );
        let task = store.get(&task_id).expect("import task");
        assert_eq!(task.attr("schedule_id"), None);
        assert_eq!(task.attr("schedule_periods"), Some("7"));
    }

    #[test]
    fn task_delete_and_restore_cascade_to_reports_and_results() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Cascading");
        let report_id = store.start_task(&task_id).expect("start task");
        let mut result = Resource::new("result", "Linked Result");
        result.set_attr("report_id", &report_id.to_string());
        let result_id = store.create(result);
        store.stop_task(&task_id).expect("stop task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");
        store
            .delete_typed(&task_id, "task", false)
            .expect("trashing an already trashed task is idempotent");
        assert!(store
            .list_trashed("report")
            .iter()
            .any(|r| r.id == report_id));
        assert!(store
            .list_trashed("result")
            .iter()
            .any(|r| r.id == result_id));

        store.restore_checked(&task_id).expect("restore task graph");
        assert!(store.get(&report_id).is_some());
        assert!(store.get(&result_id).is_some());

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete task graph");
        assert!(store.get(&report_id).is_none());
        assert!(store.get(&result_id).is_none());
    }

    #[test]
    fn trashed_tasks_do_not_block_permanent_reference_deletion() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Disposable Target"));
        let config_id = store.create(Resource::new("config", "Disposable Config"));
        let scanner_id = store.create(Resource::new("scanner", "Disposable Scanner"));
        let task_id = store
            .create_task(
                Resource::new("task", "Trashed Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(config_id),
                    scanner: Some(scanner_id),
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("create task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");

        for (id, resource_type) in [
            (target_id, "target"),
            (config_id, "config"),
            (scanner_id, "scanner"),
        ] {
            store
                .delete_typed(&id, resource_type, true)
                .expect("trashed task must not block permanent deletion");
            assert!(store.get(&id).is_none());
        }
    }

    #[test]
    fn trashed_tasks_block_permanent_schedule_deletion() {
        let store = ResourceStore::new();
        let target_id = store.create(Resource::new("target", "Scheduled Target"));
        let schedule_id = store.create(Resource::new("schedule", "Retained Schedule"));
        let task_id = store
            .create_task(
                Resource::new("task", "Trashed Scheduled Task"),
                TaskReferences {
                    target: Some(target_id),
                    specialized_target: None,
                    config: Some(DEFAULT_CONFIG_ID),
                    scanner: Some(DEFAULT_SCANNER_ID),
                    schedule: Some(schedule_id),
                    schedule_periods: Some(2),
                },
            )
            .expect("create scheduled task");

        store
            .delete_typed(&task_id, "task", false)
            .expect("trash task");
        assert_eq!(
            store.delete_typed(&schedule_id, "schedule", true),
            Err(StoreError::InUse("schedule"))
        );

        store
            .delete_typed(&schedule_id, "schedule", false)
            .expect("trash schedule referenced only by a trashed task");
        assert_eq!(
            store.delete_typed(&schedule_id, "schedule", true),
            Err(StoreError::InUse("schedule"))
        );

        store
            .delete_typed(&task_id, "task", true)
            .expect("permanently delete dependent task");
        store
            .delete_typed(&schedule_id, "schedule", true)
            .expect("permanently delete unreferenced schedule");
    }

    #[test]
    fn deleting_an_active_task_tolerates_a_missing_report_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Active Without Report");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
            task.attrs.remove("report_id");
        }));

        store
            .delete_typed(&task_id, "task", true)
            .expect("synchronous mock deletion should still remove the task");
        assert!(store.get(&task_id).is_none());
    }

    #[test]
    fn deleting_an_active_task_does_not_mutate_an_unrelated_report_reference() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Corrupt Report Link");
        let other_task_id = create_valid_task(&store, "Report Owner");
        let other_report_id = store.start_task(&other_task_id).expect("start other task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("status", TaskStatus::Running.as_str());
            task.set_attr("report_id", &other_report_id.to_string());
        }));

        store
            .delete_typed(&task_id, "task", true)
            .expect("delete corrupt task");

        let other_report = store
            .get(&other_report_id)
            .expect("unrelated report remains");
        assert_eq!(
            other_report.attr("task_id"),
            Some(other_task_id.to_string().as_str())
        );
        assert_eq!(
            other_report.attr("status"),
            Some(TaskStatus::Running.as_str())
        );
    }

    #[test]
    fn fallback_selected_active_report_is_protected_from_deletion() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Missing Current Pointer");
        let current_report_id = store.start_task(&task_id).expect("start task");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("report_id", &Uuid::new_v4().to_string());
        }));

        let task = store.get(&task_id).expect("active task");
        let resolved = {
            let inner = store.inner.read().expect("store lock");
            resolve_task_reports(&inner, &task).0
        };
        assert_eq!(resolved, Some(current_report_id));
        assert_eq!(
            store.delete_typed(&current_report_id, "report", true),
            Err(StoreError::InUse("report"))
        );
        assert!(store.get(&current_report_id).is_some());
    }

    #[test]
    fn deleting_stale_report_pointer_repairs_active_task_to_resolved_report() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Stale Current Pointer");
        let current_report_id = store.start_task(&task_id).expect("start task");
        let mut stale_report = Resource::new("report", "Stale completed report");
        stale_report.set_attr("status", TaskStatus::Done.as_str());
        let stale_report_id = store
            .create_linked_report(stale_report, Some(task_id))
            .expect("create stale report");
        assert!(store.modify(&task_id, |task| {
            task.set_attr("report_id", &stale_report_id.to_string());
        }));

        store
            .delete_typed(&stale_report_id, "report", true)
            .expect("delete non-current stale report");

        let task = store.get(&task_id).expect("active task remains");
        assert_eq!(task.attr("status"), Some(TaskStatus::Running.as_str()));
        assert_eq!(
            task.attr("report_id"),
            Some(current_report_id.to_string().as_str())
        );
        assert!(store.get(&stale_report_id).is_none());
        assert!(store.get(&current_report_id).is_some());
    }

    #[test]
    fn cloning_validates_linked_reports_and_preserves_import_task_state() {
        let store = ResourceStore::new();
        let task_id = create_valid_task(&store, "Report Owner");
        let report_id = store
            .create_linked_report(Resource::new("report", "Linked"), Some(task_id))
            .expect("linked report");
        let report_copy = store
            .clone_typed(&report_id, "report", None)
            .expect("clone linked report");
        assert_eq!(
            store
                .get(&report_copy)
                .expect("report copy")
                .attr("task_id"),
            Some(task_id.to_string().as_str())
        );

        let mut malformed_report = Resource::new("report", "Malformed Link");
        malformed_report.set_attr("task_id", "not-a-uuid");
        let malformed_report_id = store.create(malformed_report);
        assert_eq!(
            store.clone_typed(&malformed_report_id, "report", None),
            Err(StoreError::Inconsistent("report task"))
        );

        let mut missing_task_report = Resource::new("report", "Missing Task");
        missing_task_report.set_attr("task_id", &Uuid::new_v4().to_string());
        let missing_task_report_id = store.create(missing_task_report);
        assert_eq!(
            store.clone_typed(&missing_task_report_id, "report", None),
            Err(StoreError::NotFound("task".to_string()))
        );

        let import_task_id = store
            .create_task(
                Resource::new("task", "Imported"),
                TaskReferences {
                    target: None,
                    specialized_target: None,
                    config: None,
                    scanner: None,
                    schedule: None,
                    schedule_periods: None,
                },
            )
            .expect("import task");
        let import_copy = store
            .clone_typed(&import_task_id, "task", None)
            .expect("clone import task");
        assert_eq!(
            store.get(&import_copy).expect("import copy").attr("status"),
            Some(TaskStatus::Done.as_str())
        );
        assert_eq!(
            store.start_task(&import_task_id),
            Err(StoreError::InvalidState("Import tasks cannot be started"))
        );
    }

    #[test]
    fn cloning_rejects_corrupt_specialized_task_graphs() {
        let store = ResourceStore::new();
        let agent_group_id = store.create(Resource::new("agent_group", "Agents"));
        let oci_target_id = store.create(Resource::new("oci_image_target", "OCI"));

        let mut multiple_targets = Resource::new("task", "Multiple specialized targets");
        multiple_targets.set_attr("agent_group_id", &agent_group_id.to_string());
        multiple_targets.set_attr("oci_image_target_id", &oci_target_id.to_string());
        multiple_targets.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        multiple_targets.set_attr("status", TaskStatus::New.as_str());
        let multiple_targets_id = store.create(multiple_targets);
        assert_eq!(
            store.clone_typed(&multiple_targets_id, "task", None),
            Err(StoreError::Inconsistent("task target"))
        );

        let mut missing_config = Resource::new("task", "Missing optional config");
        missing_config.set_attr("agent_group_id", &agent_group_id.to_string());
        missing_config.set_attr("scanner_id", &DEFAULT_SCANNER_ID.to_string());
        missing_config.set_attr("config_id", &Uuid::new_v4().to_string());
        missing_config.set_attr("status", TaskStatus::New.as_str());
        let missing_config_id = store.create(missing_config);
        assert_eq!(
            store.clone_typed(&missing_config_id, "task", None),
            Err(StoreError::NotFound("config".to_string()))
        );
    }

    #[test]
    fn lifecycle_rejects_corrupt_or_inapplicable_states_atomically() {
        let store = ResourceStore::new();

        let invalid_state_id = create_valid_task(&store, "Invalid State");
        assert!(store.modify(&invalid_state_id, |task| {
            task.set_attr("status", "Paused");
        }));
        assert_eq!(
            store.start_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task cannot be started in current state"
            ))
        );
        assert_eq!(
            store.stop_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task cannot be stopped in current state"
            ))
        );
        assert_eq!(
            store.resume_task(&invalid_state_id),
            Err(StoreError::InvalidState(
                "Task can only be resumed from Stopped or Interrupted state"
            ))
        );

        let missing_status_id = create_valid_task(&store, "Missing Status");
        assert!(store.modify(&missing_status_id, |task| {
            task.attrs.remove("status");
        }));
        for result in [
            store.start_task(&missing_status_id).map(|_| ()),
            store.stop_task(&missing_status_id),
            store.resume_task(&missing_status_id).map(|_| ()),
        ] {
            assert_eq!(result, Err(StoreError::Inconsistent("task status")));
        }

        let mismatched_report_id = create_valid_task(&store, "Mismatched Report");
        let report_id = store.start_task(&mismatched_report_id).expect("start task");
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &Uuid::new_v4().to_string());
        }));
        assert_eq!(
            store.stop_task(&mismatched_report_id),
            Err(StoreError::Inconsistent("task report"))
        );
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &mismatched_report_id.to_string());
        }));
        store.stop_task(&mismatched_report_id).expect("stop task");
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &Uuid::new_v4().to_string());
        }));
        assert_eq!(
            store.resume_task(&mismatched_report_id),
            Err(StoreError::Inconsistent("task report"))
        );
        assert!(store.modify(&report_id, |report| {
            report.set_attr("task_id", &mismatched_report_id.to_string());
        }));
        assert!(store.modify(&mismatched_report_id, |task| {
            task.set_attr("status", TaskStatus::Interrupted.as_str());
        }));
        assert_eq!(
            store
                .resume_task(&mismatched_report_id)
                .expect("resume interrupted task"),
            report_id
        );
    }

    #[test]
    fn administration_state_changes_without_exposing_confidential_values() {
        let store = ResourceStore::new();
        store.apply_auth_groups(BTreeMap::from([(
            "method:radius_connect".to_string(),
            BTreeMap::from([("radiuskey".to_string(), "radius-secret".to_string())]),
        )]));
        store.replace_license("license-secret".to_string());
        store.record_wizard_run(
            "quick_first_scan".to_string(),
            Some("step".to_string()),
            Some(false),
            vec![("password".to_string(), "wizard-secret".to_string())],
        );

        assert_eq!(store.wizard_run_count(), 1);
        assert!(store.license_installed());
        let debug = format!("{store:?}");
        for secret in ["radius-secret", "license-secret", "wizard-secret"] {
            assert!(!debug.contains(secret));
        }
    }
}
