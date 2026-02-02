//! Artifact management for Lux Network operations

use rust_embed::RustEmbed;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// Embedded artifacts (metrics rules, scripts, etc.)
#[derive(RustEmbed)]
#[folder = "artifacts/"]
pub struct Assets;

/// Get an embedded asset by path
pub fn get_asset(path: &str) -> Option<std::borrow::Cow<'static, [u8]>> {
    Assets::get(path).map(|f| f.data)
}

/// Get an embedded asset as a string
pub fn get_asset_string(path: &str) -> Option<String> {
    Assets::get(path).map(|f| String::from_utf8_lossy(f.data.as_ref()).into_owned())
}

/// List all embedded assets
pub fn list_assets() -> Vec<String> {
    Assets::iter().map(|s| s.to_string()).collect()
}

/// Default metrics rules file name
pub const DEFAULT_METRICS_RULES: &str = "default.metrics.rules.yaml";

/// Get the default metrics rules YAML content
pub fn get_default_metrics_rules() -> Option<String> {
    get_asset_string(DEFAULT_METRICS_RULES)
}

/// Parse the default metrics rules into a structured format
pub fn parse_default_metrics_rules() -> Option<MetricsRules> {
    let content = get_asset_string(DEFAULT_METRICS_RULES)?;
    serde_yaml::from_str(&content).ok()
}

/// Metrics rules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsRules {
    /// Filter rules for metrics
    pub filters: Vec<MetricsFilter>,
}

/// Individual metrics filter
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsFilter {
    /// Regex pattern to match metric names
    pub regex: String,
    /// Optional label matchers
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
}

/// Binary artifact types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryType {
    /// luxd node binary
    Luxd,
    /// luxd daemon (operator agent)
    LuxDaemon,
    /// Plugin/VM binary
    Plugin,
}

impl BinaryType {
    /// Get the string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Luxd => "luxd",
            Self::LuxDaemon => "luxd-daemon",
            Self::Plugin => "plugin",
        }
    }
}

/// Architecture types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Amd64,
    Arm64,
}

impl Arch {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Amd64 => "amd64",
            Self::Arm64 => "arm64",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "amd64" | "x86_64" => Some(Self::Amd64),
            "arm64" | "aarch64" => Some(Self::Arm64),
            _ => None,
        }
    }

    /// Get the linux triplet suffix
    pub fn linux_suffix(&self) -> &'static str {
        match self {
            Self::Amd64 => "linux-amd64",
            Self::Arm64 => "linux-arm64",
        }
    }
}

/// Operating system types
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Os {
    Ubuntu2004,
    Ubuntu2204,
    AmazonLinux2,
}

impl Os {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Ubuntu2004 => "ubuntu20.04",
            Self::Ubuntu2204 => "ubuntu22.04",
            Self::AmazonLinux2 => "al2",
        }
    }

    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "ubuntu20.04" | "ubuntu2004" => Some(Self::Ubuntu2004),
            "ubuntu22.04" | "ubuntu2204" => Some(Self::Ubuntu2204),
            "al2" | "amazonlinux2" => Some(Self::AmazonLinux2),
            _ => None,
        }
    }
}

/// Get the download URL for luxd release
pub fn luxd_download_url(version: &str, arch: Arch) -> String {
    format!(
        "https://github.com/luxfi/node/releases/download/{}/luxd-{}-{}.tar.gz",
        version,
        version,
        arch.linux_suffix()
    )
}

/// Get the S3 key for an artifact
pub fn s3_artifact_key(cluster_id: &str, artifact_type: BinaryType, arch: Arch) -> String {
    format!(
        "{}/artifacts/{}/{}",
        cluster_id,
        artifact_type.as_str(),
        arch.as_str()
    )
}

/// Validate artifact path exists and is a file
pub fn validate_artifact_path(path: &Path) -> Result<(), String> {
    if !path.exists() {
        return Err(format!("Artifact path does not exist: {:?}", path));
    }
    if !path.is_file() {
        return Err(format!("Artifact path is not a file: {:?}", path));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_assets() {
        let assets = list_assets();
        assert!(
            assets.contains(&DEFAULT_METRICS_RULES.to_string()),
            "Expected default.metrics.rules.yaml in assets"
        );
    }

    #[test]
    fn test_get_default_metrics_rules() {
        let content = get_default_metrics_rules();
        assert!(content.is_some(), "Expected metrics rules to be embedded");
        let content = content.unwrap();
        assert!(
            content.contains("filters:"),
            "Expected 'filters:' in metrics rules"
        );
    }

    #[test]
    fn test_parse_default_metrics_rules() {
        let rules = parse_default_metrics_rules();
        assert!(rules.is_some(), "Expected to parse metrics rules");
        let rules = rules.unwrap();
        assert!(!rules.filters.is_empty(), "Expected at least one filter");
    }

    #[test]
    fn test_arch_from_str() {
        assert_eq!(Arch::from_str("amd64"), Some(Arch::Amd64));
        assert_eq!(Arch::from_str("x86_64"), Some(Arch::Amd64));
        assert_eq!(Arch::from_str("arm64"), Some(Arch::Arm64));
        assert_eq!(Arch::from_str("aarch64"), Some(Arch::Arm64));
        assert_eq!(Arch::from_str("unknown"), None);
    }

    #[test]
    fn test_os_from_str() {
        assert_eq!(Os::from_str("ubuntu22.04"), Some(Os::Ubuntu2204));
        assert_eq!(Os::from_str("al2"), Some(Os::AmazonLinux2));
        assert_eq!(Os::from_str("unknown"), None);
    }

    #[test]
    fn test_luxd_download_url() {
        let url = luxd_download_url("v1.0.0", Arch::Amd64);
        assert_eq!(
            url,
            "https://github.com/luxfi/node/releases/download/v1.0.0/luxd-v1.0.0-linux-amd64.tar.gz"
        );
    }

    #[test]
    fn test_s3_artifact_key() {
        let key = s3_artifact_key("cluster-1", BinaryType::Luxd, Arch::Arm64);
        assert_eq!(key, "cluster-1/artifacts/luxd/arm64");
    }
}
