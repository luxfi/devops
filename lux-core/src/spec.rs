//! Deployment specification for Lux Network operations

use crate::config::{CChainConfig, GenesisConfig, LuxdConfig};
use crate::types::{KeyInfo, NetworkId, NodeInfo};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use thiserror::Error;

pub const SPEC_VERSION: usize = 1;

/// Spec file name
pub const SPEC_FILE_NAME: &str = "spec.yaml";

/// Errors from spec operations
#[derive(Debug, Error)]
pub enum SpecError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("YAML parse error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Validation error: {0}")]
    Validation(String),
    #[error("Spec version mismatch: expected {expected}, got {actual}")]
    VersionMismatch { expected: usize, actual: usize },
}

/// Deployment specification for a Lux network cluster
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Spec {
    /// Spec version
    #[serde(default)]
    pub version: usize,

    /// Cluster identifier (user-provided)
    pub id: String,

    /// AAD tag for envelope encryption
    #[serde(default)]
    pub aad_tag: String,

    /// Deployment target
    pub target: DeploymentTarget,

    /// Network configuration
    pub network: NetworkConfig,

    /// Machine/instance configuration
    pub machine: MachineConfig,

    /// Luxd node configuration
    pub luxd_config: LuxdConfig,

    /// C-Chain configuration
    #[serde(default)]
    pub c_chain_config: CChainConfig,

    /// Genesis template (for custom networks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_template: Option<GenesisConfig>,

    /// Pre-funded keys (for testing only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefunded_keys: Option<Vec<KeyInfo>>,

    /// Upload artifacts configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upload_artifacts: Option<UploadArtifacts>,

    /// Luxd release tag to download
    #[serde(skip_serializing_if = "Option::is_none")]
    pub luxd_release_tag: Option<String>,

    /// Created nodes (populated during deployment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_nodes: Option<Vec<NodeInfo>>,

    /// Deployment state
    #[serde(default)]
    pub state: DeploymentState,
}

/// Deployment state tracking
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentState {
    /// Not yet deployed
    #[default]
    Pending,
    /// Infrastructure being created
    Creating,
    /// Nodes bootstrapping
    Bootstrapping,
    /// Cluster is running
    Running,
    /// Cluster is degraded (some nodes down)
    Degraded,
    /// Cluster has failed
    Failed,
    /// Cluster is being deleted
    Deleting,
    /// Cluster has been deleted
    Deleted,
}

impl DeploymentState {
    /// Check if cluster is operational
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }

    /// Check if a deployment operation is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Creating | Self::Bootstrapping | Self::Deleting)
    }

    /// Check if the cluster is in a terminal state
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Failed | Self::Deleted)
    }
}

/// Deployment target (AWS or Kubernetes)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum DeploymentTarget {
    /// AWS deployment
    Aws(AwsConfig),
    /// Kubernetes deployment
    Kubernetes(K8sConfig),
}

impl DeploymentTarget {
    /// Check if this is an AWS deployment
    pub fn is_aws(&self) -> bool {
        matches!(self, Self::Aws(_))
    }

    /// Check if this is a Kubernetes deployment
    pub fn is_k8s(&self) -> bool {
        matches!(self, Self::Kubernetes(_))
    }

    /// Get AWS config if applicable
    pub fn aws(&self) -> Option<&AwsConfig> {
        match self {
            Self::Aws(cfg) => Some(cfg),
            _ => None,
        }
    }

    /// Get Kubernetes config if applicable
    pub fn k8s(&self) -> Option<&K8sConfig> {
        match self {
            Self::Kubernetes(cfg) => Some(cfg),
            _ => None,
        }
    }
}

/// AWS-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AwsConfig {
    /// AWS profile name
    #[serde(default)]
    pub profile_name: String,

    /// AWS regions
    pub regions: Vec<String>,

    /// S3 bucket for artifacts
    pub s3_bucket: String,

    /// Ingress CIDR
    #[serde(default = "default_ingress_cidr")]
    pub ingress_ipv4_cidr: String,

    /// KMS key for encryption
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms_key: Option<KmsKey>,

    /// Regional resources
    #[serde(default)]
    pub regional_resources: BTreeMap<String, RegionalResource>,

    /// Enable NLB
    #[serde(default)]
    pub enable_nlb: bool,

    /// NLB ACM certificate ARNs per region
    #[serde(default)]
    pub nlb_acm_certificate_arns: BTreeMap<String, String>,

    /// Keep resources on delete
    #[serde(default)]
    pub keep_resources: bool,

    /// Disable CloudWatch log auto-removal
    #[serde(default)]
    pub disable_logs_auto_removal: bool,

    /// Metrics fetch interval (seconds, 0 to disable)
    #[serde(default)]
    pub metrics_fetch_interval_seconds: u64,
}

fn default_ingress_cidr() -> String {
    "0.0.0.0/0".to_string()
}

/// KMS key configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct KmsKey {
    pub id: String,
    pub arn: String,
}

/// Regional AWS resource state
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RegionalResource {
    pub region: String,
    pub ec2_key_name: String,
    pub ec2_key_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vpc_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_group_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloudformation_asg_non_anchor: Option<String>,
}

/// Kubernetes-specific configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct K8sConfig {
    /// Kubernetes namespace
    #[serde(default = "default_namespace")]
    pub namespace: String,

    /// Storage class for PVCs
    #[serde(default)]
    pub storage_class: String,

    /// Image repository
    #[serde(default = "default_image_repo")]
    pub image_repository: String,

    /// Image tag
    #[serde(default = "default_image_tag")]
    pub image_tag: String,

    /// Image pull policy
    #[serde(default = "default_pull_policy")]
    pub image_pull_policy: String,

    /// Image pull secrets
    #[serde(default)]
    pub image_pull_secrets: Vec<String>,

    /// Service account name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_account: Option<String>,

    /// Pod security context
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_context: Option<serde_json::Value>,

    /// Use Lux MPC for key management
    #[serde(default)]
    pub use_lux_mpc: bool,

    /// Lux MPC endpoint
    #[serde(skip_serializing_if = "Option::is_none")]
    pub lux_mpc_endpoint: Option<String>,

    /// Enable metrics (Prometheus)
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    /// Metrics port
    #[serde(default = "default_metrics_port")]
    pub metrics_port: u16,
}

fn default_namespace() -> String {
    "lux".to_string()
}

fn default_image_repo() -> String {
    "ghcr.io/luxfi/luxd".to_string()
}

fn default_image_tag() -> String {
    "latest".to_string()
}

fn default_pull_policy() -> String {
    "IfNotPresent".to_string()
}

fn default_metrics_port() -> u16 {
    9090
}

fn default_true() -> bool {
    true
}

/// Network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NetworkConfig {
    /// Network ID
    pub network_id: NetworkId,

    /// Number of anchor/beacon nodes
    #[serde(default)]
    pub anchor_nodes: u32,

    /// Number of non-anchor nodes
    #[serde(default)]
    pub non_anchor_nodes: u32,

    /// Primary network validation period (days)
    #[serde(default = "default_validate_period")]
    pub validate_period_in_days: u64,
}

fn default_validate_period() -> u64 {
    365
}

impl NetworkConfig {
    /// Total number of nodes
    pub fn total_nodes(&self) -> u32 {
        self.anchor_nodes + self.non_anchor_nodes
    }
}

/// Machine/instance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MachineConfig {
    /// Machine architecture
    #[serde(default = "default_arch")]
    pub arch: String,

    /// Operating system
    #[serde(default = "default_os")]
    pub os: String,

    /// Instance types per region
    #[serde(default)]
    pub instance_types: BTreeMap<String, Vec<String>>,

    /// Volume size (GB) for anchor nodes
    #[serde(default = "default_anchor_volume")]
    pub anchor_volume_size_gb: u32,

    /// Volume size (GB) for non-anchor nodes
    #[serde(default = "default_non_anchor_volume")]
    pub non_anchor_volume_size_gb: u32,

    /// Volume type (e.g., gp3)
    #[serde(default = "default_volume_type")]
    pub volume_type: String,

    /// Volume IOPS
    #[serde(default = "default_volume_iops")]
    pub volume_iops: u32,

    /// Volume throughput (MB/s)
    #[serde(default = "default_volume_throughput")]
    pub volume_throughput: u32,
}

fn default_arch() -> String {
    "amd64".to_string()
}

fn default_os() -> String {
    "ubuntu22.04".to_string()
}

fn default_anchor_volume() -> u32 {
    400
}

fn default_non_anchor_volume() -> u32 {
    300
}

fn default_volume_type() -> String {
    "gp3".to_string()
}

fn default_volume_iops() -> u32 {
    3000
}

fn default_volume_throughput() -> u32 {
    125
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            arch: default_arch(),
            os: default_os(),
            instance_types: BTreeMap::new(),
            anchor_volume_size_gb: default_anchor_volume(),
            non_anchor_volume_size_gb: default_non_anchor_volume(),
            volume_type: default_volume_type(),
            volume_iops: default_volume_iops(),
            volume_throughput: default_volume_throughput(),
        }
    }
}

/// Artifacts to upload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct UploadArtifacts {
    /// Path to luxd binary
    #[serde(skip_serializing_if = "Option::is_none")]
    pub luxd_bin: Option<PathBuf>,

    /// Path to plugins directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugins_dir: Option<PathBuf>,

    /// VM binaries to upload
    #[serde(default)]
    pub vm_binaries: Vec<VmBinary>,
}

/// VM binary to upload
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct VmBinary {
    /// VM ID
    pub vm_id: String,
    /// Path to binary
    pub path: PathBuf,
}

impl Spec {
    /// Create a new spec with defaults
    pub fn new(id: String, target: DeploymentTarget) -> Self {
        Self {
            version: SPEC_VERSION,
            id,
            aad_tag: String::new(),
            target,
            network: NetworkConfig {
                network_id: NetworkId::LOCAL,
                anchor_nodes: 1,
                non_anchor_nodes: 2,
                validate_period_in_days: default_validate_period(),
            },
            machine: MachineConfig::default(),
            luxd_config: LuxdConfig::default(),
            c_chain_config: CChainConfig::default(),
            genesis_template: None,
            prefunded_keys: None,
            upload_artifacts: None,
            luxd_release_tag: None,
            created_nodes: None,
            state: DeploymentState::default(),
        }
    }

    /// Load spec from file
    pub fn load(path: &Path) -> Result<Self, SpecError> {
        let contents = std::fs::read_to_string(path)?;
        let spec: Self = serde_yaml::from_str(&contents)?;
        Ok(spec)
    }

    /// Load spec from a directory (looks for spec.yaml)
    pub fn load_from_dir(dir: &Path) -> Result<Self, SpecError> {
        Self::load(&dir.join(SPEC_FILE_NAME))
    }

    /// Save spec to file
    pub fn save(&self, path: &Path) -> Result<(), SpecError> {
        let contents = serde_yaml::to_string(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Save spec to a directory (saves as spec.yaml)
    pub fn save_to_dir(&self, dir: &Path) -> Result<(), SpecError> {
        std::fs::create_dir_all(dir)?;
        self.save(&dir.join(SPEC_FILE_NAME))
    }

    /// Validate the spec
    pub fn validate(&self) -> Result<(), SpecError> {
        // Check version
        if self.version > SPEC_VERSION {
            return Err(SpecError::VersionMismatch {
                expected: SPEC_VERSION,
                actual: self.version,
            });
        }

        // Check cluster ID
        if self.id.is_empty() {
            return Err(SpecError::Validation(
                "cluster id cannot be empty".to_string(),
            ));
        }

        if !self
            .id
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
        {
            return Err(SpecError::Validation(
                "cluster id must be alphanumeric with dashes or underscores".to_string(),
            ));
        }

        // Check network config
        if self.network.anchor_nodes == 0 && self.network.non_anchor_nodes == 0 {
            return Err(SpecError::Validation(
                "at least one node (anchor or non-anchor) is required".to_string(),
            ));
        }

        // Check target-specific config
        match &self.target {
            DeploymentTarget::Aws(aws) => {
                if aws.regions.is_empty() {
                    return Err(SpecError::Validation(
                        "at least one AWS region is required".to_string(),
                    ));
                }
                if aws.s3_bucket.is_empty() {
                    return Err(SpecError::Validation(
                        "S3 bucket name is required".to_string(),
                    ));
                }
            }
            DeploymentTarget::Kubernetes(k8s) => {
                if k8s.namespace.is_empty() {
                    return Err(SpecError::Validation(
                        "Kubernetes namespace is required".to_string(),
                    ));
                }
            }
        }

        Ok(())
    }

    /// Update state and save
    pub fn set_state(&mut self, state: DeploymentState) {
        self.state = state;
    }

    /// Add a created node
    pub fn add_node(&mut self, node: NodeInfo) {
        self.created_nodes.get_or_insert_with(Vec::new).push(node);
    }

    /// Get anchor nodes
    pub fn anchor_nodes(&self) -> Vec<&NodeInfo> {
        self.created_nodes
            .as_ref()
            .map(|nodes| nodes.iter().filter(|n| n.is_anchor).collect())
            .unwrap_or_default()
    }

    /// Get non-anchor nodes
    pub fn non_anchor_nodes(&self) -> Vec<&NodeInfo> {
        self.created_nodes
            .as_ref()
            .map(|nodes| nodes.iter().filter(|n| !n.is_anchor).collect())
            .unwrap_or_default()
    }

    /// Get bootstrap IPs string for luxd config
    pub fn bootstrap_ips(&self) -> Option<String> {
        let anchors = self.anchor_nodes();
        if anchors.is_empty() {
            return None;
        }
        let ips: Vec<String> = anchors
            .iter()
            .map(|n| format!("{}:{}", n.public_ip, n.staking_port))
            .collect();
        Some(ips.join(","))
    }

    /// Get bootstrap IDs string for luxd config
    pub fn bootstrap_ids(&self) -> Option<String> {
        let anchors = self.anchor_nodes();
        if anchors.is_empty() {
            return None;
        }
        let ids: Vec<String> = anchors.iter().map(|n| n.node_id.clone()).collect();
        Some(ids.join(","))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_test_spec() -> Spec {
        Spec::new(
            "test-cluster".to_string(),
            DeploymentTarget::Aws(AwsConfig {
                profile_name: String::new(),
                regions: vec!["us-west-2".to_string()],
                s3_bucket: "test-bucket".to_string(),
                ingress_ipv4_cidr: "0.0.0.0/0".to_string(),
                kms_key: None,
                regional_resources: BTreeMap::new(),
                enable_nlb: false,
                nlb_acm_certificate_arns: BTreeMap::new(),
                keep_resources: false,
                disable_logs_auto_removal: false,
                metrics_fetch_interval_seconds: 0,
            }),
        )
    }

    #[test]
    fn test_spec_new() {
        let spec = make_test_spec();
        assert_eq!(spec.version, SPEC_VERSION);
        assert_eq!(spec.id, "test-cluster");
        assert!(spec.target.is_aws());
    }

    #[test]
    fn test_spec_validate_valid() {
        let spec = make_test_spec();
        assert!(spec.validate().is_ok());
    }

    #[test]
    fn test_spec_validate_empty_id() {
        let mut spec = make_test_spec();
        spec.id = String::new();
        let result = spec.validate();
        assert!(result.is_err());
        assert!(matches!(result, Err(SpecError::Validation(_))));
    }

    #[test]
    fn test_spec_validate_invalid_id() {
        let mut spec = make_test_spec();
        spec.id = "invalid id!".to_string();
        let result = spec.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_spec_validate_no_nodes() {
        let mut spec = make_test_spec();
        spec.network.anchor_nodes = 0;
        spec.network.non_anchor_nodes = 0;
        let result = spec.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_spec_save_load() {
        let spec = make_test_spec();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spec.yaml");

        spec.save(&path).unwrap();
        let loaded = Spec::load(&path).unwrap();

        assert_eq!(spec.id, loaded.id);
        assert_eq!(spec.version, loaded.version);
    }

    #[test]
    fn test_spec_save_load_dir() {
        let spec = make_test_spec();
        let dir = tempfile::tempdir().unwrap();

        spec.save_to_dir(dir.path()).unwrap();
        let loaded = Spec::load_from_dir(dir.path()).unwrap();

        assert_eq!(spec.id, loaded.id);
    }

    #[test]
    fn test_deployment_state() {
        assert!(DeploymentState::Running.is_operational());
        assert!(DeploymentState::Degraded.is_operational());
        assert!(!DeploymentState::Pending.is_operational());

        assert!(DeploymentState::Creating.is_in_progress());
        assert!(DeploymentState::Deleting.is_in_progress());
        assert!(!DeploymentState::Running.is_in_progress());

        assert!(DeploymentState::Failed.is_terminal());
        assert!(DeploymentState::Deleted.is_terminal());
        assert!(!DeploymentState::Running.is_terminal());
    }

    #[test]
    fn test_network_config_total_nodes() {
        let config = NetworkConfig {
            network_id: NetworkId::LOCAL,
            anchor_nodes: 3,
            non_anchor_nodes: 7,
            validate_period_in_days: 365,
        };
        assert_eq!(config.total_nodes(), 10);
    }

    #[test]
    fn test_add_and_get_nodes() {
        let mut spec = make_test_spec();

        spec.add_node(NodeInfo {
            machine_id: "i-001".to_string(),
            node_id: "NodeID-anchor1".to_string(),
            public_ip: "1.2.3.4".to_string(),
            http_port: 9650,
            staking_port: 9651,
            region: "us-west-2".to_string(),
            is_anchor: true,
        });

        spec.add_node(NodeInfo {
            machine_id: "i-002".to_string(),
            node_id: "NodeID-node1".to_string(),
            public_ip: "1.2.3.5".to_string(),
            http_port: 9650,
            staking_port: 9651,
            region: "us-west-2".to_string(),
            is_anchor: false,
        });

        assert_eq!(spec.anchor_nodes().len(), 1);
        assert_eq!(spec.non_anchor_nodes().len(), 1);
        assert_eq!(spec.bootstrap_ips(), Some("1.2.3.4:9651".to_string()));
        assert_eq!(spec.bootstrap_ids(), Some("NodeID-anchor1".to_string()));
    }
}
