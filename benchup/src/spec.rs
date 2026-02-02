//! Blizzard deployment specification

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

pub const SPEC_VERSION: usize = 1;

/// Load test type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TestType {
    /// X-Chain UTXO transactions
    XChain,
    /// C-Chain EVM transactions
    CChainEvm,
}

impl Default for TestType {
    fn default() -> Self {
        Self::CChainEvm
    }
}

impl std::str::FromStr for TestType {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "x-chain" | "xchain" => Ok(Self::XChain),
            "c-chain-evm" | "cchain" | "evm" => Ok(Self::CChainEvm),
            _ => Err(anyhow::anyhow!("unknown test type: {}", s)),
        }
    }
}

/// Instance mode for EC2
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum InstanceMode {
    #[default]
    Spot,
    OnDemand,
}

/// Blizzard deployment specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct BlizzardSpec {
    /// Spec version
    #[serde(default)]
    pub version: usize,

    /// Unique deployment identifier
    pub id: String,

    /// AWS configuration
    pub aws: AwsConfig,

    /// Load test configuration
    pub load_test: LoadTestConfig,

    /// Machine configuration
    #[serde(default)]
    pub machine: MachineConfig,

    /// Deployment state (populated during apply)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<DeploymentState>,
}

/// AWS configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AwsConfig {
    /// AWS profile name (empty for default)
    #[serde(default)]
    pub profile_name: String,

    /// AWS regions for deployment
    pub regions: Vec<String>,

    /// S3 bucket for artifacts
    pub s3_bucket: String,

    /// Ingress CIDR for SSH
    #[serde(default = "default_ingress_cidr")]
    pub ingress_ipv4_cidr: String,

    /// EC2 key pair name per region
    #[serde(default)]
    pub ec2_key_names: BTreeMap<String, String>,

    /// Keep resources on delete
    #[serde(default)]
    pub keep_resources: bool,
}

fn default_ingress_cidr() -> String {
    "0.0.0.0/0".to_string()
}

/// Load test configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LoadTestConfig {
    /// Number of blizzard instances per region
    pub instances_per_region: u32,

    /// Target RPC endpoints
    pub rpc_endpoints: Vec<String>,

    /// Transactions per second target per instance
    #[serde(default = "default_tps")]
    pub tps_per_instance: u32,

    /// Number of worker tasks per instance
    #[serde(default = "default_workers")]
    pub workers_per_instance: u32,

    /// Test duration in seconds
    #[serde(default = "default_duration")]
    pub duration_seconds: u64,

    /// Test type
    #[serde(default)]
    pub test_type: TestType,

    /// Auto-start load test on instance launch
    #[serde(default = "default_true")]
    pub auto_start: bool,
}

fn default_tps() -> u32 {
    100
}

fn default_workers() -> u32 {
    10
}

fn default_duration() -> u64 {
    300
}

fn default_true() -> bool {
    true
}

/// Machine/instance configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct MachineConfig {
    /// Instance types (prioritized list)
    #[serde(default = "default_instance_types")]
    pub instance_types: Vec<String>,

    /// Instance mode (spot or on-demand)
    #[serde(default)]
    pub instance_mode: InstanceMode,

    /// Architecture (amd64 or arm64)
    #[serde(default = "default_arch")]
    pub arch: String,

    /// OS type
    #[serde(default = "default_os")]
    pub os: String,

    /// Volume size in GB
    #[serde(default = "default_volume_size")]
    pub volume_size_gb: u32,
}

fn default_instance_types() -> Vec<String> {
    vec![
        "c6a.xlarge".to_string(),
        "m6a.xlarge".to_string(),
        "m5.xlarge".to_string(),
        "c5.xlarge".to_string(),
    ]
}

fn default_arch() -> String {
    "amd64".to_string()
}

fn default_os() -> String {
    "ubuntu20.04".to_string()
}

fn default_volume_size() -> u32 {
    8
}

impl Default for MachineConfig {
    fn default() -> Self {
        Self {
            instance_types: default_instance_types(),
            instance_mode: InstanceMode::default(),
            arch: default_arch(),
            os: default_os(),
            volume_size_gb: default_volume_size(),
        }
    }
}

/// Deployment state (populated during apply)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct DeploymentState {
    /// CloudFormation stack names per region
    #[serde(default)]
    pub cloudformation_stacks: BTreeMap<String, RegionalStacks>,

    /// Instance IDs per region
    #[serde(default)]
    pub instance_ids: BTreeMap<String, Vec<String>>,

    /// S3 blizzard binary path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub s3_blizzard_path: Option<String>,

    /// Deployment timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deployed_at: Option<String>,
}

/// Regional CloudFormation stacks
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct RegionalStacks {
    pub vpc_stack: Option<String>,
    pub iam_stack: Option<String>,
    pub asg_stack: Option<String>,
}

impl BlizzardSpec {
    /// Create a new spec with defaults
    pub fn new(id: String, regions: Vec<String>, s3_bucket: String) -> Self {
        Self {
            version: SPEC_VERSION,
            id,
            aws: AwsConfig {
                profile_name: String::new(),
                regions,
                s3_bucket,
                ingress_ipv4_cidr: default_ingress_cidr(),
                ec2_key_names: BTreeMap::new(),
                keep_resources: false,
            },
            load_test: LoadTestConfig {
                instances_per_region: 1,
                rpc_endpoints: vec![],
                tps_per_instance: default_tps(),
                workers_per_instance: default_workers(),
                duration_seconds: default_duration(),
                test_type: TestType::default(),
                auto_start: true,
            },
            machine: MachineConfig::default(),
            state: None,
        }
    }

    /// Load spec from file
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let spec: Self = serde_yaml::from_str(&contents)?;
        Ok(spec)
    }

    /// Save spec to file
    pub fn save(&self, path: &Path) -> anyhow::Result<()> {
        let contents = serde_yaml::to_string(self)?;
        std::fs::write(path, contents)?;
        Ok(())
    }

    /// Total number of instances across all regions
    pub fn total_instances(&self) -> u32 {
        self.load_test.instances_per_region * self.aws.regions.len() as u32
    }

    /// Aggregate target TPS
    pub fn aggregate_tps(&self) -> u32 {
        self.total_instances() * self.load_test.tps_per_instance
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_spec_roundtrip() {
        let spec = BlizzardSpec::new(
            "test-blizzard".to_string(),
            vec!["us-west-2".to_string()],
            "test-bucket".to_string(),
        );

        let yaml = serde_yaml::to_string(&spec).unwrap();
        let loaded: BlizzardSpec = serde_yaml::from_str(&yaml).unwrap();

        assert_eq!(spec.id, loaded.id);
        assert_eq!(spec.aws.regions, loaded.aws.regions);
    }

    #[test]
    fn test_total_instances() {
        let mut spec = BlizzardSpec::new(
            "test".to_string(),
            vec!["us-west-2".to_string(), "us-east-1".to_string()],
            "bucket".to_string(),
        );
        spec.load_test.instances_per_region = 3;

        assert_eq!(spec.total_instances(), 6);
    }

    #[test]
    fn test_aggregate_tps() {
        let mut spec = BlizzardSpec::new(
            "test".to_string(),
            vec!["us-west-2".to_string()],
            "bucket".to_string(),
        );
        spec.load_test.instances_per_region = 5;
        spec.load_test.tps_per_instance = 100;

        assert_eq!(spec.aggregate_tps(), 500);
    }
}
