//! Custom Resource Definitions for Lux Network

use k8s_openapi::apimachinery::pkg::apis::meta::v1::Condition;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// LuxNetwork is the primary CRD for deploying a Lux network cluster
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxNetwork",
    namespaced,
    status = "LuxNetworkStatus",
    shortname = "luxnet",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.readyValidators"}"#,
    printcolumn = r#"{"name":"Total","type":"string","jsonPath":".status.totalValidators"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LuxNetworkSpec {
    /// Network ID (1=mainnet, 5=testnet, custom)
    pub network_id: u32,

    /// Number of validator nodes
    pub validators: u32,

    /// Image configuration
    #[serde(default)]
    pub image: ImageSpec,

    /// Storage configuration
    #[serde(default)]
    pub storage: StorageSpec,

    /// Resource requirements
    #[serde(default)]
    pub resources: ResourceSpec,

    /// Luxd configuration overrides
    #[serde(default)]
    pub config: BTreeMap<String, serde_json::Value>,

    /// Genesis configuration (for custom networks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<serde_json::Value>,

    /// Lux MPC configuration for key management
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc: Option<MpcSpec>,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsSpec,

    /// Service configuration
    #[serde(default)]
    pub service: ServiceSpec,

    /// Chain tracking configuration
    #[serde(default)]
    pub chain_tracking: ChainTrackingSpec,

    /// Snapshot configuration for fast bootstrap
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<SnapshotSpec>,

    /// RLP import configuration for C-chain bootstrap
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rlp_import: Option<RlpImportSpec>,
}

/// Image configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ImageSpec {
    /// Image repository
    #[serde(default = "default_image_repo")]
    pub repository: String,

    /// Image tag
    #[serde(default = "default_image_tag")]
    pub tag: String,

    /// Image pull policy
    #[serde(default = "default_pull_policy")]
    pub pull_policy: String,

    /// Image pull secrets
    #[serde(default)]
    pub pull_secrets: Vec<String>,
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

/// Storage configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    /// Storage class name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Storage size
    #[serde(default = "default_storage_size")]
    pub size: String,
}

fn default_storage_size() -> String {
    "200Gi".to_string()
}

/// Resource requirements
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ResourceSpec {
    /// CPU request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_request: Option<String>,

    /// CPU limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_limit: Option<String>,

    /// Memory request
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_request: Option<String>,

    /// Memory limit
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<String>,
}

/// Lux MPC configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MpcSpec {
    /// Enable MPC key management
    #[serde(default)]
    pub enabled: bool,

    /// MPC endpoint URL
    pub endpoint: String,

    /// Secret containing MPC authentication credentials
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_secret_ref: Option<String>,

    /// Use threshold signatures
    #[serde(default)]
    pub use_tss: bool,

    /// TSS threshold
    #[serde(skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,

    /// TSS total parties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parties: Option<u32>,
}

/// Metrics configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSpec {
    /// Enable metrics
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics port
    #[serde(default = "default_metrics_port")]
    pub port: u16,

    /// Create ServiceMonitor for Prometheus Operator
    #[serde(default)]
    pub service_monitor: bool,
}

fn default_true() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

/// Service configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Service type
    #[serde(default = "default_service_type")]
    pub service_type: String,

    /// Additional annotations
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,

    /// Enable ingress
    #[serde(default)]
    pub ingress_enabled: bool,

    /// Ingress host
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_host: Option<String>,
}

fn default_service_type() -> String {
    "ClusterIP".to_string()
}

/// Chain tracking configuration
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainTrackingSpec {
    /// Track all chains automatically (for testnet/devnet)
    #[serde(default)]
    pub track_all_chains: bool,

    /// Specific chain IDs to track (for mainnet)
    #[serde(default)]
    pub tracked_chains: Vec<String>,

    /// Chain aliases to register (e.g., "zoo", "hanzo", "spc")
    #[serde(default)]
    pub aliases: Vec<String>,
}

/// Snapshot configuration for fast node bootstrap
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotSpec {
    /// Enable snapshot restore on pod init
    #[serde(default)]
    pub enabled: bool,

    /// URL to download snapshot archive (tar.zst)
    pub url: String,

    /// Expected snapshot size in bytes (for progress display)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_size: Option<u64>,

    /// Skip snapshot if data directory already has state
    #[serde(default = "default_true")]
    pub skip_if_exists: bool,
}

/// RLP import configuration for C-chain block data
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RlpImportSpec {
    /// Enable RLP import after node startup
    #[serde(default)]
    pub enabled: bool,

    /// Base URL for RLP file download
    pub base_url: String,

    /// RLP filename (e.g., "lux-mainnet-96369.rlp")
    pub filename: String,

    /// Use multi-part download (e.g., .part.aa, .part.ab, ...)
    #[serde(default)]
    pub multi_part: bool,

    /// Part suffixes for multi-part download
    #[serde(default)]
    pub parts: Vec<String>,

    /// Minimum block height to trigger import (skip if already above)
    #[serde(default = "default_min_height")]
    pub min_height: u64,

    /// Import timeout in seconds
    #[serde(default = "default_import_timeout")]
    pub timeout: u64,
}

fn default_min_height() -> u64 {
    1
}

fn default_import_timeout() -> u64 {
    7200
}

/// Status of a LuxNetwork
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxNetworkStatus {
    /// Current phase
    #[serde(default)]
    pub phase: String,

    /// Ready validator count
    #[serde(default)]
    pub ready_validators: u32,

    /// Total validator count
    #[serde(default)]
    pub total_validators: u32,

    /// Network ID (assigned after creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<u32>,

    /// Bootstrap node endpoints
    #[serde(default)]
    pub bootstrap_endpoints: Vec<String>,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,

    /// Last reconciled generation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// LuxSubnet CRD for subnet deployments
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxSubnet",
    namespaced,
    status = "LuxSubnetStatus",
    shortname = "luxsub"
)]
#[serde(rename_all = "camelCase")]
pub struct LuxSubnetSpec {
    /// Reference to parent LuxNetwork
    pub network_ref: String,

    /// Subnet ID (if joining existing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,

    /// Validators for this subnet
    #[serde(default)]
    pub validators: Vec<SubnetValidator>,

    /// VM configuration
    pub vm: VmSpec,
}

/// Subnet validator reference
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SubnetValidator {
    /// Node ID
    pub node_id: String,
    /// Stake weight
    #[serde(default = "default_weight")]
    pub weight: u64,
}

fn default_weight() -> u64 {
    100
}

/// VM specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct VmSpec {
    /// VM type (subnet-evm, etc.)
    pub vm_type: String,

    /// VM binary URL (for custom VMs)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_url: Option<String>,

    /// Genesis configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<serde_json::Value>,

    /// Chain config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_config: Option<serde_json::Value>,
}

/// Status of a LuxSubnet
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxSubnetStatus {
    /// Subnet ID (assigned after creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,

    /// Chain ID (assigned after creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,

    /// Current phase
    #[serde(default)]
    pub phase: String,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}
