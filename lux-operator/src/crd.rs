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
    /// Network ID (1=mainnet, 2=testnet, 3=devnet, custom)
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

    /// Genesis ConfigMap name (for pre-existing genesis)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis_config_map: Option<String>,

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

    /// Port configuration
    #[serde(default)]
    pub ports: PortSpec,

    /// Staking key configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking: Option<StakingSpec>,

    /// Init container configuration for plugins/setup
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<InitSpec>,

    /// Startup script ConfigMap name (custom entrypoint, overrides generated script)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub startup_script: Option<String>,

    /// Security context configuration
    #[serde(default)]
    pub security: SecuritySpec,

    /// Adopt existing resources (don't recreate StatefulSet, etc.)
    #[serde(default)]
    pub adopt_existing: bool,

    /// Chain references (blockchain IDs for EVM config + chain tracking)
    #[serde(default)]
    pub chains: Vec<ChainRef>,

    /// Consensus configuration
    #[serde(default)]
    pub consensus: ConsensusSpec,

    /// Database type (zapdb, pebbledb, memdb)
    #[serde(default = "default_db_type")]
    pub db_type: String,

    /// Upgrade config JSON (base64-encoded at runtime for --upgrade-file-content)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub upgrade_config: Option<serde_json::Value>,

    /// EVM chain config applied to C-chain and other chains
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evm_config: Option<serde_json::Value>,

    /// Gateway integration configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<GatewaySpec>,

    /// Bootstrap configuration
    #[serde(default)]
    pub bootstrap: BootstrapSpec,

    /// API configuration
    #[serde(default)]
    pub api: ApiSpec,

    /// Network compression type (zstd, none)
    #[serde(default = "default_compression")]
    pub network_compression_type: String,

    /// Chain aliases (blockchain_id -> [alias1, alias2, ...]), emitted as --chain-aliases-file-content
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_aliases: Option<BTreeMap<String, Vec<String>>>,

    /// Path to RLP file for built-in C-chain import via --import-chain-data
    #[serde(skip_serializing_if = "Option::is_none")]
    pub import_chain_data: Option<String>,

    /// Health policy for degraded detection
    #[serde(default)]
    pub health_policy: HealthPolicy,

    /// Upgrade strategy for pod rollouts
    #[serde(default)]
    pub upgrade_strategy: UpgradeStrategy,

    /// Seed/snapshot restore configuration for fast bootstrap
    #[serde(default)]
    pub seed_restore: SeedRestoreSpec,

    /// Automated snapshot schedule configuration
    #[serde(default)]
    pub snapshot_schedule: SnapshotScheduleSpec,

    /// Startup gating: wait for peers before starting luxd
    #[serde(default)]
    pub startup_gate: StartupGateSpec,

    /// Allow removing validator pods when scaling down (must be explicit)
    #[serde(default)]
    pub allow_validator_removal: bool,
}

fn default_db_type() -> String {
    "zapdb".to_string()
}

fn default_compression() -> String {
    "zstd".to_string()
}

/// Health policy for detecting degraded states
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct HealthPolicy {
    /// Require inbound validator connections (false = allow outbound-only in small clusters)
    #[serde(default)]
    pub require_inbound_validators: bool,

    /// Minimum inbound peer connections before marking degraded
    #[serde(default = "default_min_inbound")]
    pub min_inbound: u32,

    /// Grace period (seconds) after pod start before enforcing peer requirements
    #[serde(default = "default_health_grace")]
    pub grace_period_seconds: u64,

    /// Maximum allowed P-chain height skew between nodes before marking degraded
    #[serde(default = "default_max_height_skew")]
    pub max_height_skew: u64,

    /// Health check interval in seconds
    #[serde(default = "default_health_interval")]
    pub check_interval_seconds: u64,
}

impl Default for HealthPolicy {
    fn default() -> Self {
        Self {
            require_inbound_validators: false,
            min_inbound: default_min_inbound(),
            grace_period_seconds: default_health_grace(),
            max_height_skew: default_max_height_skew(),
            check_interval_seconds: default_health_interval(),
        }
    }
}

fn default_min_inbound() -> u32 {
    1
}

fn default_health_grace() -> u64 {
    300
}

fn default_max_height_skew() -> u64 {
    10
}

fn default_health_interval() -> u64 {
    60
}

/// Upgrade strategy for controlled rollouts
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct UpgradeStrategy {
    /// Strategy type: OnDelete (safest) or RollingCanary (automated with health checks)
    #[serde(default = "default_upgrade_type")]
    pub strategy_type: String,

    /// Maximum pods unavailable during rolling canary (default 1)
    #[serde(default = "default_max_unavailable")]
    pub max_unavailable: u32,

    /// Require network health check between each pod restart (for RollingCanary)
    #[serde(default = "default_true")]
    pub health_check_between_restarts: bool,

    /// Seconds to wait after pod becomes ready before proceeding to next (for RollingCanary)
    #[serde(default = "default_stabilization_seconds")]
    pub stabilization_seconds: u64,
}

impl Default for UpgradeStrategy {
    fn default() -> Self {
        Self {
            strategy_type: default_upgrade_type(),
            max_unavailable: default_max_unavailable(),
            health_check_between_restarts: true,
            stabilization_seconds: default_stabilization_seconds(),
        }
    }
}

fn default_upgrade_type() -> String {
    "OnDelete".to_string()
}

fn default_max_unavailable() -> u32 {
    1
}

fn default_stabilization_seconds() -> u64 {
    60
}

/// Seed/snapshot restore configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SeedRestoreSpec {
    /// Enable seed restore on pod init
    #[serde(default)]
    pub enabled: bool,

    /// Seed source type: VolumeSnapshot, PVCClone, ObjectStore, None
    #[serde(default = "default_seed_source")]
    pub source_type: String,

    /// Object store URL for tarball download (when source_type=ObjectStore)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub object_store_url: Option<String>,

    /// VolumeSnapshot name to clone from (when source_type=VolumeSnapshot)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_snapshot_name: Option<String>,

    /// Donor PVC name to clone from (when source_type=PVCClone)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub donor_pvc_name: Option<String>,

    /// Restore policy: IfNotSeeded (default) or Always
    #[serde(default = "default_restore_policy")]
    pub restore_policy: String,

    /// Marker file path to track seed completion
    #[serde(default = "default_marker_path")]
    pub marker_path: String,
}

impl Default for SeedRestoreSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            source_type: default_seed_source(),
            object_store_url: None,
            volume_snapshot_name: None,
            donor_pvc_name: None,
            restore_policy: default_restore_policy(),
            marker_path: default_marker_path(),
        }
    }
}

fn default_seed_source() -> String {
    "None".to_string()
}

fn default_restore_policy() -> String {
    "IfNotSeeded".to_string()
}

fn default_marker_path() -> String {
    "/data/.seeded".to_string()
}

/// Startup gating configuration: wait for peers before starting luxd
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StartupGateSpec {
    /// Enable startup gating (wait for peers)
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Minimum peers that must be TCP-reachable before starting
    #[serde(default = "default_min_peers")]
    pub min_peers: u32,

    /// Wait for at least one peer to report healthy via /ext/health (slower but safer)
    #[serde(default)]
    pub wait_for_healthy_peer: bool,

    /// Maximum seconds to wait for peers before timeout action
    #[serde(default = "default_gate_timeout")]
    pub timeout_seconds: u64,

    /// Seconds between peer check attempts
    #[serde(default = "default_gate_interval")]
    pub check_interval_seconds: u64,

    /// Action on timeout: "Fail" (exit 1, pod restarts) or "StartAnyway" (proceed without peers).
    /// Default is Fail — prevents bootstrap-at-height-0 race condition.
    #[serde(default = "default_on_timeout")]
    pub on_timeout: String,
}

impl Default for StartupGateSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            min_peers: default_min_peers(),
            wait_for_healthy_peer: false,
            timeout_seconds: default_gate_timeout(),
            check_interval_seconds: default_gate_interval(),
            on_timeout: default_on_timeout(),
        }
    }
}

fn default_on_timeout() -> String {
    "Fail".to_string()
}

fn default_min_peers() -> u32 {
    2
}

fn default_gate_timeout() -> u64 {
    300
}

fn default_gate_interval() -> u64 {
    5
}

/// Reference to a deployed chain
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainRef {
    /// Blockchain ID (base58-encoded, from createBlockchain TX)
    pub blockchain_id: String,
    /// Human-readable alias (e.g., "zoo", "hanzo", "spc", "pars")
    pub alias: String,
    /// Chain tracking ID (for --track-chains; on mainnet this differs from blockchain ID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tracking_id: Option<String>,
}

/// Consensus configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConsensusSpec {
    /// Snow sample size
    #[serde(default = "default_sample_size")]
    pub sample_size: u32,

    /// Snow quorum size
    #[serde(default = "default_quorum_size")]
    pub quorum_size: u32,

    /// Enable sybil protection (required for networkID 1 and 2)
    #[serde(default)]
    pub sybil_protection_enabled: bool,

    /// Require validators to connect
    #[serde(default)]
    pub require_validator_to_connect: bool,

    /// Allow private IPs for P2P
    #[serde(default = "default_true")]
    pub allow_private_ips: bool,
}

impl Default for ConsensusSpec {
    fn default() -> Self {
        Self {
            sample_size: default_sample_size(),
            quorum_size: default_quorum_size(),
            sybil_protection_enabled: false,
            require_validator_to_connect: false,
            allow_private_ips: true,
        }
    }
}

fn default_sample_size() -> u32 {
    5
}

fn default_quorum_size() -> u32 {
    4
}

/// Bootstrap configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BootstrapSpec {
    /// Use internal K8s DNS hostnames for bootstrap (recommended)
    #[serde(default = "default_true")]
    pub use_hostnames: bool,

    /// Static external IPs for bootstrap (overrides LB discovery)
    #[serde(default)]
    pub external_ips: Vec<String>,
}

impl Default for BootstrapSpec {
    fn default() -> Self {
        Self {
            use_hostnames: true,
            external_ips: vec![],
        }
    }
}

/// API configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ApiSpec {
    /// Enable admin API
    #[serde(default = "default_true")]
    pub admin_enabled: bool,

    /// Enable metrics API
    #[serde(default = "default_true")]
    pub metrics_enabled: bool,

    /// Enable index API
    #[serde(default = "default_true")]
    pub index_enabled: bool,

    /// Allowed HTTP hosts
    #[serde(default = "default_http_allowed_hosts")]
    pub http_allowed_hosts: String,
}

impl Default for ApiSpec {
    fn default() -> Self {
        Self {
            admin_enabled: true,
            metrics_enabled: true,
            index_enabled: true,
            http_allowed_hosts: default_http_allowed_hosts(),
        }
    }
}

fn default_http_allowed_hosts() -> String {
    "*".to_string()
}

/// Gateway integration configuration (for KrakenD or similar)
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewaySpec {
    /// ConfigMap name for gateway config output
    pub config_map: String,
    /// Auto-generate gateway routes for all chains
    #[serde(default)]
    pub auto_routes: bool,
    /// Host for gateway ingress
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
}

/// Port configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PortSpec {
    /// HTTP/RPC port
    #[serde(default = "default_http_port")]
    pub http: i32,

    /// Staking/P2P port
    #[serde(default = "default_staking_port")]
    pub staking: i32,
}

impl Default for PortSpec {
    fn default() -> Self {
        Self {
            http: default_http_port(),
            staking: default_staking_port(),
        }
    }
}

fn default_http_port() -> i32 {
    9650
}

fn default_staking_port() -> i32 {
    9651
}

/// Staking key configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct StakingSpec {
    /// Secret name containing staking keys (staker-{idx}.crt, staker-{idx}.key, signer-{idx}.key).
    /// When using KMS, this is the target secret name that KMS will sync into.
    pub secret_name: String,

    /// KMS configuration for syncing staking keys from Hanzo KMS.
    /// When set, the operator creates a KMSSecret resource that syncs
    /// staking keys from KMS into the K8s Secret named by secret_name.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kms: Option<KmsStakingSpec>,
}

/// KMS-backed staking key management via Hanzo KMS (secrets.lux.network/v1alpha1 KMSSecret)
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsStakingSpec {
    /// KMS API endpoint (e.g., "https://kms.lux.network/api")
    #[serde(default = "default_kms_host")]
    pub host_api: String,

    /// KMS project slug (e.g., "lux-infra")
    pub project_slug: String,

    /// KMS environment slug (e.g., "mainnet", "testnet", "devnet")
    pub env_slug: String,

    /// Path within the KMS project for staking secrets (e.g., "/staking")
    #[serde(default = "default_kms_staking_path")]
    pub secrets_path: String,

    /// Authentication configuration for KMS
    pub auth: KmsAuthSpec,

    /// Resync interval in seconds (how often to re-fetch from KMS)
    #[serde(default = "default_kms_resync")]
    pub resync_interval: u64,
}

/// KMS authentication configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct KmsAuthSpec {
    /// Secret name containing KMS credentials (clientId, clientSecret)
    pub credentials_secret: String,

    /// Namespace of the credentials secret (defaults to operator namespace)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credentials_namespace: Option<String>,
}

fn default_kms_host() -> String {
    "https://kms.lux.network/api".to_string()
}

fn default_kms_staking_path() -> String {
    "/staking".to_string()
}

fn default_kms_resync() -> u64 {
    300
}

/// Init container configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct InitSpec {
    /// Image for init container (must contain plugins)
    pub image: String,

    /// Image pull policy for init container
    #[serde(default = "default_init_pull_policy")]
    pub pull_policy: String,

    /// Plugin binary names to copy from init image
    #[serde(default)]
    pub plugins: Vec<PluginSpec>,

    /// Clear chain data on init (for re-genesis)
    #[serde(default)]
    pub clear_data: bool,
}

fn default_init_pull_policy() -> String {
    "IfNotPresent".to_string()
}

/// Plugin specification
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PluginSpec {
    /// Source path in init image
    pub source: String,
    /// Destination filename in /data/plugins/
    pub dest: String,
}

/// Security context configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecuritySpec {
    /// Run as user ID
    #[serde(default = "default_uid")]
    pub run_as_user: i64,

    /// Run as group ID
    #[serde(default = "default_uid")]
    pub run_as_group: i64,

    /// FS group
    #[serde(default = "default_uid")]
    pub fs_group: i64,
}

impl Default for SecuritySpec {
    fn default() -> Self {
        Self {
            run_as_user: default_uid(),
            run_as_group: default_uid(),
            fs_group: default_uid(),
        }
    }
}

fn default_uid() -> i64 {
    1000
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
    "ghcr.io/luxfi/node".to_string()
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

    /// Specific chain IDs to track (for mainnet, use tracking IDs NOT blockchain IDs)
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

/// Automated snapshot schedule for backup and fast bootstrap
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotScheduleSpec {
    /// Enable periodic snapshot creation
    #[serde(default)]
    pub enabled: bool,

    /// Snapshot interval in seconds (default: 3600 = 1 hour)
    #[serde(default = "default_snapshot_interval")]
    pub interval_seconds: u64,

    /// MinIO/S3 endpoint for snapshot upload (e.g., "http://minio.hanzo.svc.cluster.local:9000")
    pub object_store_endpoint: String,

    /// Bucket name for snapshots
    #[serde(default = "default_snapshot_bucket")]
    pub bucket: String,

    /// Prefix path within bucket (e.g., "mainnet/")
    #[serde(default)]
    pub prefix: String,

    /// Access key for object store
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_key: Option<String>,

    /// Secret key for object store (reference to K8s secret)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_key_ref: Option<String>,

    /// Which node index to snapshot from (default: 0)
    #[serde(default)]
    pub source_node_index: u32,

    /// Include RLP exports for each chain in the snapshot
    #[serde(default = "default_true")]
    pub include_rlp_exports: bool,

    /// Maximum snapshots to retain (older ones are deleted)
    #[serde(default = "default_max_snapshots")]
    pub max_retained: u32,
}

impl Default for SnapshotScheduleSpec {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_seconds: default_snapshot_interval(),
            object_store_endpoint: String::new(),
            bucket: default_snapshot_bucket(),
            prefix: String::new(),
            access_key: None,
            secret_key_ref: None,
            source_node_index: 0,
            include_rlp_exports: true,
            max_retained: default_max_snapshots(),
        }
    }
}

fn default_snapshot_interval() -> u64 {
    3600
}

fn default_snapshot_bucket() -> String {
    "lux-snapshots".to_string()
}

fn default_max_snapshots() -> u32 {
    5
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

    /// C-chain blockchain ID (for clearing chain data before import)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_chain_id: Option<String>,
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

    /// Per-chain health status (aggregated across nodes)
    #[serde(default)]
    pub chain_statuses: BTreeMap<String, ChainStatus>,

    /// Per-pod external IPs (discovered from LB services)
    #[serde(default)]
    pub external_ips: BTreeMap<String, String>,

    /// Per-node detailed status
    #[serde(default)]
    pub node_statuses: BTreeMap<String, NodeStatus>,

    /// Degraded reasons (empty when Running)
    #[serde(default)]
    pub degraded_reasons: Vec<DegradedCondition>,

    /// Network-wide metrics
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_metrics: Option<NetworkMetrics>,

    /// Last snapshot timestamp (RFC3339)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_snapshot_time: Option<String>,

    /// Last snapshot URL (in object store)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_snapshot_url: Option<String>,

    /// Last snapshot version (from admin.snapshot)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_snapshot_version: Option<u64>,

    /// Number of snapshots stored
    #[serde(default)]
    pub snapshot_count: u32,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,

    /// Last reconciled generation
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
}

/// Per-node detailed status
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NodeStatus {
    /// Node ID (from info.getNodeID)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// External IP (from LB service)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_ip: Option<String>,

    /// P-chain height
    #[serde(skip_serializing_if = "Option::is_none")]
    pub p_chain_height: Option<u64>,

    /// C-chain block height
    #[serde(skip_serializing_if = "Option::is_none")]
    pub c_chain_height: Option<u64>,

    /// Number of tracked chains responding
    #[serde(default)]
    pub chains_count: u32,

    /// Connected peers count
    #[serde(default)]
    pub connected_peers: u32,

    /// Inbound peer count
    #[serde(default)]
    pub inbound_peers: u32,

    /// Outbound peer count
    #[serde(default)]
    pub outbound_peers: u32,

    /// Whether this node is bootstrapped
    #[serde(default)]
    pub bootstrapped: bool,

    /// Whether this node is healthy
    #[serde(default)]
    pub healthy: bool,

    /// Pod start time (for grace period calculation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
}

/// Degraded condition with reason and detail
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct DegradedCondition {
    /// Condition type
    pub reason: DegradedReason,
    /// Human-readable message
    pub message: String,
    /// Affected node(s)
    #[serde(default)]
    pub affected_nodes: Vec<String>,
}

/// Degraded reason enum
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, JsonSchema)]
pub enum DegradedReason {
    /// Waiting for peers to be reachable
    BootstrapBlocked,
    /// Node is lagging behind others
    HeightSkew,
    /// Insufficient inbound peer connections
    InboundPeersTooLow,
    /// One or more chains not responding
    ChainUnhealthy,
    /// Pod not ready
    PodNotReady,
    /// Node failed health check
    NodeUnhealthy,
}

/// Network-wide aggregated metrics
#[derive(Deserialize, Serialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkMetrics {
    /// Minimum P-chain height across all nodes
    #[serde(default)]
    pub min_p_height: u64,
    /// Maximum P-chain height across all nodes
    #[serde(default)]
    pub max_p_height: u64,
    /// Height skew (max - min)
    #[serde(default)]
    pub height_skew: u64,
    /// Number of bootstrapped chains (on any node)
    #[serde(default)]
    pub bootstrapped_chains: u32,
    /// Total connected peers across all nodes
    #[serde(default)]
    pub total_peers: u32,
}

/// Per-chain health status
#[derive(Deserialize, Serialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainStatus {
    /// Chain alias (e.g., "C", "zoo", "hanzo")
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,
    /// Whether the chain endpoint is responding
    #[serde(default)]
    pub healthy: bool,
    /// Last known block height
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_height: Option<u64>,
}

// ---------------------------------------------------------------------------
// LuxIndexer CRD
// ---------------------------------------------------------------------------

/// LuxIndexer deploys blockchain indexer instances for EVM chains.
/// Each indexer tracks one chain (C-chain or subnet) and exposes REST/WS/GraphQL APIs.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxIndexer",
    namespaced,
    status = "LuxIndexerStatus",
    shortname = "luxidx",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Chain","type":"string","jsonPath":".spec.chainAlias"}"#,
    printcolumn = r#"{"name":"Height","type":"integer","jsonPath":".status.indexedHeight"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LuxIndexerSpec {
    /// Reference to parent LuxNetwork name (same namespace)
    pub network_ref: String,

    /// Chain alias being indexed (e.g., "C", "zoo", "hanzo", "spc", "pars")
    pub chain_alias: String,

    /// EVM chain ID
    pub chain_id: u64,

    /// Blockchain ID (for subnet chains; empty for C-chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_id: Option<String>,

    /// Indexer image configuration
    #[serde(default = "default_indexer_image")]
    pub image: IndexerImageSpec,

    /// RPC endpoint override (default: auto-discovered from LuxNetwork)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_endpoint: Option<String>,

    /// WebSocket endpoint override
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_endpoint: Option<String>,

    /// Database configuration
    #[serde(default)]
    pub database: IndexerDatabaseSpec,

    /// HTTP API port
    #[serde(default = "default_indexer_port")]
    pub port: i32,

    /// Number of indexer replicas (read replicas, only 1 writer)
    #[serde(default = "default_one")]
    pub replicas: i32,

    /// Resource requirements
    #[serde(default)]
    pub resources: ResourceSpec,

    /// Enable DeFi protocol indexing (AMM, lending, staking)
    #[serde(default)]
    pub defi_indexing: bool,

    /// Enable NFT indexing
    #[serde(default)]
    pub nft_indexing: bool,

    /// Enable contract verification
    #[serde(default = "default_true")]
    pub contract_verification: bool,

    /// Enable internal transaction tracing
    #[serde(default = "default_true")]
    pub trace_enabled: bool,

    /// Poll interval in seconds for new blocks
    #[serde(default = "default_poll_interval")]
    pub poll_interval: u64,

    /// Indexer storage for KV layer (BadgerDB)
    #[serde(default)]
    pub storage: IndexerStorageSpec,
}

/// Indexer image configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexerImageSpec {
    pub repository: String,
    pub tag: String,
    #[serde(default = "default_pull_policy")]
    pub pull_policy: String,
}

impl Default for IndexerImageSpec {
    fn default() -> Self {
        default_indexer_image()
    }
}

fn default_indexer_image() -> IndexerImageSpec {
    IndexerImageSpec {
        repository: "registry.digitalocean.com/hanzo/lux-indexer".to_string(),
        tag: "latest".to_string(),
        pull_policy: "IfNotPresent".to_string(),
    }
}

fn default_indexer_port() -> i32 {
    4000
}

fn default_one() -> i32 {
    1
}

fn default_poll_interval() -> u64 {
    2
}

/// Indexer database configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexerDatabaseSpec {
    /// Deploy a PostgreSQL StatefulSet for this indexer (true) or use external DB (false)
    #[serde(default = "default_true")]
    pub managed: bool,

    /// External database URL (when managed=false)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Database name (auto-generated from chain alias if not set)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// PostgreSQL image
    #[serde(default = "default_pg_image")]
    pub image: String,

    /// Storage size for managed PostgreSQL PVC
    #[serde(default = "default_pg_storage")]
    pub storage_size: String,

    /// Storage class for managed PostgreSQL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

impl Default for IndexerDatabaseSpec {
    fn default() -> Self {
        Self {
            managed: true,
            url: None,
            name: None,
            image: default_pg_image(),
            storage_size: default_pg_storage(),
            storage_class: None,
        }
    }
}

fn default_pg_image() -> String {
    "postgres:16-alpine".to_string()
}

fn default_pg_storage() -> String {
    "20Gi".to_string()
}

/// Indexer KV storage configuration (BadgerDB)
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IndexerStorageSpec {
    /// Storage size for indexer KV data PVC
    #[serde(default = "default_indexer_storage")]
    pub size: String,

    /// Storage class
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
}

fn default_indexer_storage() -> String {
    "10Gi".to_string()
}

/// Status of a LuxIndexer
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxIndexerStatus {
    /// Current phase: Pending, Creating, Syncing, Ready, Error
    #[serde(default)]
    pub phase: String,

    /// Current indexed block height
    #[serde(default)]
    pub indexed_height: u64,

    /// Chain tip height (from RPC)
    #[serde(default)]
    pub chain_height: u64,

    /// Sync progress percentage (0-100)
    #[serde(default)]
    pub sync_progress: u32,

    /// API endpoint URL (ClusterIP service)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_endpoint: Option<String>,

    /// Database connection status
    #[serde(default)]
    pub database_ready: bool,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// LuxExplorer CRD
// ---------------------------------------------------------------------------

/// LuxExplorer deploys a blockchain explorer web UI for one or more chains.
/// It connects to LuxIndexer instances for data.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxExplorer",
    namespaced,
    status = "LuxExplorerStatus",
    shortname = "luxexp",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".status.url"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LuxExplorerSpec {
    /// Reference to parent LuxNetwork name (same namespace)
    pub network_ref: String,

    /// Explorer image configuration
    #[serde(default = "default_explorer_image")]
    pub image: ExplorerImageSpec,

    /// Chains to display in this explorer (references to LuxIndexer names)
    pub indexer_refs: Vec<ExplorerChainRef>,

    /// Number of replicas
    #[serde(default = "default_explorer_replicas")]
    pub replicas: i32,

    /// HTTP port
    #[serde(default = "default_explorer_port")]
    pub port: i32,

    /// Resource requirements
    #[serde(default)]
    pub resources: ResourceSpec,

    /// Ingress configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<ExplorerIngressSpec>,

    /// Custom branding
    #[serde(skip_serializing_if = "Option::is_none")]
    pub branding: Option<ExplorerBrandingSpec>,
}

/// Reference to an indexer for explorer
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerChainRef {
    /// LuxIndexer CR name (same namespace)
    pub indexer_name: String,
    /// Display name in the explorer UI
    pub display_name: String,
    /// Chain color (hex, for UI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub color: Option<String>,
    /// Whether this is the default chain shown
    #[serde(default)]
    pub default: bool,
}

/// Explorer image configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerImageSpec {
    pub repository: String,
    pub tag: String,
    #[serde(default = "default_pull_policy")]
    pub pull_policy: String,
}

impl Default for ExplorerImageSpec {
    fn default() -> Self {
        default_explorer_image()
    }
}

fn default_explorer_image() -> ExplorerImageSpec {
    ExplorerImageSpec {
        repository: "ghcr.io/blockscout/frontend".to_string(),
        tag: "latest".to_string(),
        pull_policy: "IfNotPresent".to_string(),
    }
}

fn default_explorer_replicas() -> i32 {
    2
}

fn default_explorer_port() -> i32 {
    3000
}

/// Explorer ingress configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerIngressSpec {
    /// Hostname for the explorer (e.g., "explorer.lux.network")
    pub host: String,
    /// TLS secret name (for HTTPS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_secret: Option<String>,
    /// Ingress class (e.g., "nginx")
    #[serde(default = "default_ingress_class")]
    pub ingress_class: String,
    /// Additional annotations
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,
}

fn default_ingress_class() -> String {
    "nginx".to_string()
}

/// Explorer branding configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExplorerBrandingSpec {
    /// Network name displayed in UI
    pub network_name: String,
    /// Logo URL
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logo_url: Option<String>,
    /// Primary color (hex)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub primary_color: Option<String>,
}

/// Status of a LuxExplorer
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxExplorerStatus {
    /// Current phase: Pending, Creating, Ready, Error
    #[serde(default)]
    pub phase: String,

    /// Public URL (from ingress or LB)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// Ready replicas
    #[serde(default)]
    pub ready_replicas: i32,

    /// Connected indexers (by name) and their sync status
    #[serde(default)]
    pub indexer_statuses: BTreeMap<String, bool>,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// LuxGateway CRD
// ---------------------------------------------------------------------------

/// LuxGateway manages an API gateway (KrakenD) for routing external traffic
/// to blockchain RPC, indexer APIs, and explorer UIs.
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxGateway",
    namespaced,
    status = "LuxGatewayStatus",
    shortname = "luxgw",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"Host","type":"string","jsonPath":".spec.host"}"#,
    printcolumn = r#"{"name":"Routes","type":"integer","jsonPath":".status.routeCount"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LuxGatewaySpec {
    /// Reference to parent LuxNetwork name (same namespace)
    pub network_ref: String,

    /// Gateway image
    #[serde(default = "default_gateway_image")]
    pub image: GatewayImageSpec,

    /// Primary hostname (e.g., "api.lux.network")
    pub host: String,

    /// Number of gateway replicas
    #[serde(default = "default_gateway_replicas")]
    pub replicas: i32,

    /// HTTP port
    #[serde(default = "default_gateway_port")]
    pub port: i32,

    /// Auto-discover and route all chains from the referenced LuxNetwork
    #[serde(default = "default_true")]
    pub auto_routes: bool,

    /// Additional custom routes
    #[serde(default)]
    pub custom_routes: Vec<GatewayRoute>,

    /// Rate limiting configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_limit: Option<GatewayRateLimitSpec>,

    /// CORS configuration
    #[serde(default)]
    pub cors: GatewayCorsSpec,

    /// TLS configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<GatewayTlsSpec>,

    /// Resource requirements
    #[serde(default)]
    pub resources: ResourceSpec,

    /// Indexer references for API routing (connects indexer APIs to gateway)
    #[serde(default)]
    pub indexer_refs: Vec<String>,

    /// Explorer references for UI routing
    #[serde(default)]
    pub explorer_refs: Vec<String>,
}

/// Gateway image configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayImageSpec {
    pub repository: String,
    pub tag: String,
    #[serde(default = "default_pull_policy")]
    pub pull_policy: String,
}

impl Default for GatewayImageSpec {
    fn default() -> Self {
        default_gateway_image()
    }
}

fn default_gateway_image() -> GatewayImageSpec {
    GatewayImageSpec {
        repository: "devopsfaith/krakend".to_string(),
        tag: "2.7".to_string(),
        pull_policy: "IfNotPresent".to_string(),
    }
}

fn default_gateway_replicas() -> i32 {
    2
}

fn default_gateway_port() -> i32 {
    8080
}

/// A custom gateway route
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRoute {
    /// URL path pattern (e.g., "/ext/bc/C/rpc")
    pub path: String,
    /// Backend service URL
    pub backend: String,
    /// HTTP methods allowed
    #[serde(default = "default_methods")]
    pub methods: Vec<String>,
    /// Request timeout in seconds
    #[serde(default = "default_route_timeout")]
    pub timeout: u64,
}

fn default_methods() -> Vec<String> {
    vec!["GET".to_string(), "POST".to_string()]
}

fn default_route_timeout() -> u64 {
    30
}

/// Rate limiting configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayRateLimitSpec {
    /// Requests per second per client IP
    #[serde(default = "default_rate_limit")]
    pub requests_per_second: u32,
    /// Burst size
    #[serde(default = "default_burst")]
    pub burst: u32,
}

fn default_rate_limit() -> u32 {
    100
}

fn default_burst() -> u32 {
    200
}

/// CORS configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayCorsSpec {
    /// Allowed origins
    #[serde(default = "default_cors_origins")]
    pub allowed_origins: Vec<String>,
    /// Allowed methods
    #[serde(default = "default_methods")]
    pub allowed_methods: Vec<String>,
    /// Allowed headers
    #[serde(default = "default_cors_headers")]
    pub allowed_headers: Vec<String>,
}

impl Default for GatewayCorsSpec {
    fn default() -> Self {
        Self {
            allowed_origins: default_cors_origins(),
            allowed_methods: default_methods(),
            allowed_headers: default_cors_headers(),
        }
    }
}

fn default_cors_origins() -> Vec<String> {
    vec!["*".to_string()]
}

fn default_cors_headers() -> Vec<String> {
    vec!["Content-Type".to_string(), "Authorization".to_string()]
}

/// TLS configuration
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GatewayTlsSpec {
    /// TLS secret name
    pub secret_name: String,
    /// Enable automatic cert-manager certificates
    #[serde(default)]
    pub cert_manager: bool,
    /// cert-manager issuer name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
}

/// Status of a LuxGateway
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxGatewayStatus {
    /// Current phase: Pending, Creating, Ready, Error
    #[serde(default)]
    pub phase: String,

    /// Number of configured routes
    #[serde(default)]
    pub route_count: u32,

    /// External IP or hostname
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_endpoint: Option<String>,

    /// Ready replicas
    #[serde(default)]
    pub ready_replicas: i32,

    /// Auto-discovered chain routes
    #[serde(default)]
    pub chain_routes: BTreeMap<String, String>,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}

// ---------------------------------------------------------------------------
// LuxChain CRD
// ---------------------------------------------------------------------------

/// LuxChain CRD for chain deployments
#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[kube(
    group = "lux.network",
    version = "v1alpha1",
    kind = "LuxChain",
    namespaced,
    status = "LuxChainStatus",
    shortname = "luxchain",
    printcolumn = r#"{"name":"Phase","type":"string","jsonPath":".status.phase"}"#,
    printcolumn = r#"{"name":"ChainID","type":"string","jsonPath":".status.chainId"}"#,
    printcolumn = r#"{"name":"BlockchainID","type":"string","jsonPath":".status.blockchainId"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct LuxChainSpec {
    /// Reference to parent LuxNetwork name (same namespace)
    pub network_ref: String,

    /// Chain ID (if joining existing chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,

    /// Blockchain ID (set after chain is deployed)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_id: Option<String>,

    /// Human-readable alias for this chain
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alias: Option<String>,

    /// Validators for this chain
    #[serde(default)]
    pub validators: Vec<ChainValidator>,

    /// VM configuration
    pub vm: VmSpec,
}

/// Chain validator reference
#[derive(Deserialize, Serialize, Clone, Debug, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChainValidator {
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
    /// VM type (evm, or custom VM name)
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

/// Status of a LuxChain
#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LuxChainStatus {
    /// Chain ID (assigned after creation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_id: Option<String>,

    /// Blockchain ID (assigned after chain deployment)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blockchain_id: Option<String>,

    /// Current phase: Pending, Deploying, Active, Error
    #[serde(default)]
    pub phase: String,

    /// Conditions
    #[serde(default)]
    #[schemars(skip)]
    pub conditions: Vec<Condition>,
}
