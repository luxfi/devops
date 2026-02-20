//! Kubernetes CRD and operator types for Lux Network

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Custom Resource Definition for a Lux Network
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LuxNetworkSpec {
    /// Network ID
    pub network_id: u32,

    /// Number of validators
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

    /// Lux MPC configuration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mpc: Option<MpcConfig>,

    /// Metrics configuration
    #[serde(default)]
    pub metrics: MetricsSpec,

    /// Service configuration
    #[serde(default)]
    pub service: ServiceSpec,
}

impl LuxNetworkSpec {
    /// Create a new network spec with required fields
    pub fn new(network_id: u32, validators: u32) -> Self {
        Self {
            network_id,
            validators,
            image: ImageSpec::default(),
            storage: StorageSpec::default(),
            resources: ResourceSpec::default(),
            config: BTreeMap::new(),
            genesis: None,
            mpc: None,
            metrics: MetricsSpec::default(),
            service: ServiceSpec::default(),
        }
    }

    /// Builder: set image spec
    pub fn with_image(mut self, image: ImageSpec) -> Self {
        self.image = image;
        self
    }

    /// Builder: set storage spec
    pub fn with_storage(mut self, storage: StorageSpec) -> Self {
        self.storage = storage;
        self
    }

    /// Builder: set resource spec
    pub fn with_resources(mut self, resources: ResourceSpec) -> Self {
        self.resources = resources;
        self
    }

    /// Builder: add config override
    pub fn with_config(mut self, key: impl Into<String>, value: serde_json::Value) -> Self {
        self.config.insert(key.into(), value);
        self
    }

    /// Builder: set genesis
    pub fn with_genesis(mut self, genesis: serde_json::Value) -> Self {
        self.genesis = Some(genesis);
        self
    }

    /// Builder: set MPC config
    pub fn with_mpc(mut self, mpc: MpcConfig) -> Self {
        self.mpc = Some(mpc);
        self
    }

    /// Builder: set metrics spec
    pub fn with_metrics(mut self, metrics: MetricsSpec) -> Self {
        self.metrics = metrics;
        self
    }

    /// Builder: set service spec
    pub fn with_service(mut self, service: ServiceSpec) -> Self {
        self.service = service;
        self
    }
}

/// Image configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
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

impl Default for ImageSpec {
    fn default() -> Self {
        Self {
            repository: default_image_repo(),
            tag: default_image_tag(),
            pull_policy: default_pull_policy(),
            pull_secrets: vec![],
        }
    }
}

impl ImageSpec {
    /// Create a new image spec
    pub fn new(repository: impl Into<String>, tag: impl Into<String>) -> Self {
        Self {
            repository: repository.into(),
            tag: tag.into(),
            ..Default::default()
        }
    }

    /// Builder: set pull policy
    pub fn with_pull_policy(mut self, policy: impl Into<String>) -> Self {
        self.pull_policy = policy.into();
        self
    }

    /// Builder: add pull secret
    pub fn with_pull_secret(mut self, secret: impl Into<String>) -> Self {
        self.pull_secrets.push(secret.into());
        self
    }

    /// Get the full image reference
    pub fn full_image(&self) -> String {
        format!("{}:{}", self.repository, self.tag)
    }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageSpec {
    /// Storage class name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,

    /// Storage size (e.g., "100Gi")
    #[serde(default = "default_storage_size")]
    pub size: String,

    /// Access modes
    #[serde(default = "default_access_modes")]
    pub access_modes: Vec<String>,
}

impl Default for StorageSpec {
    fn default() -> Self {
        Self {
            storage_class: None,
            size: default_storage_size(),
            access_modes: default_access_modes(),
        }
    }
}

impl StorageSpec {
    /// Create a new storage spec with size
    pub fn new(size: impl Into<String>) -> Self {
        Self {
            size: size.into(),
            ..Default::default()
        }
    }

    /// Builder: set storage class
    pub fn with_storage_class(mut self, class: impl Into<String>) -> Self {
        self.storage_class = Some(class.into());
        self
    }

    /// Builder: set access modes
    pub fn with_access_modes(mut self, modes: Vec<String>) -> Self {
        self.access_modes = modes;
        self
    }
}

fn default_storage_size() -> String {
    "200Gi".to_string()
}

fn default_access_modes() -> Vec<String> {
    vec!["ReadWriteOnce".to_string()]
}

/// Resource requirements
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
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

impl ResourceSpec {
    /// Create a new resource spec
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set CPU request and limit
    pub fn with_cpu(mut self, request: impl Into<String>, limit: impl Into<String>) -> Self {
        self.cpu_request = Some(request.into());
        self.cpu_limit = Some(limit.into());
        self
    }

    /// Builder: set memory request and limit
    pub fn with_memory(mut self, request: impl Into<String>, limit: impl Into<String>) -> Self {
        self.memory_request = Some(request.into());
        self.memory_limit = Some(limit.into());
        self
    }

    /// Create a preset for small nodes
    pub fn small() -> Self {
        Self::new().with_cpu("1", "2").with_memory("4Gi", "8Gi")
    }

    /// Create a preset for medium nodes
    pub fn medium() -> Self {
        Self::new().with_cpu("2", "4").with_memory("8Gi", "16Gi")
    }

    /// Create a preset for large nodes
    pub fn large() -> Self {
        Self::new().with_cpu("4", "8").with_memory("16Gi", "32Gi")
    }
}

/// Lux MPC configuration for key management
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MpcConfig {
    /// Enable MPC key management
    #[serde(default)]
    pub enabled: bool,

    /// MPC endpoint URL
    pub endpoint: String,

    /// MPC authentication secret name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auth_secret: Option<String>,

    /// Key derivation path prefix
    #[serde(skip_serializing_if = "Option::is_none")]
    pub derivation_prefix: Option<String>,

    /// Use TSS (threshold signatures)
    #[serde(default)]
    pub use_tss: bool,

    /// TSS threshold (e.g., 2 of 3)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tss_threshold: Option<u32>,

    /// TSS total parties
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tss_parties: Option<u32>,
}

impl MpcConfig {
    /// Create a new MPC config
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            enabled: true,
            endpoint: endpoint.into(),
            auth_secret: None,
            derivation_prefix: None,
            use_tss: false,
            tss_threshold: None,
            tss_parties: None,
        }
    }

    /// Builder: set auth secret
    pub fn with_auth_secret(mut self, secret: impl Into<String>) -> Self {
        self.auth_secret = Some(secret.into());
        self
    }

    /// Builder: enable TSS
    pub fn with_tss(mut self, threshold: u32, parties: u32) -> Self {
        self.use_tss = true;
        self.tss_threshold = Some(threshold);
        self.tss_parties = Some(parties);
        self
    }
}

/// Metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MetricsSpec {
    /// Enable metrics
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Metrics port
    #[serde(default = "default_metrics_port")]
    pub port: u16,

    /// Enable ServiceMonitor (for Prometheus Operator)
    #[serde(default)]
    pub service_monitor: bool,

    /// ServiceMonitor labels
    #[serde(default)]
    pub service_monitor_labels: BTreeMap<String, String>,
}

impl Default for MetricsSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            port: default_metrics_port(),
            service_monitor: false,
            service_monitor_labels: BTreeMap::new(),
        }
    }
}

impl MetricsSpec {
    /// Create a new metrics spec
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: enable ServiceMonitor
    pub fn with_service_monitor(mut self) -> Self {
        self.service_monitor = true;
        self
    }

    /// Builder: add ServiceMonitor label
    pub fn with_label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.service_monitor_labels.insert(key.into(), value.into());
        self
    }

    /// Builder: set port
    pub fn with_port(mut self, port: u16) -> Self {
        self.port = port;
        self
    }
}

fn default_true() -> bool {
    true
}

fn default_metrics_port() -> u16 {
    9090
}

/// Service configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ServiceSpec {
    /// Service type (ClusterIP, LoadBalancer, NodePort)
    #[serde(default = "default_service_type")]
    pub service_type: String,

    /// HTTP port
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Staking port
    #[serde(default = "default_staking_port")]
    pub staking_port: u16,

    /// Annotations
    #[serde(default)]
    pub annotations: BTreeMap<String, String>,

    /// Enable ingress
    #[serde(default)]
    pub ingress_enabled: bool,

    /// Ingress class
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_class: Option<String>,

    /// Ingress host
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress_host: Option<String>,

    /// Enable TLS
    #[serde(default)]
    pub tls_enabled: bool,

    /// TLS secret name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_secret: Option<String>,
}

impl Default for ServiceSpec {
    fn default() -> Self {
        Self {
            service_type: default_service_type(),
            http_port: default_http_port(),
            staking_port: default_staking_port(),
            annotations: BTreeMap::new(),
            ingress_enabled: false,
            ingress_class: None,
            ingress_host: None,
            tls_enabled: false,
            tls_secret: None,
        }
    }
}

impl ServiceSpec {
    /// Create a new service spec
    pub fn new() -> Self {
        Self::default()
    }

    /// Builder: set service type
    pub fn with_type(mut self, service_type: impl Into<String>) -> Self {
        self.service_type = service_type.into();
        self
    }

    /// Builder: add annotation
    pub fn with_annotation(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.annotations.insert(key.into(), value.into());
        self
    }

    /// Builder: enable ingress
    pub fn with_ingress(mut self, host: impl Into<String>) -> Self {
        self.ingress_enabled = true;
        self.ingress_host = Some(host.into());
        self
    }

    /// Builder: set ingress class
    pub fn with_ingress_class(mut self, class: impl Into<String>) -> Self {
        self.ingress_class = Some(class.into());
        self
    }

    /// Builder: enable TLS
    pub fn with_tls(mut self, secret: impl Into<String>) -> Self {
        self.tls_enabled = true;
        self.tls_secret = Some(secret.into());
        self
    }

    /// Create a LoadBalancer service spec
    pub fn load_balancer() -> Self {
        Self::new().with_type("LoadBalancer")
    }

    /// Create a NodePort service spec
    pub fn node_port() -> Self {
        Self::new().with_type("NodePort")
    }
}

fn default_service_type() -> String {
    "ClusterIP".to_string()
}

fn default_http_port() -> u16 {
    9650
}

fn default_staking_port() -> u16 {
    9651
}

/// Status of a Lux Network
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct LuxNetworkStatus {
    /// Overall phase
    pub phase: NetworkPhase,

    /// Number of ready validators
    pub ready_validators: u32,

    /// Total validators
    pub total_validators: u32,

    /// Network ID
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<u32>,

    /// Bootstrap node endpoints
    #[serde(default)]
    pub bootstrap_nodes: Vec<String>,

    /// Conditions
    #[serde(default)]
    pub conditions: Vec<Condition>,

    /// Last updated timestamp
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_updated: Option<String>,
}

impl LuxNetworkStatus {
    /// Check if the network is healthy
    pub fn is_healthy(&self) -> bool {
        self.phase == NetworkPhase::Running && self.ready_validators == self.total_validators
    }

    /// Get the ready ratio as a percentage
    pub fn ready_percentage(&self) -> u32 {
        if self.total_validators == 0 {
            return 0;
        }
        (self.ready_validators * 100) / self.total_validators
    }
}

/// Network phase
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub enum NetworkPhase {
    #[default]
    Pending,
    Creating,
    Bootstrapping,
    Running,
    Degraded,
    Failed,
    Deleting,
}

impl NetworkPhase {
    /// Check if the network is operational
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Running | Self::Degraded)
    }

    /// Check if the network is in progress
    pub fn is_in_progress(&self) -> bool {
        matches!(self, Self::Creating | Self::Bootstrapping | Self::Deleting)
    }
}

/// Condition for status
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Condition {
    /// Condition type
    pub condition_type: String,
    /// Status (True, False, Unknown)
    pub status: String,
    /// Last transition time
    pub last_transition_time: String,
    /// Reason
    pub reason: String,
    /// Message
    pub message: String,
}

impl Condition {
    /// Create a new condition
    pub fn new(
        condition_type: impl Into<String>,
        status: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self {
            condition_type: condition_type.into(),
            status: status.into(),
            last_transition_time: chrono::Utc::now().to_rfc3339(),
            reason: reason.into(),
            message: message.into(),
        }
    }

    /// Create a "True" condition
    pub fn true_condition(
        condition_type: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(condition_type, "True", reason, message)
    }

    /// Create a "False" condition
    pub fn false_condition(
        condition_type: impl Into<String>,
        reason: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        Self::new(condition_type, "False", reason, message)
    }
}

/// Custom Resource Definition for a Lux Subnet
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LuxSubnetSpec {
    /// Reference to the parent LuxNetwork
    pub network_ref: String,

    /// Subnet ID (if existing)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_id: Option<String>,

    /// Validators for this subnet
    pub validators: Vec<SubnetValidator>,

    /// VM configuration
    pub vm: VmSpec,
}

impl LuxSubnetSpec {
    /// Create a new subnet spec
    pub fn new(network_ref: impl Into<String>, vm: VmSpec) -> Self {
        Self {
            network_ref: network_ref.into(),
            subnet_id: None,
            validators: Vec::new(),
            vm,
        }
    }

    /// Builder: add validator
    pub fn with_validator(mut self, node_id: impl Into<String>, weight: u64) -> Self {
        self.validators.push(SubnetValidator {
            node_id: node_id.into(),
            weight,
        });
        self
    }

    /// Builder: set existing subnet ID
    pub fn with_subnet_id(mut self, subnet_id: impl Into<String>) -> Self {
        self.subnet_id = Some(subnet_id.into());
        self
    }
}

/// Subnet validator
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SubnetValidator {
    /// Node ID
    pub node_id: String,
    /// Weight
    pub weight: u64,
}

/// VM specification for subnet
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VmSpec {
    /// VM type (subnet-evm, timestampvm, etc.)
    pub vm_type: String,

    /// VM binary (if custom)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binary_url: Option<String>,

    /// VM genesis
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<serde_json::Value>,

    /// VM chain config
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_config: Option<serde_json::Value>,
}

impl VmSpec {
    /// Create a new VM spec
    pub fn new(vm_type: impl Into<String>) -> Self {
        Self {
            vm_type: vm_type.into(),
            binary_url: None,
            genesis: None,
            chain_config: None,
        }
    }

    /// Create a subnet-evm spec
    pub fn subnet_evm() -> Self {
        Self::new("subnet-evm")
    }

    /// Builder: set binary URL
    pub fn with_binary_url(mut self, url: impl Into<String>) -> Self {
        self.binary_url = Some(url.into());
        self
    }

    /// Builder: set genesis
    pub fn with_genesis(mut self, genesis: serde_json::Value) -> Self {
        self.genesis = Some(genesis);
        self
    }

    /// Builder: set chain config
    pub fn with_chain_config(mut self, config: serde_json::Value) -> Self {
        self.chain_config = Some(config);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_lux_network_spec_builder() {
        let spec = LuxNetworkSpec::new(12345, 5)
            .with_image(ImageSpec::new("my-repo/luxd", "v1.0.0"))
            .with_storage(StorageSpec::new("500Gi").with_storage_class("gp3"))
            .with_resources(ResourceSpec::medium())
            .with_metrics(MetricsSpec::new().with_service_monitor());

        assert_eq!(spec.network_id, 12345);
        assert_eq!(spec.validators, 5);
        assert_eq!(spec.image.repository, "my-repo/luxd");
        assert_eq!(spec.storage.size, "500Gi");
        assert!(spec.metrics.service_monitor);
    }

    #[test]
    fn test_image_spec() {
        let image = ImageSpec::new("ghcr.io/luxfi/luxd", "v1.0.0")
            .with_pull_policy("Always")
            .with_pull_secret("my-secret");

        assert_eq!(image.full_image(), "ghcr.io/luxfi/luxd:v1.0.0");
        assert_eq!(image.pull_policy, "Always");
        assert!(image.pull_secrets.contains(&"my-secret".to_string()));
    }

    #[test]
    fn test_resource_presets() {
        let small = ResourceSpec::small();
        assert_eq!(small.cpu_request, Some("1".to_string()));
        assert_eq!(small.memory_limit, Some("8Gi".to_string()));

        let large = ResourceSpec::large();
        assert_eq!(large.cpu_limit, Some("8".to_string()));
        assert_eq!(large.memory_request, Some("16Gi".to_string()));
    }

    #[test]
    fn test_service_spec_builder() {
        let service = ServiceSpec::load_balancer()
            .with_annotation("service.beta.kubernetes.io/aws-load-balancer-type", "nlb")
            .with_ingress("node.example.com")
            .with_tls("tls-secret");

        assert_eq!(service.service_type, "LoadBalancer");
        assert!(service.ingress_enabled);
        assert_eq!(service.ingress_host, Some("node.example.com".to_string()));
        assert!(service.tls_enabled);
    }

    #[test]
    fn test_network_status() {
        let status = LuxNetworkStatus {
            phase: NetworkPhase::Running,
            ready_validators: 4,
            total_validators: 5,
            ..Default::default()
        };

        assert!(!status.is_healthy());
        assert_eq!(status.ready_percentage(), 80);

        let healthy_status = LuxNetworkStatus {
            phase: NetworkPhase::Running,
            ready_validators: 5,
            total_validators: 5,
            ..Default::default()
        };
        assert!(healthy_status.is_healthy());
    }

    #[test]
    fn test_network_phase() {
        assert!(NetworkPhase::Running.is_operational());
        assert!(NetworkPhase::Degraded.is_operational());
        assert!(!NetworkPhase::Creating.is_operational());

        assert!(NetworkPhase::Creating.is_in_progress());
        assert!(NetworkPhase::Bootstrapping.is_in_progress());
        assert!(!NetworkPhase::Running.is_in_progress());
    }

    #[test]
    fn test_subnet_spec_builder() {
        let vm = VmSpec::subnet_evm().with_genesis(serde_json::json!({"chainId": 12345}));

        let subnet = LuxSubnetSpec::new("my-network", vm)
            .with_validator("NodeID-abc123", 100)
            .with_validator("NodeID-def456", 100);

        assert_eq!(subnet.network_ref, "my-network");
        assert_eq!(subnet.validators.len(), 2);
        assert_eq!(subnet.vm.vm_type, "subnet-evm");
    }

    #[test]
    fn test_condition() {
        let cond = Condition::true_condition("Ready", "AllReady", "All validators are ready");
        assert_eq!(cond.status, "True");
        assert_eq!(cond.condition_type, "Ready");
    }

    #[test]
    fn test_mpc_config() {
        let mpc = MpcConfig::new("https://mpc.example.com")
            .with_auth_secret("mpc-auth")
            .with_tss(2, 3);

        assert!(mpc.enabled);
        assert!(mpc.use_tss);
        assert_eq!(mpc.tss_threshold, Some(2));
        assert_eq!(mpc.tss_parties, Some(3));
    }
}
