//! Configuration types for Lux Network nodes

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

/// luxd node configuration
/// Matches the CLI flags and config file format for luxd
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct LuxdConfig {
    /// Network ID (1=mainnet, 5=testnet)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<u32>,

    /// HTTP host
    #[serde(default = "default_http_host")]
    pub http_host: String,

    /// HTTP port
    #[serde(default = "default_http_port")]
    pub http_port: u16,

    /// Staking port
    #[serde(default = "default_staking_port")]
    pub staking_port: u16,

    /// Enable staking
    #[serde(default = "default_true")]
    pub staking_enabled: bool,

    /// Path to staking TLS key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_key_file: Option<PathBuf>,

    /// Path to staking TLS cert
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_tls_cert_file: Option<PathBuf>,

    /// Path to staking signer key (BLS)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub staking_signer_key_file: Option<PathBuf>,

    /// Database directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub db_dir: Option<PathBuf>,

    /// Log directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_dir: Option<PathBuf>,

    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Log display level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_display_level: Option<String>,

    /// Bootstrap IPs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ips: Option<String>,

    /// Bootstrap IDs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bootstrap_ids: Option<String>,

    /// Genesis file path (for custom networks)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub genesis: Option<PathBuf>,

    /// Plugin directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_dir: Option<PathBuf>,

    /// Chain config directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub chain_config_dir: Option<PathBuf>,

    /// Subnet config directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_config_dir: Option<PathBuf>,

    /// Public IP (for advertising)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip: Option<String>,

    /// Public IP resolution service
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_ip_resolution_service: Option<String>,

    /// Index enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_enabled: Option<bool>,

    /// API admin enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_admin_enabled: Option<bool>,

    /// API info enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_info_enabled: Option<bool>,

    /// API health enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_health_enabled: Option<bool>,

    /// Track subnets
    #[serde(skip_serializing_if = "Option::is_none")]
    pub track_subnets: Option<String>,

    /// Additional config entries
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn default_http_host() -> String {
    "0.0.0.0".to_string()
}

fn default_http_port() -> u16 {
    9650
}

fn default_staking_port() -> u16 {
    9651
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}

impl LuxdConfig {
    /// Create a new config with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Create config for mainnet
    pub fn mainnet() -> Self {
        Self {
            network_id: Some(1),
            ..Default::default()
        }
    }

    /// Create config for testnet
    pub fn testnet() -> Self {
        Self {
            network_id: Some(5),
            ..Default::default()
        }
    }

    /// Create config for local network
    pub fn local(network_id: u32) -> Self {
        Self {
            network_id: Some(network_id),
            staking_enabled: false,
            ..Default::default()
        }
    }

    /// Generate CLI arguments for luxd
    pub fn to_cli_args(&self) -> Vec<String> {
        let mut args = Vec::new();

        if let Some(network_id) = self.network_id {
            args.push(format!("--network-id={}", network_id));
        }

        args.push(format!("--http-host={}", self.http_host));
        args.push(format!("--http-port={}", self.http_port));
        args.push(format!("--staking-port={}", self.staking_port));
        args.push(format!("--staking-enabled={}", self.staking_enabled));
        args.push(format!("--log-level={}", self.log_level));

        if let Some(ref key_file) = self.staking_tls_key_file {
            args.push(format!("--staking-tls-key-file={}", key_file.display()));
        }

        if let Some(ref cert_file) = self.staking_tls_cert_file {
            args.push(format!("--staking-tls-cert-file={}", cert_file.display()));
        }

        if let Some(ref signer_key) = self.staking_signer_key_file {
            args.push(format!(
                "--staking-signer-key-file={}",
                signer_key.display()
            ));
        }

        if let Some(ref db_dir) = self.db_dir {
            args.push(format!("--db-dir={}", db_dir.display()));
        }

        if let Some(ref log_dir) = self.log_dir {
            args.push(format!("--log-dir={}", log_dir.display()));
        }

        if let Some(ref display_level) = self.log_display_level {
            args.push(format!("--log-display-level={}", display_level));
        }

        if let Some(ref bootstrap_ips) = self.bootstrap_ips {
            args.push(format!("--bootstrap-ips={}", bootstrap_ips));
        }

        if let Some(ref bootstrap_ids) = self.bootstrap_ids {
            args.push(format!("--bootstrap-ids={}", bootstrap_ids));
        }

        if let Some(ref genesis) = self.genesis {
            args.push(format!("--genesis={}", genesis.display()));
        }

        if let Some(ref plugin_dir) = self.plugin_dir {
            args.push(format!("--plugin-dir={}", plugin_dir.display()));
        }

        if let Some(ref chain_config_dir) = self.chain_config_dir {
            args.push(format!("--chain-config-dir={}", chain_config_dir.display()));
        }

        if let Some(ref subnet_config_dir) = self.subnet_config_dir {
            args.push(format!(
                "--subnet-config-dir={}",
                subnet_config_dir.display()
            ));
        }

        if let Some(ref public_ip) = self.public_ip {
            args.push(format!("--public-ip={}", public_ip));
        }

        if let Some(ref service) = self.public_ip_resolution_service {
            args.push(format!("--public-ip-resolution-service={}", service));
        }

        if let Some(index_enabled) = self.index_enabled {
            args.push(format!("--index-enabled={}", index_enabled));
        }

        if let Some(admin_enabled) = self.api_admin_enabled {
            args.push(format!("--api-admin-enabled={}", admin_enabled));
        }

        if let Some(info_enabled) = self.api_info_enabled {
            args.push(format!("--api-info-enabled={}", info_enabled));
        }

        if let Some(health_enabled) = self.api_health_enabled {
            args.push(format!("--api-health-enabled={}", health_enabled));
        }

        if let Some(ref track_subnets) = self.track_subnets {
            args.push(format!("--track-subnets={}", track_subnets));
        }

        // Add extra config as individual args
        for (key, value) in &self.extra {
            let value_str = match value {
                serde_json::Value::String(s) => s.clone(),
                serde_json::Value::Bool(b) => b.to_string(),
                serde_json::Value::Number(n) => n.to_string(),
                _ => serde_json::to_string(value).unwrap_or_default(),
            };
            args.push(format!("--{}={}", key, value_str));
        }

        args
    }

    /// Generate config file content as JSON
    pub fn to_config_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Set bootstrap nodes
    pub fn with_bootstrap(&mut self, ips: &str, ids: &str) -> &mut Self {
        self.bootstrap_ips = Some(ips.to_string());
        self.bootstrap_ids = Some(ids.to_string());
        self
    }

    /// Set staking files
    pub fn with_staking_files(
        &mut self,
        key_file: PathBuf,
        cert_file: PathBuf,
        signer_key_file: Option<PathBuf>,
    ) -> &mut Self {
        self.staking_tls_key_file = Some(key_file);
        self.staking_tls_cert_file = Some(cert_file);
        self.staking_signer_key_file = signer_key_file;
        self
    }

    /// Set data directories
    pub fn with_data_dirs(&mut self, db_dir: PathBuf, log_dir: PathBuf) -> &mut Self {
        self.db_dir = Some(db_dir);
        self.log_dir = Some(log_dir);
        self
    }

    /// Merge another config into this one (other takes precedence for non-None values)
    pub fn merge(&mut self, other: &LuxdConfig) {
        if other.network_id.is_some() {
            self.network_id = other.network_id;
        }
        if other.http_host != default_http_host() {
            self.http_host = other.http_host.clone();
        }
        if other.http_port != default_http_port() {
            self.http_port = other.http_port;
        }
        if other.staking_port != default_staking_port() {
            self.staking_port = other.staking_port;
        }
        if !other.staking_enabled {
            self.staking_enabled = false;
        }
        if other.log_level != default_log_level() {
            self.log_level = other.log_level.clone();
        }
        if other.staking_tls_key_file.is_some() {
            self.staking_tls_key_file = other.staking_tls_key_file.clone();
        }
        if other.staking_tls_cert_file.is_some() {
            self.staking_tls_cert_file = other.staking_tls_cert_file.clone();
        }
        if other.staking_signer_key_file.is_some() {
            self.staking_signer_key_file = other.staking_signer_key_file.clone();
        }
        if other.db_dir.is_some() {
            self.db_dir = other.db_dir.clone();
        }
        if other.log_dir.is_some() {
            self.log_dir = other.log_dir.clone();
        }
        if other.log_display_level.is_some() {
            self.log_display_level = other.log_display_level.clone();
        }
        if other.bootstrap_ips.is_some() {
            self.bootstrap_ips = other.bootstrap_ips.clone();
        }
        if other.bootstrap_ids.is_some() {
            self.bootstrap_ids = other.bootstrap_ids.clone();
        }
        if other.genesis.is_some() {
            self.genesis = other.genesis.clone();
        }
        if other.plugin_dir.is_some() {
            self.plugin_dir = other.plugin_dir.clone();
        }
        if other.chain_config_dir.is_some() {
            self.chain_config_dir = other.chain_config_dir.clone();
        }
        if other.subnet_config_dir.is_some() {
            self.subnet_config_dir = other.subnet_config_dir.clone();
        }
        if other.public_ip.is_some() {
            self.public_ip = other.public_ip.clone();
        }
        if other.public_ip_resolution_service.is_some() {
            self.public_ip_resolution_service = other.public_ip_resolution_service.clone();
        }
        if other.index_enabled.is_some() {
            self.index_enabled = other.index_enabled;
        }
        if other.api_admin_enabled.is_some() {
            self.api_admin_enabled = other.api_admin_enabled;
        }
        if other.api_info_enabled.is_some() {
            self.api_info_enabled = other.api_info_enabled;
        }
        if other.api_health_enabled.is_some() {
            self.api_health_enabled = other.api_health_enabled;
        }
        if other.track_subnets.is_some() {
            self.track_subnets = other.track_subnets.clone();
        }
        // Merge extra fields
        for (k, v) in &other.extra {
            self.extra.insert(k.clone(), v.clone());
        }
    }
}

/// C-Chain (coreth) configuration
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub struct CChainConfig {
    /// Snowman API enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snowman_api_enabled: Option<bool>,

    /// Admin API enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_api_enabled: Option<bool>,

    /// Admin API directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub admin_api_dir: Option<String>,

    /// Enable eth APIs
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_apis: Option<Vec<String>>,

    /// WebSocket CPU refill rate
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ws_cpu_refill_rate: Option<u64>,

    /// Log level
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_level: Option<String>,

    /// Pruning enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pruning_enabled: Option<bool>,

    /// State sync enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state_sync_enabled: Option<bool>,

    /// Continuous profiler directory
    #[serde(skip_serializing_if = "Option::is_none")]
    pub continuous_profiler_dir: Option<String>,

    /// Local txs enabled
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_txs_enabled: Option<bool>,

    /// Priority regossip addresses
    #[serde(skip_serializing_if = "Option::is_none")]
    pub priority_regossip_addresses: Option<Vec<String>>,

    /// Additional config entries
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

impl CChainConfig {
    /// Generate config file content as JSON
    pub fn to_config_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Check if config is empty (all None)
    pub fn is_empty(&self) -> bool {
        self.snowman_api_enabled.is_none()
            && self.admin_api_enabled.is_none()
            && self.admin_api_dir.is_none()
            && self.eth_apis.is_none()
            && self.ws_cpu_refill_rate.is_none()
            && self.log_level.is_none()
            && self.pruning_enabled.is_none()
            && self.state_sync_enabled.is_none()
            && self.continuous_profiler_dir.is_none()
            && self.local_txs_enabled.is_none()
            && self.priority_regossip_addresses.is_none()
            && self.extra.is_empty()
    }
}

/// Genesis configuration for custom networks
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisConfig {
    /// Network ID
    pub network_id: u32,

    /// Initial allocations
    pub allocations: Vec<GenesisAllocation>,

    /// Start time
    pub start_time: u64,

    /// Initial staking duration (seconds)
    pub initial_stake_duration: u64,

    /// Initial staking duration offset (seconds)
    pub initial_stake_duration_offset: u64,

    /// Initial staked funds
    pub initial_staked_funds: Vec<String>,

    /// Initial stakers
    pub initial_stakers: Vec<InitialStaker>,

    /// C-Chain genesis
    pub c_chain_genesis: String,

    /// Message
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl GenesisConfig {
    /// Generate genesis file content as JSON
    pub fn to_genesis_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

/// Genesis allocation entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GenesisAllocation {
    /// Address (X/P chain format)
    #[serde(rename = "avaxAddr")]
    pub lux_addr: String,

    /// ETH address (C-chain)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eth_addr: Option<String>,

    /// Initial amount
    pub initial_amount: u64,

    /// Unlock schedule
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_schedule: Option<Vec<UnlockSchedule>>,
}

/// Unlock schedule entry
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UnlockSchedule {
    /// Locktime
    pub locktime: u64,
    /// Amount
    pub amount: u64,
}

/// Initial staker for genesis
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InitialStaker {
    /// Node ID
    pub node_id: String,
    /// Reward address
    pub reward_address: String,
    /// Delegation fee (basis points)
    pub delegation_fee: u32,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_luxd_config_default() {
        let config = LuxdConfig::default();
        assert_eq!(config.http_host, "0.0.0.0");
        assert_eq!(config.http_port, 9650);
        assert_eq!(config.staking_port, 9651);
        assert!(config.staking_enabled);
        assert_eq!(config.log_level, "info");
    }

    #[test]
    fn test_luxd_config_mainnet() {
        let config = LuxdConfig::mainnet();
        assert_eq!(config.network_id, Some(1));
    }

    #[test]
    fn test_luxd_config_testnet() {
        let config = LuxdConfig::testnet();
        assert_eq!(config.network_id, Some(5));
    }

    #[test]
    fn test_luxd_config_local() {
        let config = LuxdConfig::local(12345);
        assert_eq!(config.network_id, Some(12345));
        assert!(!config.staking_enabled);
    }

    #[test]
    fn test_to_cli_args() {
        let config = LuxdConfig {
            network_id: Some(1),
            http_host: "127.0.0.1".to_string(),
            http_port: 9650,
            staking_port: 9651,
            staking_enabled: true,
            log_level: "debug".to_string(),
            db_dir: Some(PathBuf::from("/data/db")),
            bootstrap_ips: Some("1.2.3.4:9651".to_string()),
            bootstrap_ids: Some("NodeID-abc123".to_string()),
            ..Default::default()
        };

        let args = config.to_cli_args();

        assert!(args.contains(&"--network-id=1".to_string()));
        assert!(args.contains(&"--http-host=127.0.0.1".to_string()));
        assert!(args.contains(&"--http-port=9650".to_string()));
        assert!(args.contains(&"--staking-port=9651".to_string()));
        assert!(args.contains(&"--staking-enabled=true".to_string()));
        assert!(args.contains(&"--log-level=debug".to_string()));
        assert!(args.contains(&"--db-dir=/data/db".to_string()));
        assert!(args.contains(&"--bootstrap-ips=1.2.3.4:9651".to_string()));
        assert!(args.contains(&"--bootstrap-ids=NodeID-abc123".to_string()));
    }

    #[test]
    fn test_to_config_json() {
        let config = LuxdConfig {
            network_id: Some(1),
            log_level: "info".to_string(),
            ..Default::default()
        };

        let json = config.to_config_json().unwrap();
        assert!(json.contains("\"network-id\""));
        assert!(json.contains("\"log-level\""));
    }

    #[test]
    fn test_with_bootstrap() {
        let mut config = LuxdConfig::default();
        config.with_bootstrap("1.2.3.4:9651,5.6.7.8:9651", "NodeID-abc,NodeID-def");

        assert_eq!(
            config.bootstrap_ips,
            Some("1.2.3.4:9651,5.6.7.8:9651".to_string())
        );
        assert_eq!(
            config.bootstrap_ids,
            Some("NodeID-abc,NodeID-def".to_string())
        );
    }

    #[test]
    fn test_with_staking_files() {
        let mut config = LuxdConfig::default();
        config.with_staking_files(
            PathBuf::from("/pki/staking.key"),
            PathBuf::from("/pki/staking.crt"),
            Some(PathBuf::from("/pki/signer.key")),
        );

        assert_eq!(
            config.staking_tls_key_file,
            Some(PathBuf::from("/pki/staking.key"))
        );
        assert_eq!(
            config.staking_tls_cert_file,
            Some(PathBuf::from("/pki/staking.crt"))
        );
        assert_eq!(
            config.staking_signer_key_file,
            Some(PathBuf::from("/pki/signer.key"))
        );
    }

    #[test]
    fn test_merge_config() {
        let mut base = LuxdConfig {
            network_id: Some(1),
            log_level: "info".to_string(),
            db_dir: Some(PathBuf::from("/data")),
            ..Default::default()
        };

        let override_cfg = LuxdConfig {
            log_level: "debug".to_string(),
            public_ip: Some("1.2.3.4".to_string()),
            ..Default::default()
        };

        base.merge(&override_cfg);

        assert_eq!(base.network_id, Some(1)); // preserved from base
        assert_eq!(base.log_level, "debug"); // overridden
        assert_eq!(base.public_ip, Some("1.2.3.4".to_string())); // added
        assert_eq!(base.db_dir, Some(PathBuf::from("/data"))); // preserved
    }

    #[test]
    fn test_c_chain_config_is_empty() {
        let empty = CChainConfig::default();
        assert!(empty.is_empty());

        let not_empty = CChainConfig {
            log_level: Some("debug".to_string()),
            ..Default::default()
        };
        assert!(!not_empty.is_empty());
    }

    #[test]
    fn test_c_chain_to_json() {
        let config = CChainConfig {
            pruning_enabled: Some(true),
            state_sync_enabled: Some(false),
            eth_apis: Some(vec!["eth".to_string(), "net".to_string()]),
            ..Default::default()
        };

        let json = config.to_config_json().unwrap();
        assert!(json.contains("\"pruning-enabled\""));
        assert!(json.contains("\"state-sync-enabled\""));
        assert!(json.contains("\"eth-apis\""));
    }

    #[test]
    fn test_genesis_config_to_json() {
        let genesis = GenesisConfig {
            network_id: 12345,
            allocations: vec![GenesisAllocation {
                lux_addr: "X-local1abc".to_string(),
                eth_addr: Some("0x1234".to_string()),
                initial_amount: 1_000_000_000_000,
                unlock_schedule: None,
            }],
            start_time: 1700000000,
            initial_stake_duration: 31536000,
            initial_stake_duration_offset: 0,
            initial_staked_funds: vec!["X-local1abc".to_string()],
            initial_stakers: vec![InitialStaker {
                node_id: "NodeID-abc123".to_string(),
                reward_address: "X-local1abc".to_string(),
                delegation_fee: 200000,
            }],
            c_chain_genesis: "{}".to_string(),
            message: Some("Test genesis".to_string()),
        };

        let json = genesis.to_genesis_json().unwrap();
        assert!(json.contains("\"networkId\""));
        assert!(json.contains("12345"));
        assert!(json.contains("\"allocations\""));
    }
}
