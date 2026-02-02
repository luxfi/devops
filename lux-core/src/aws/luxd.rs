//! Luxd daemon configuration for AWS

use serde::{Deserialize, Serialize};

/// Flags for the luxd daemon (agent running on AWS instances)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub struct Flags {
    /// Log level
    #[serde(default = "default_log_level")]
    pub log_level: String,

    /// Use default config
    #[serde(default)]
    pub use_default_config: bool,

    /// Publish periodic node info to S3
    #[serde(default = "default_true")]
    pub publish_periodic_node_info: bool,
}

fn default_log_level() -> String {
    "info".to_string()
}

fn default_true() -> bool {
    true
}
