//! Core types for Lux Network operations

use serde::{Deserialize, Serialize};
use std::fmt;

/// Network identifier for Lux networks
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(from = "u32", into = "u32")]
pub struct NetworkId(pub u32);

impl NetworkId {
    /// Mainnet (network ID: 1)
    pub const MAINNET: Self = Self(1);
    /// Testnet (network ID: 5)
    pub const TESTNET: Self = Self(5);
    /// Local development network
    pub const LOCAL: Self = Self(12345);

    pub fn new(id: u32) -> Self {
        Self(id)
    }

    pub fn is_mainnet(&self) -> bool {
        self.0 == 1
    }

    pub fn is_testnet(&self) -> bool {
        self.0 == 5
    }
}

impl Default for NetworkId {
    fn default() -> Self {
        Self::LOCAL
    }
}

impl From<u32> for NetworkId {
    fn from(id: u32) -> Self {
        Self(id)
    }
}

impl From<NetworkId> for u32 {
    fn from(id: NetworkId) -> Self {
        id.0
    }
}

impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            1 => write!(f, "mainnet"),
            5 => write!(f, "testnet"),
            12345 => write!(f, "local"),
            id => write!(f, "custom-{}", id),
        }
    }
}

/// Node identifier (20-byte hash)
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeId(#[serde(with = "hex_serde")] pub [u8; 20]);

impl NodeId {
    pub fn from_bytes(bytes: [u8; 20]) -> Self {
        Self(bytes)
    }

    pub fn to_cb58_string(&self) -> String {
        format!("NodeID-{}", bs58::encode(&self.0).with_check().into_string())
    }
}

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_cb58_string())
    }
}

/// Chain types in Lux Network
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ChainType {
    /// X-Chain (Exchange Chain) - DAG-based
    X,
    /// P-Chain (Platform Chain) - Staking and subnets
    P,
    /// C-Chain (Contract Chain) - EVM compatible
    C,
}

impl fmt::Display for ChainType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::X => write!(f, "X"),
            Self::P => write!(f, "P"),
            Self::C => write!(f, "C"),
        }
    }
}

/// Represents a secp256k1 key pair info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KeyInfo {
    /// Private key in hex format (for testing only)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key_hex: Option<String>,
    /// Public key in hex format
    pub public_key_hex: String,
    /// X-Chain address
    pub x_address: String,
    /// P-Chain address
    pub p_address: String,
    /// C-Chain address (0x prefixed)
    pub c_address: String,
    /// Short address (for P-chain/X-chain)
    pub short_address: String,
}

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct NodeInfo {
    /// Machine ID (e.g., EC2 instance ID)
    pub machine_id: String,
    /// Node ID
    pub node_id: String,
    /// Public IP address
    pub public_ip: String,
    /// HTTP port
    pub http_port: u16,
    /// Staking port
    pub staking_port: u16,
    /// Region
    pub region: String,
    /// Is anchor/beacon node
    pub is_anchor: bool,
}

mod hex_serde {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(bytes: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    }
}

/// LUX denomination units
pub mod units {
    /// 1 nLUX = 1 (smallest unit)
    pub const NLUX: u64 = 1;
    /// 1 µLUX = 1,000 nLUX
    pub const ULUX: u64 = 1_000;
    /// 1 mLUX = 1,000,000 nLUX
    pub const MLUX: u64 = 1_000_000;
    /// 1 LUX = 1,000,000,000 nLUX
    pub const LUX: u64 = 1_000_000_000;

    /// Default staking amount (2000 LUX)
    pub const DEFAULT_STAKING_AMOUNT: u64 = 2_000 * LUX;
    /// Minimum staking amount (25 LUX for testnet)
    pub const MIN_STAKING_AMOUNT_TESTNET: u64 = 25 * LUX;
    /// Minimum staking amount (2000 LUX for mainnet)
    pub const MIN_STAKING_AMOUNT_MAINNET: u64 = 2_000 * LUX;
}

/// Well-known chain IDs
pub mod chain_ids {
    /// X-Chain alias
    pub const X_CHAIN: &str = "X";
    /// P-Chain alias
    pub const P_CHAIN: &str = "P";
    /// C-Chain alias
    pub const C_CHAIN: &str = "C";
}

/// Default ports
pub mod ports {
    /// Default HTTP API port
    pub const HTTP: u16 = 9650;
    /// Default staking port
    pub const STAKING: u16 = 9651;
    /// Default C-Chain websocket port
    pub const C_CHAIN_WS: u16 = 9650;
}
