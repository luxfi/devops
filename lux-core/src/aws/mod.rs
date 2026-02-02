//! AWS infrastructure management for Lux Network

pub mod cfn;
pub mod luxd;

use serde::{Deserialize, Serialize};

/// AWS STS Identity
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct Identity {
    pub account_id: String,
    pub user_id: String,
    pub arn: String,
}

/// EC2 instance state
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct InstanceInfo {
    pub instance_id: String,
    pub region: String,
    pub availability_zone: String,
    pub instance_type: String,
    pub public_ip: Option<String>,
    pub private_ip: String,
    pub state: String,
    pub launch_time: String,
}

/// S3 object metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct S3ObjectMeta {
    pub bucket: String,
    pub key: String,
    pub size: u64,
    pub etag: Option<String>,
    pub last_modified: Option<String>,
}

/// S3 upload options
#[derive(Debug, Clone, Default)]
pub struct S3UploadOptions {
    /// Server-side encryption algorithm (e.g., "aws:kms", "AES256")
    pub server_side_encryption: Option<String>,
    /// KMS key ID for encryption (when using aws:kms)
    pub kms_key_id: Option<String>,
    /// Content type
    pub content_type: Option<String>,
    /// Cache control header
    pub cache_control: Option<String>,
    /// Additional metadata
    pub metadata: std::collections::HashMap<String, String>,
}

impl S3UploadOptions {
    /// Create options with KMS encryption
    pub fn with_kms(key_id: impl Into<String>) -> Self {
        Self {
            server_side_encryption: Some("aws:kms".to_string()),
            kms_key_id: Some(key_id.into()),
            ..Default::default()
        }
    }

    /// Create options with AES256 encryption
    pub fn with_aes256() -> Self {
        Self {
            server_side_encryption: Some("AES256".to_string()),
            ..Default::default()
        }
    }

    /// Set content type
    pub fn content_type(mut self, content_type: impl Into<String>) -> Self {
        self.content_type = Some(content_type.into());
        self
    }

    /// Add metadata
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// S3 path helper
#[derive(Debug, Clone)]
pub struct S3Path {
    pub bucket: String,
    pub key: String,
}

impl S3Path {
    pub fn new(bucket: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            bucket: bucket.into(),
            key: key.into(),
        }
    }

    /// Parse from s3://bucket/key format
    pub fn from_uri(uri: &str) -> Option<Self> {
        let uri = uri.strip_prefix("s3://")?;
        let (bucket, key) = uri.split_once('/')?;
        Some(Self::new(bucket, key))
    }

    /// Convert to s3://bucket/key format
    pub fn to_uri(&self) -> String {
        format!("s3://{}/{}", self.bucket, self.key)
    }

    /// Join a path component
    pub fn join(&self, path: &str) -> Self {
        let key = if self.key.ends_with('/') || self.key.is_empty() {
            format!("{}{}", self.key, path.trim_start_matches('/'))
        } else {
            format!("{}/{}", self.key, path.trim_start_matches('/'))
        };
        Self::new(&self.bucket, key)
    }
}

/// Common S3 key prefixes for lux-ops
pub mod s3_prefixes {
    /// Bootstrap files (genesis, staking info)
    pub const BOOTSTRAP: &str = "bootstrap";
    /// PKI files (TLS certs, keys)
    pub const PKI: &str = "pki";
    /// Discovery files (node info)
    pub const DISCOVER: &str = "discover";
    /// Backup files
    pub const BACKUPS: &str = "backups";
    /// Event logs
    pub const EVENTS: &str = "events";
    /// Artifacts (binaries, plugins)
    pub const ARTIFACTS: &str = "artifacts";
    /// SSM output logs
    pub const SSM_LOGS: &str = "ssm-output-logs";
}

/// Generate S3 key for cluster resource
pub fn cluster_s3_key(cluster_id: &str, prefix: &str, path: &str) -> String {
    format!("{}/{}/{}", cluster_id, prefix, path.trim_start_matches('/'))
}

/// Generate S3 key for node PKI files
pub fn node_pki_s3_key(cluster_id: &str, node_id: &str, filename: &str) -> String {
    cluster_s3_key(cluster_id, s3_prefixes::PKI, &format!("{}/{}", node_id, filename))
}

/// Generate S3 key for bootstrap files
pub fn bootstrap_s3_key(cluster_id: &str, filename: &str) -> String {
    cluster_s3_key(cluster_id, s3_prefixes::BOOTSTRAP, filename)
}

/// Generate S3 key for discovery files
pub fn discover_s3_key(cluster_id: &str, node_id: &str) -> String {
    cluster_s3_key(cluster_id, s3_prefixes::DISCOVER, &format!("{}.yaml", node_id))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_s3_path_from_uri() {
        let path = S3Path::from_uri("s3://my-bucket/path/to/file.txt");
        assert!(path.is_some());
        let path = path.unwrap();
        assert_eq!(path.bucket, "my-bucket");
        assert_eq!(path.key, "path/to/file.txt");
    }

    #[test]
    fn test_s3_path_to_uri() {
        let path = S3Path::new("my-bucket", "path/to/file.txt");
        assert_eq!(path.to_uri(), "s3://my-bucket/path/to/file.txt");
    }

    #[test]
    fn test_s3_path_join() {
        let path = S3Path::new("bucket", "prefix");
        let joined = path.join("subpath/file.txt");
        assert_eq!(joined.key, "prefix/subpath/file.txt");

        let path2 = S3Path::new("bucket", "prefix/");
        let joined2 = path2.join("/subpath");
        assert_eq!(joined2.key, "prefix/subpath");
    }

    #[test]
    fn test_s3_upload_options() {
        let opts = S3UploadOptions::with_kms("my-key-id")
            .content_type("application/octet-stream")
            .with_metadata("x-custom", "value");

        assert_eq!(opts.server_side_encryption, Some("aws:kms".to_string()));
        assert_eq!(opts.kms_key_id, Some("my-key-id".to_string()));
        assert_eq!(opts.content_type, Some("application/octet-stream".to_string()));
        assert_eq!(opts.metadata.get("x-custom"), Some(&"value".to_string()));
    }

    #[test]
    fn test_cluster_s3_key() {
        let key = cluster_s3_key("cluster-1", "bootstrap", "genesis.json");
        assert_eq!(key, "cluster-1/bootstrap/genesis.json");
    }

    #[test]
    fn test_node_pki_s3_key() {
        let key = node_pki_s3_key("cluster-1", "NodeID-abc123", "staking.key");
        assert_eq!(key, "cluster-1/pki/NodeID-abc123/staking.key");
    }

    #[test]
    fn test_discover_s3_key() {
        let key = discover_s3_key("cluster-1", "NodeID-abc123");
        assert_eq!(key, "cluster-1/discover/NodeID-abc123.yaml");
    }
}
