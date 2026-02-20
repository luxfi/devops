//! Staking Key/Cert Downloader
//!
//! Downloads TLS staking key and certificate from S3 with KMS decryption.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::Path;

use anyhow::{anyhow, Context, Result};
use aws_config::BehaviorVersion;
use aws_sdk_kms::primitives::Blob;
use aws_sdk_kms::types::EncryptionAlgorithmSpec;
use aws_sdk_kms::Client as KmsClient;
use aws_sdk_s3::Client as S3Client;
use clap::Parser;
use flate2::read::GzDecoder;
use tracing::{debug, info, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "staking-key-downloader";

const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Download staking TLS key/cert from S3")]
#[command(version)]
struct Cli {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// S3 region
    #[arg(long)]
    s3_region: String,

    /// S3 bucket
    #[arg(long)]
    s3_bucket: String,

    /// S3 key for TLS key
    #[arg(long)]
    s3_key_tls_key: String,

    /// S3 key for TLS cert
    #[arg(long)]
    s3_key_tls_cert: String,

    /// KMS region
    #[arg(long)]
    kms_region: String,

    /// KMS key ID for decryption
    #[arg(long)]
    kms_key_id: String,

    /// AAD tag for envelope encryption
    #[arg(long)]
    aad_tag: String,

    /// Local path to save TLS key
    #[arg(long)]
    tls_key_path: String,

    /// Local path to save TLS cert
    #[arg(long)]
    tls_cert_path: String,

    /// AWS profile name
    #[arg(long, default_value = "default")]
    profile_name: String,
}

/// Download object from S3
async fn download_from_s3(client: &S3Client, bucket: &str, key: &str) -> Result<Vec<u8>> {
    debug!("Downloading s3://{}/{}", bucket, key);

    let resp = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .with_context(|| format!("Failed to download s3://{}/{}", bucket, key))?;

    let data = resp
        .body
        .collect()
        .await
        .with_context(|| format!("Failed to read body from s3://{}/{}", bucket, key))?
        .into_bytes()
        .to_vec();

    debug!(
        "Downloaded {} bytes from s3://{}/{}",
        data.len(),
        bucket,
        key
    );
    Ok(data)
}

/// Decrypt data using KMS with AAD tag
async fn decrypt_with_kms(
    client: &KmsClient,
    key_id: &str,
    ciphertext: &[u8],
    aad_tag: &str,
) -> Result<Vec<u8>> {
    debug!(
        "Decrypting {} bytes with KMS key {}",
        ciphertext.len(),
        key_id
    );

    let resp = client
        .decrypt()
        .key_id(key_id)
        .ciphertext_blob(Blob::new(ciphertext))
        .encryption_algorithm(EncryptionAlgorithmSpec::RsaesOaepSha256)
        .encryption_context("AAD", aad_tag)
        .send()
        .await
        .context("KMS decryption failed")?;

    let plaintext = resp
        .plaintext()
        .ok_or_else(|| anyhow!("KMS returned no plaintext"))?
        .as_ref()
        .to_vec();

    debug!("Decrypted to {} bytes", plaintext.len());
    Ok(plaintext)
}

/// Decompress data if gzip compressed
fn decompress_if_needed(data: Vec<u8>) -> Result<Vec<u8>> {
    if data.len() >= 2 && data[0] == GZIP_MAGIC[0] && data[1] == GZIP_MAGIC[1] {
        debug!("Detected gzip compression, decompressing");
        let mut decoder = GzDecoder::new(&data[..]);
        let mut decompressed = Vec::new();
        decoder
            .read_to_end(&mut decompressed)
            .context("Failed to decompress gzip data")?;
        debug!(
            "Decompressed {} -> {} bytes",
            data.len(),
            decompressed.len()
        );
        Ok(decompressed)
    } else {
        debug!("No compression detected");
        Ok(data)
    }
}

/// Write data to file with specified permissions
fn write_file(path: &str, data: &[u8], mode: u32) -> Result<()> {
    let path = Path::new(path);

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory {:?}", parent))?;
    }

    let mut file =
        File::create(path).with_context(|| format!("Failed to create file {}", path.display()))?;

    file.write_all(data)
        .with_context(|| format!("Failed to write to {}", path.display()))?;

    file.sync_all()
        .with_context(|| format!("Failed to sync {}", path.display()))?;

    let perms = fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms)
        .with_context(|| format!("Failed to set permissions on {}", path.display()))?;

    debug!(
        "Wrote {} bytes to {} with mode {:o}",
        data.len(),
        path.display(),
        mode
    );
    Ok(())
}

/// Download, decrypt, decompress, and write a single file
async fn process_file(
    s3_client: &S3Client,
    kms_client: &KmsClient,
    bucket: &str,
    s3_key: &str,
    kms_key_id: &str,
    aad_tag: &str,
    local_path: &str,
    mode: u32,
) -> Result<()> {
    let encrypted = download_from_s3(s3_client, bucket, s3_key).await?;
    let decrypted = decrypt_with_kms(kms_client, kms_key_id, &encrypted, aad_tag).await?;
    let data = decompress_if_needed(decrypted)?;
    write_file(local_path, &data, mode)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let level = match cli.log_level.to_lowercase().as_str() {
        "trace" => Level::TRACE,
        "debug" => Level::DEBUG,
        "info" => Level::INFO,
        "warn" => Level::WARN,
        "error" => Level::ERROR,
        _ => Level::INFO,
    };

    let subscriber = FmtSubscriber::builder()
        .with_max_level(level)
        .with_target(true)
        .finish();

    tracing::subscriber::set_global_default(subscriber)?;

    info!("Starting {}", APP_NAME);
    info!("S3 bucket: {}/{}", cli.s3_region, cli.s3_bucket);
    info!("TLS key: {} -> {}", cli.s3_key_tls_key, cli.tls_key_path);
    info!("TLS cert: {} -> {}", cli.s3_key_tls_cert, cli.tls_cert_path);

    let s3_config = aws_config::defaults(BehaviorVersion::latest())
        .profile_name(&cli.profile_name)
        .region(aws_config::Region::new(cli.s3_region.clone()))
        .load()
        .await;

    let kms_config = aws_config::defaults(BehaviorVersion::latest())
        .profile_name(&cli.profile_name)
        .region(aws_config::Region::new(cli.kms_region.clone()))
        .load()
        .await;

    let s3_client = S3Client::new(&s3_config);
    let kms_client = KmsClient::new(&kms_config);

    info!("Downloading TLS key");
    process_file(
        &s3_client,
        &kms_client,
        &cli.s3_bucket,
        &cli.s3_key_tls_key,
        &cli.kms_key_id,
        &cli.aad_tag,
        &cli.tls_key_path,
        0o600,
    )
    .await
    .context("Failed to process TLS key")?;

    info!("Downloading TLS cert");
    process_file(
        &s3_client,
        &kms_client,
        &cli.s3_bucket,
        &cli.s3_key_tls_cert,
        &cli.kms_key_id,
        &cli.aad_tag,
        &cli.tls_cert_path,
        0o644,
    )
    .await
    .context("Failed to process TLS cert")?;

    info!("Download complete");
    Ok(())
}
