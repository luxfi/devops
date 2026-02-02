//! Installation utilities for luxd artifacts

use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use lux_core::artifacts::{luxd_download_url, Arch};
use lux_core::LuxdConfig;
use sha2::{Digest, Sha256};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use tar::Archive;
use tracing::{debug, info, warn};

/// Default installation paths
const LUXD_BIN_PATH: &str = "/usr/local/bin/luxd";
const LUXD_PLUGINS_DIR: &str = "/var/lib/luxd/plugins";
const LUXD_CONFIG_DIR: &str = "/etc/luxd";
const LUXD_CHAIN_CONFIG_DIR: &str = "/etc/luxd/chains";
const LUXD_SUBNET_CONFIG_DIR: &str = "/etc/luxd/subnets";
const SYSTEMD_SERVICE_PATH: &str = "/etc/systemd/system/luxd.service";

/// Systemd service file template
const SYSTEMD_SERVICE_TEMPLATE: &str = r#"[Unit]
Description=Lux Network Node
Documentation=https://docs.lux.network
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=luxd
Group=luxd
ExecStart=/usr/local/bin/luxd --config-file=/etc/luxd/node.json
ExecStop=/bin/kill -SIGTERM $MAINPID
Restart=always
RestartSec=10
LimitNOFILE=65535

# Hardening
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/luxd /var/log/luxd /etc/luxd

# Environment
Environment="HOME=/var/lib/luxd"

[Install]
WantedBy=multi-user.target
"#;

/// Install luxd and related artifacts
pub async fn install_artifacts(
    s3_region: &str,
    s3_bucket: &str,
    luxd_s3_key: Option<&str>,
    luxd_local_path: Option<&str>,
    luxd_release_tag: Option<&str>,
    os_type: &str,
) -> Result<()> {
    info!("Installing artifacts from s3://{}", s3_bucket);
    info!("Region: {}, OS: {}", s3_region, os_type);

    // Initialize S3 client
    let aws_config = aws_config::from_env()
        .region(aws_config::Region::new(s3_region.to_string()))
        .load()
        .await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);

    // Determine architecture
    let arch = detect_architecture()?;
    info!("Detected architecture: {:?}", arch);

    // Get luxd binary from one of the sources
    let binary_path = if let Some(s3_key) = luxd_s3_key {
        info!("Downloading luxd from S3: {}", s3_key);
        download_from_s3(&s3_client, s3_bucket, s3_key).await?
    } else if let Some(tag) = luxd_release_tag {
        info!("Downloading luxd release: {}", tag);
        download_from_release(tag, arch).await?
    } else if let Some(path) = luxd_local_path {
        info!("Using local luxd: {}", path);
        PathBuf::from(path)
    } else {
        anyhow::bail!("No luxd source specified (s3_key, release_tag, or local_path required)");
    };

    // Install binary
    install_binary(&binary_path, LUXD_BIN_PATH)?;

    // Create system user if not exists
    create_system_user()?;

    // Create directories
    create_directories()?;

    // Write systemd service
    write_systemd_service()?;

    // Reload systemd
    reload_systemd()?;

    info!("Installation complete");
    Ok(())
}

/// Install subnet VM binary and config
pub async fn install_subnet(
    s3_region: &str,
    s3_bucket: &str,
    subnet_config_s3_key: Option<&str>,
    subnet_config_local_path: Option<&str>,
    vm_binary_s3_key: &str,
    vm_binary_local_path: &str,
    subnet_id: &str,
    luxd_config_path: &str,
) -> Result<()> {
    info!("Installing subnet {} VM", subnet_id);

    // Initialize S3 client
    let aws_config = aws_config::from_env()
        .region(aws_config::Region::new(s3_region.to_string()))
        .load()
        .await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);

    // Download and install VM binary
    info!("Downloading VM binary from S3: {}", vm_binary_s3_key);
    let vm_temp_path = download_from_s3(&s3_client, s3_bucket, vm_binary_s3_key).await?;
    install_binary(&vm_temp_path, vm_binary_local_path)?;

    // Install VM to plugins directory
    let vm_id = extract_vm_id(subnet_id)?;
    let plugin_path = PathBuf::from(LUXD_PLUGINS_DIR).join(&vm_id);
    fs::create_dir_all(LUXD_PLUGINS_DIR)?;
    fs::copy(vm_binary_local_path, &plugin_path)?;
    set_executable(&plugin_path)?;
    info!("Installed VM to {:?}", plugin_path);

    // Download subnet config if provided
    if let Some(s3_key) = subnet_config_s3_key {
        info!("Downloading subnet config from S3: {}", s3_key);
        let config_temp = download_from_s3(&s3_client, s3_bucket, s3_key).await?;
        let config_dir = PathBuf::from(LUXD_SUBNET_CONFIG_DIR);
        fs::create_dir_all(&config_dir)?;
        let config_dest = config_dir.join(format!("{}.json", subnet_id));
        fs::copy(&config_temp, &config_dest)?;
        info!("Installed subnet config to {:?}", config_dest);
    } else if let Some(local_path) = subnet_config_local_path {
        let config_dir = PathBuf::from(LUXD_SUBNET_CONFIG_DIR);
        fs::create_dir_all(&config_dir)?;
        let config_dest = config_dir.join(format!("{}.json", subnet_id));
        fs::copy(local_path, &config_dest)?;
        info!("Installed subnet config from {:?} to {:?}", local_path, config_dest);
    }

    // Update luxd config to track subnet
    update_track_subnets(luxd_config_path, subnet_id)?;

    // Restart node to pick up changes
    restart_luxd_service()?;

    info!("Subnet {} installation complete", subnet_id);
    Ok(())
}

/// Install chain configuration
pub async fn install_chain(
    s3_region: &str,
    s3_bucket: &str,
    chain_config_s3_key: &str,
    chain_config_local_path: &str,
) -> Result<()> {
    info!("Installing chain config from S3: s3://{}/{}", s3_bucket, chain_config_s3_key);

    // Initialize S3 client
    let aws_config = aws_config::from_env()
        .region(aws_config::Region::new(s3_region.to_string()))
        .load()
        .await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);

    // Download chain config
    let temp_path = download_from_s3(&s3_client, s3_bucket, chain_config_s3_key).await?;

    // Parse to validate JSON
    let config_contents = fs::read_to_string(&temp_path)?;
    let _: serde_json::Value = serde_json::from_str(&config_contents)
        .context("Invalid JSON in chain config")?;

    // Extract chain ID from path (e.g., "C/config.json" -> "C")
    let chain_id = extract_chain_id(chain_config_s3_key)?;

    // Create chain config directory
    let chain_dir = PathBuf::from(LUXD_CHAIN_CONFIG_DIR).join(&chain_id);
    fs::create_dir_all(&chain_dir)?;

    // Write config file
    let config_dest = chain_dir.join("config.json");
    fs::copy(&temp_path, &config_dest)?;
    info!("Installed chain config to {:?}", config_dest);

    // Copy to specified local path
    let local_path = PathBuf::from(chain_config_local_path);
    if let Some(parent) = local_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&temp_path, &local_path)?;
    info!("Also copied to {:?}", local_path);

    // Check if genesis file exists in S3 (same directory as config)
    let genesis_key = chain_config_s3_key.replace("config.json", "genesis.json");
    match download_from_s3(&s3_client, s3_bucket, &genesis_key).await {
        Ok(genesis_temp) => {
            let genesis_dest = chain_dir.join("genesis.json");
            fs::copy(&genesis_temp, &genesis_dest)?;
            info!("Installed genesis to {:?}", genesis_dest);
        }
        Err(_) => {
            debug!("No genesis file found at {}", genesis_key);
        }
    }

    // Restart node if running
    if is_luxd_running()? {
        info!("Restarting luxd to apply chain config");
        restart_luxd_service()?;
    }

    info!("Chain config installation complete");
    Ok(())
}

/// Detect system architecture
fn detect_architecture() -> Result<Arch> {
    let arch = std::env::consts::ARCH;
    Arch::from_str(arch).ok_or_else(|| anyhow::anyhow!("Unsupported architecture: {}", arch))
}

/// Download file from S3
async fn download_from_s3(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    key: &str,
) -> Result<PathBuf> {
    let response = client
        .get_object()
        .bucket(bucket)
        .key(key)
        .send()
        .await
        .context(format!("Failed to download s3://{}/{}", bucket, key))?;

    let body = response.body.collect().await?.into_bytes();

    // Create temp file
    let temp_file = tempfile::NamedTempFile::new()?;
    let temp_path = temp_file.path().to_path_buf();

    // Write to temp file
    let mut file = File::create(&temp_path)?;
    file.write_all(&body)?;
    file.sync_all()?;

    // Keep file (don't delete on drop)
    temp_file.keep()?;

    info!("Downloaded {} bytes from S3 to {:?}", body.len(), temp_path);
    Ok(temp_path)
}

/// Download from GitHub releases
async fn download_from_release(version: &str, arch: Arch) -> Result<PathBuf> {
    let url = luxd_download_url(version, arch);
    info!("Downloading from {}", url);

    let client = reqwest::Client::new();
    let response = client.get(&url).send().await?;

    if !response.status().is_success() {
        anyhow::bail!("Failed to download release: HTTP {}", response.status());
    }

    let bytes = response.bytes().await?;

    // Create temp directory for extraction
    let temp_dir = tempfile::tempdir()?;
    let archive_path = temp_dir.path().join("luxd.tar.gz");

    // Write archive
    fs::write(&archive_path, &bytes)?;
    info!("Downloaded {} bytes", bytes.len());

    // Extract tarball
    let tar_gz = File::open(&archive_path)?;
    let tar = GzDecoder::new(tar_gz);
    let mut archive = Archive::new(tar);
    archive.unpack(temp_dir.path())?;

    // Find luxd binary in extracted files
    let binary_path = find_luxd_binary(temp_dir.path())?;

    // Copy to a stable temp location
    let final_temp = tempfile::NamedTempFile::new()?;
    let final_path = final_temp.path().to_path_buf();
    fs::copy(&binary_path, &final_path)?;
    final_temp.keep()?;

    info!("Extracted luxd binary to {:?}", final_path);
    Ok(final_path)
}

/// Find luxd binary in extracted directory
fn find_luxd_binary(dir: &Path) -> Result<PathBuf> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if path.is_file() && path.file_name().map(|n| n == "luxd").unwrap_or(false) {
            return Ok(path);
        }

        if path.is_dir() {
            if let Ok(found) = find_luxd_binary(&path) {
                return Ok(found);
            }
        }
    }

    anyhow::bail!("luxd binary not found in extracted archive")
}

/// Install binary to destination
fn install_binary(source: &Path, dest: &str) -> Result<()> {
    let dest_path = Path::new(dest);

    // Create parent directories
    if let Some(parent) = dest_path.parent() {
        fs::create_dir_all(parent)?;
    }

    // Copy binary
    fs::copy(source, dest_path)?;

    // Set executable permissions
    set_executable(dest_path)?;

    // Verify binary
    verify_binary(dest_path)?;

    info!("Installed binary to {}", dest);
    Ok(())
}

/// Set executable permissions
fn set_executable(path: &Path) -> Result<()> {
    let mut perms = fs::metadata(path)?.permissions();
    perms.set_mode(0o755);
    fs::set_permissions(path, perms)?;
    Ok(())
}

/// Verify binary is valid
fn verify_binary(path: &Path) -> Result<()> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .context("Failed to execute binary")?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout);
        info!("Binary version: {}", version.trim());
        Ok(())
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("Binary verification failed: {}", stderr)
    }
}

/// Create system user for luxd
fn create_system_user() -> Result<()> {
    // Check if user exists
    let output = std::process::Command::new("id")
        .arg("luxd")
        .output()?;

    if output.status.success() {
        debug!("User luxd already exists");
        return Ok(());
    }

    info!("Creating system user: luxd");

    // Create group
    let _ = std::process::Command::new("groupadd")
        .args(["--system", "luxd"])
        .output();

    // Create user
    let status = std::process::Command::new("useradd")
        .args([
            "--system",
            "--gid", "luxd",
            "--home-dir", "/var/lib/luxd",
            "--shell", "/usr/sbin/nologin",
            "--comment", "Lux Network Node",
            "luxd",
        ])
        .status()?;

    if !status.success() {
        warn!("Failed to create user (may already exist)");
    }

    Ok(())
}

/// Create required directories
fn create_directories() -> Result<()> {
    let dirs = [
        "/var/lib/luxd",
        "/var/lib/luxd/plugins",
        "/var/lib/luxd/db",
        "/var/lib/luxd/staking",
        "/var/log/luxd",
        "/etc/luxd",
        "/etc/luxd/chains",
        "/etc/luxd/subnets",
    ];

    for dir in &dirs {
        fs::create_dir_all(dir)?;
        debug!("Created directory: {}", dir);
    }

    // Set ownership
    let _ = std::process::Command::new("chown")
        .args(["-R", "luxd:luxd", "/var/lib/luxd", "/var/log/luxd", "/etc/luxd"])
        .output();

    info!("Created required directories");
    Ok(())
}

/// Write systemd service file
fn write_systemd_service() -> Result<()> {
    fs::write(SYSTEMD_SERVICE_PATH, SYSTEMD_SERVICE_TEMPLATE)?;
    info!("Wrote systemd service to {}", SYSTEMD_SERVICE_PATH);
    Ok(())
}

/// Reload systemd daemon
fn reload_systemd() -> Result<()> {
    let status = std::process::Command::new("systemctl")
        .arg("daemon-reload")
        .status()?;

    if !status.success() {
        warn!("Failed to reload systemd daemon");
    }

    // Enable service
    let _ = std::process::Command::new("systemctl")
        .args(["enable", "luxd"])
        .output();

    info!("Reloaded systemd and enabled luxd service");
    Ok(())
}

/// Extract VM ID from subnet ID
fn extract_vm_id(subnet_id: &str) -> Result<String> {
    // In production, this would be fetched from the P-chain
    // For now, use the subnet ID as VM ID placeholder
    if subnet_id.starts_with("subnetevm-") || subnet_id.starts_with("srEXiWaH") {
        Ok(subnet_id.to_string())
    } else {
        // Hash the subnet ID to create a consistent VM ID
        let mut hasher = Sha256::new();
        hasher.update(subnet_id.as_bytes());
        let hash = hasher.finalize();
        Ok(hex::encode(&hash[..20]))
    }
}

/// Extract chain ID from S3 key path
fn extract_chain_id(s3_key: &str) -> Result<String> {
    // Expected format: "cluster/chains/{chain_id}/config.json"
    let parts: Vec<&str> = s3_key.split('/').collect();

    // Look for chains directory
    for (i, part) in parts.iter().enumerate() {
        if *part == "chains" && i + 1 < parts.len() {
            return Ok(parts[i + 1].to_string());
        }
    }

    // Fallback: use filename without extension
    let filename = parts.last().unwrap_or(&"config.json");
    if filename.ends_with(".json") {
        Ok(filename.trim_end_matches(".json").to_string())
    } else {
        Ok(filename.to_string())
    }
}

/// Update track-subnets in luxd config
fn update_track_subnets(config_path: &str, subnet_id: &str) -> Result<()> {
    let path = Path::new(config_path);

    let mut config: LuxdConfig = if path.exists() {
        let contents = fs::read_to_string(path)?;
        serde_json::from_str(&contents)?
    } else {
        LuxdConfig::default()
    };

    // Update track-subnets
    let current = config.track_subnets.unwrap_or_default();
    let subnets: Vec<&str> = current.split(',').filter(|s| !s.is_empty()).collect();

    if !subnets.contains(&subnet_id) {
        let mut new_subnets = subnets.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        new_subnets.push(subnet_id.to_string());
        config.track_subnets = Some(new_subnets.join(","));

        // Write updated config
        let contents = serde_json::to_string_pretty(&config)?;
        fs::write(path, contents)?;
        info!("Updated track-subnets in {:?}", path);
    }

    Ok(())
}

/// Check if luxd service is running
fn is_luxd_running() -> Result<bool> {
    let output = std::process::Command::new("systemctl")
        .args(["is-active", "luxd"])
        .output()?;

    Ok(output.status.success())
}

/// Restart luxd systemd service
fn restart_luxd_service() -> Result<()> {
    info!("Restarting luxd service");

    let status = std::process::Command::new("systemctl")
        .args(["restart", "luxd"])
        .status()?;

    if status.success() {
        info!("Service restarted successfully");
    } else {
        warn!("Service restart may have failed");
    }

    Ok(())
}

/// Calculate SHA256 checksum of file
#[allow(dead_code)]
fn calculate_checksum(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; 8192];

    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        hasher.update(&buffer[..bytes_read]);
    }

    Ok(hex::encode(hasher.finalize()))
}

/// Verify file checksum
#[allow(dead_code)]
fn verify_checksum(path: &Path, expected: &str) -> Result<()> {
    let actual = calculate_checksum(path)?;
    if actual.eq_ignore_ascii_case(expected) {
        info!("Checksum verified: {}", actual);
        Ok(())
    } else {
        anyhow::bail!("Checksum mismatch: expected {}, got {}", expected, actual)
    }
}
