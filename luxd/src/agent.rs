//! Agent module - runs on cloud instances to manage Lux node lifecycle

use anyhow::{Context, Result};
use aws_sdk_cloudwatch::types::{Dimension, MetricDatum, StandardUnit};
use aws_sdk_s3::primitives::ByteStream;
use lux_core::LuxdConfig;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// Default paths for luxd
const LUXD_BIN: &str = "/usr/local/bin/luxd";
const LUXD_DATA_DIR: &str = "/var/lib/luxd";
const LUXD_CONFIG_DIR: &str = "/etc/luxd";
const LUXD_LOG_DIR: &str = "/var/log/luxd";
const CONFIG_WATCH_INTERVAL: Duration = Duration::from_secs(30);
const HEALTH_REPORT_INTERVAL: Duration = Duration::from_secs(60);
const PROCESS_CHECK_INTERVAL: Duration = Duration::from_secs(5);

/// Agent state stored in S3
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentState {
    pub instance_id: String,
    pub node_id: Option<String>,
    pub public_ip: Option<String>,
    pub private_ip: String,
    pub region: String,
    pub status: NodeStatus,
    pub last_heartbeat: String,
    pub version: String,
    pub config_hash: String,
}

/// Node status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    Starting,
    Running,
    Bootstrapping,
    Healthy,
    Unhealthy,
    Stopped,
}

/// Agent configuration
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub s3_region: String,
    pub s3_bucket: String,
    pub cluster_id: String,
    pub instance_id: String,
    pub region: String,
    pub private_ip: String,
    pub public_ip: Option<String>,
    pub use_default_config: bool,
    pub publish_periodic_node_info: bool,
}

impl AgentConfig {
    /// Load from EC2 instance metadata and environment
    pub async fn from_environment() -> Result<Self> {
        let instance_id = get_instance_metadata("instance-id").await?;
        let region = get_instance_metadata("placement/region").await?;
        let private_ip = get_instance_metadata("local-ipv4").await?;
        let public_ip = get_instance_metadata("public-ipv4").await.ok();

        // Cluster ID and S3 bucket from instance tags or environment
        let s3_bucket = std::env::var("LUX_S3_BUCKET")
            .context("LUX_S3_BUCKET environment variable required")?;
        let cluster_id = std::env::var("LUX_CLUSTER_ID")
            .context("LUX_CLUSTER_ID environment variable required")?;

        Ok(Self {
            s3_region: region.clone(),
            s3_bucket,
            cluster_id,
            instance_id,
            region,
            private_ip,
            public_ip,
            use_default_config: false,
            publish_periodic_node_info: true,
        })
    }
}

/// Agent commands
enum AgentCommand {
    Shutdown,
    Restart,
    ReloadConfig,
}

/// Run the agent daemon
pub async fn run(use_default_config: bool, publish_periodic_node_info: bool) -> Result<()> {
    info!("Initializing agent (default_config={}, publish_info={})",
        use_default_config, publish_periodic_node_info);

    // Set up signal handlers
    let shutdown = Arc::new(AtomicBool::new(false));
    let shutdown_signal = shutdown.clone();

    tokio::spawn(async move {
        let mut sigterm = tokio::signal::unix::signal(
            tokio::signal::unix::SignalKind::terminate()
        ).expect("Failed to install SIGTERM handler");

        tokio::select! {
            _ = sigterm.recv() => {
                info!("Received SIGTERM, initiating graceful shutdown");
                shutdown_signal.store(true, Ordering::SeqCst);
            }
            _ = tokio::signal::ctrl_c() => {
                info!("Received SIGINT, initiating graceful shutdown");
                shutdown_signal.store(true, Ordering::SeqCst);
            }
        }
    });

    // Load configuration
    let mut config = AgentConfig::from_environment().await?;
    config.use_default_config = use_default_config;
    config.publish_periodic_node_info = publish_periodic_node_info;

    // Initialize AWS clients
    let aws_config = aws_config::from_env()
        .region(aws_config::Region::new(config.s3_region.clone()))
        .load()
        .await;
    let s3_client = aws_sdk_s3::Client::new(&aws_config);
    let cw_client = aws_sdk_cloudwatch::Client::new(&aws_config);

    // Create command channel
    let (cmd_tx, mut cmd_rx) = mpsc::channel::<AgentCommand>(16);

    // Load node configuration from S3 or use defaults
    let luxd_config = load_node_config(&s3_client, &config).await?;
    let config_path = write_node_config(&luxd_config)?;
    let mut config_hash = hash_config(&luxd_config)?;

    // Start luxd process
    let mut luxd_process = start_luxd(&config_path).await?;
    let mut node_status = NodeStatus::Starting;

    info!("Agent main loop starting");

    // Main loop
    let mut health_ticker = tokio::time::interval(HEALTH_REPORT_INTERVAL);
    let mut config_ticker = tokio::time::interval(CONFIG_WATCH_INTERVAL);
    let mut process_ticker = tokio::time::interval(PROCESS_CHECK_INTERVAL);

    loop {
        if shutdown.load(Ordering::SeqCst) {
            info!("Shutdown signal received, stopping luxd");
            graceful_shutdown(&mut luxd_process).await?;
            break;
        }

        tokio::select! {
            // Handle commands
            Some(cmd) = cmd_rx.recv() => {
                match cmd {
                    AgentCommand::Shutdown => {
                        info!("Shutdown command received");
                        graceful_shutdown(&mut luxd_process).await?;
                        break;
                    }
                    AgentCommand::Restart => {
                        info!("Restart command received");
                        graceful_shutdown(&mut luxd_process).await?;
                        luxd_process = start_luxd(&config_path).await?;
                        node_status = NodeStatus::Starting;
                    }
                    AgentCommand::ReloadConfig => {
                        info!("Config reload command received");
                        let new_config = load_node_config(&s3_client, &config).await?;
                        let new_hash = hash_config(&new_config)?;
                        if new_hash != config_hash {
                            info!("Configuration changed, restarting node");
                            write_node_config(&new_config)?;
                            graceful_shutdown(&mut luxd_process).await?;
                            luxd_process = start_luxd(&config_path).await?;
                            config_hash = new_hash;
                            node_status = NodeStatus::Starting;
                        }
                    }
                }
            }

            // Check process health
            _ = process_ticker.tick() => {
                match luxd_process.try_wait() {
                    Ok(Some(status)) => {
                        error!("luxd process exited with status: {:?}", status);
                        node_status = NodeStatus::Stopped;

                        // Restart after brief delay
                        tokio::time::sleep(Duration::from_secs(5)).await;
                        info!("Restarting luxd process");
                        luxd_process = start_luxd(&config_path).await?;
                        node_status = NodeStatus::Starting;
                    }
                    Ok(None) => {
                        // Process still running
                        if node_status == NodeStatus::Starting {
                            // Check if node is responsive
                            if check_node_health().await.is_ok() {
                                node_status = NodeStatus::Running;
                                info!("Node is now running");
                            }
                        } else if node_status == NodeStatus::Running {
                            // Check bootstrap status
                            match check_bootstrap_status().await {
                                Ok(true) => {
                                    if node_status != NodeStatus::Healthy {
                                        node_status = NodeStatus::Healthy;
                                        info!("Node is healthy and bootstrapped");
                                    }
                                }
                                Ok(false) => {
                                    node_status = NodeStatus::Bootstrapping;
                                }
                                Err(e) => {
                                    debug!("Bootstrap check failed: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to check process status: {}", e);
                    }
                }
            }

            // Report health to control plane
            _ = health_ticker.tick() => {
                if config.publish_periodic_node_info {
                    let node_id = get_node_id().await.ok();
                    let state = AgentState {
                        instance_id: config.instance_id.clone(),
                        node_id,
                        public_ip: config.public_ip.clone(),
                        private_ip: config.private_ip.clone(),
                        region: config.region.clone(),
                        status: node_status.clone(),
                        last_heartbeat: chrono::Utc::now().to_rfc3339(),
                        version: env!("CARGO_PKG_VERSION").to_string(),
                        config_hash: config_hash.clone(),
                    };

                    if let Err(e) = publish_node_state(&s3_client, &config, &state).await {
                        warn!("Failed to publish node state: {}", e);
                    }

                    if let Err(e) = publish_metrics(&cw_client, &config, &node_status).await {
                        warn!("Failed to publish metrics: {}", e);
                    }
                }
            }

            // Watch for configuration changes
            _ = config_ticker.tick() => {
                let new_config = match load_node_config(&s3_client, &config).await {
                    Ok(c) => c,
                    Err(e) => {
                        warn!("Failed to load config from S3: {}", e);
                        continue;
                    }
                };

                let new_hash = hash_config(&new_config)?;
                if new_hash != config_hash {
                    info!("Configuration changed (old={}, new={})", config_hash, new_hash);
                    if let Err(e) = cmd_tx.send(AgentCommand::ReloadConfig).await {
                        error!("Failed to send reload command: {}", e);
                    }
                }
            }
        }
    }

    info!("Agent shutdown complete");
    Ok(())
}

/// Get EC2 instance metadata
async fn get_instance_metadata(path: &str) -> Result<String> {
    let client = reqwest::Client::new();

    // Get IMDSv2 token
    let token = client
        .put("http://169.254.169.254/latest/api/token")
        .header("X-aws-ec2-metadata-token-ttl-seconds", "21600")
        .send()
        .await?
        .text()
        .await?;

    // Get metadata with token
    let url = format!("http://169.254.169.254/latest/meta-data/{}", path);
    let response = client
        .get(&url)
        .header("X-aws-ec2-metadata-token", &token)
        .send()
        .await?
        .text()
        .await?;

    Ok(response)
}

/// Load node configuration from S3
async fn load_node_config(
    s3_client: &aws_sdk_s3::Client,
    config: &AgentConfig,
) -> Result<LuxdConfig> {
    if config.use_default_config {
        info!("Using default node configuration");
        return Ok(LuxdConfig::default());
    }

    let key = format!("{}/config/{}/node.json", config.cluster_id, config.instance_id);

    match s3_client
        .get_object()
        .bucket(&config.s3_bucket)
        .key(&key)
        .send()
        .await
    {
        Ok(response) => {
            let body = response.body.collect().await?.into_bytes();
            let config: LuxdConfig = serde_json::from_slice(&body)?;
            info!("Loaded node configuration from S3: {}", key);
            Ok(config)
        }
        Err(e) => {
            warn!("Failed to load config from S3 ({}), using default: {}", key, e);
            Ok(LuxdConfig::default())
        }
    }
}

/// Write node configuration to disk
fn write_node_config(config: &LuxdConfig) -> Result<PathBuf> {
    let config_dir = Path::new(LUXD_CONFIG_DIR);
    std::fs::create_dir_all(config_dir)?;

    let config_path = config_dir.join("node.json");
    let contents = serde_json::to_string_pretty(config)?;
    std::fs::write(&config_path, contents)?;

    info!("Wrote node configuration to {:?}", config_path);
    Ok(config_path)
}

/// Hash configuration for change detection
fn hash_config(config: &LuxdConfig) -> Result<String> {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_string(config)?;
    let hash = Sha256::digest(json.as_bytes());
    Ok(hex::encode(&hash[..8]))
}

/// Start luxd process
async fn start_luxd(config_path: &Path) -> Result<Child> {
    info!("Starting luxd with config: {:?}", config_path);

    // Ensure directories exist
    std::fs::create_dir_all(LUXD_DATA_DIR)?;
    std::fs::create_dir_all(LUXD_LOG_DIR)?;

    let mut cmd = Command::new(LUXD_BIN);
    cmd.arg("--config-file")
        .arg(config_path)
        .arg("--data-dir")
        .arg(LUXD_DATA_DIR)
        .arg("--log-dir")
        .arg(LUXD_LOG_DIR)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);

    let mut child = cmd.spawn().context("Failed to spawn luxd process")?;

    // Spawn log readers
    if let Some(stdout) = child.stdout.take() {
        tokio::spawn(async move {
            let reader = BufReader::new(stdout);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                debug!(target: "luxd", "{}", line);
            }
        });
    }

    if let Some(stderr) = child.stderr.take() {
        tokio::spawn(async move {
            let reader = BufReader::new(stderr);
            let mut lines = reader.lines();
            while let Ok(Some(line)) = lines.next_line().await {
                warn!(target: "luxd", "{}", line);
            }
        });
    }

    info!("luxd process started (pid: {:?})", child.id());
    Ok(child)
}

/// Gracefully shutdown luxd process
async fn graceful_shutdown(process: &mut Child) -> Result<()> {
    info!("Initiating graceful shutdown of luxd");

    // Send SIGTERM
    if let Some(pid) = process.id() {
        unsafe {
            libc::kill(pid as i32, libc::SIGTERM);
        }
    }

    // Wait up to 30 seconds for graceful shutdown
    let timeout = Duration::from_secs(30);
    match tokio::time::timeout(timeout, process.wait()).await {
        Ok(Ok(status)) => {
            info!("luxd exited with status: {:?}", status);
        }
        Ok(Err(e)) => {
            warn!("Error waiting for luxd: {}", e);
        }
        Err(_) => {
            warn!("Timeout waiting for luxd graceful shutdown, sending SIGKILL");
            process.kill().await?;
        }
    }

    Ok(())
}

/// Check if node is healthy (API responding)
async fn check_node_health() -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .post("http://127.0.0.1:9650/ext/health")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "health.health",
            "params": {}
        }))
        .send()
        .await?;

    if response.status().is_success() {
        Ok(())
    } else {
        anyhow::bail!("Health check failed with status: {}", response.status())
    }
}

/// Check bootstrap status
async fn check_bootstrap_status() -> Result<bool> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .post("http://127.0.0.1:9650/ext/info")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "info.isBootstrapped",
            "params": { "chain": "X" }
        }))
        .send()
        .await?;

    #[derive(Deserialize)]
    struct Response {
        result: Option<BootstrapResult>,
    }

    #[derive(Deserialize)]
    struct BootstrapResult {
        #[serde(rename = "isBootstrapped")]
        is_bootstrapped: bool,
    }

    let body: Response = response.json().await?;
    Ok(body.result.map(|r| r.is_bootstrapped).unwrap_or(false))
}

/// Get node ID from running node
async fn get_node_id() -> Result<String> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;

    let response = client
        .post("http://127.0.0.1:9650/ext/info")
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "info.getNodeID",
            "params": {}
        }))
        .send()
        .await?;

    #[derive(Deserialize)]
    struct Response {
        result: Option<NodeIdResult>,
    }

    #[derive(Deserialize)]
    struct NodeIdResult {
        #[serde(rename = "nodeID")]
        node_id: String,
    }

    let body: Response = response.json().await?;
    body.result
        .map(|r| r.node_id)
        .ok_or_else(|| anyhow::anyhow!("No nodeID in response"))
}

/// Publish node state to S3
async fn publish_node_state(
    s3_client: &aws_sdk_s3::Client,
    config: &AgentConfig,
    state: &AgentState,
) -> Result<()> {
    let key = format!("{}/nodes/{}/state.json", config.cluster_id, config.instance_id);
    let body = serde_json::to_string_pretty(state)?;

    s3_client
        .put_object()
        .bucket(&config.s3_bucket)
        .key(&key)
        .body(ByteStream::from(body.into_bytes()))
        .content_type("application/json")
        .send()
        .await?;

    debug!("Published node state to S3: {}", key);
    Ok(())
}

/// Publish metrics to CloudWatch
async fn publish_metrics(
    cw_client: &aws_sdk_cloudwatch::Client,
    config: &AgentConfig,
    status: &NodeStatus,
) -> Result<()> {
    let status_value = match status {
        NodeStatus::Healthy => 1.0,
        NodeStatus::Running | NodeStatus::Bootstrapping => 0.5,
        _ => 0.0,
    };

    let dimension = Dimension::builder()
        .name("InstanceId")
        .value(&config.instance_id)
        .build();

    let metric = MetricDatum::builder()
        .metric_name("NodeHealth")
        .value(status_value)
        .unit(StandardUnit::None)
        .dimensions(dimension)
        .build();

    cw_client
        .put_metric_data()
        .namespace(format!("Lux/{}", config.cluster_id))
        .metric_data(metric)
        .send()
        .await?;

    debug!("Published metrics to CloudWatch");
    Ok(())
}
