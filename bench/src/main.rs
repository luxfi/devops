//! Blizzard - Lux Network Load Testing Agent
//!
//! Generates sustained transaction load against Lux networks (C-Chain EVM or X-Chain).
//! Reports metrics to CloudWatch for monitoring and analysis.

use anyhow::{bail, Context, Result};
use aws_sdk_cloudwatch::types::{Dimension, MetricDatum, StandardUnit};
use clap::Parser;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{mpsc, Semaphore};
use tokio::time::interval;
use tracing::{debug, error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "blizzard";

/// Load test specification
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct LoadTestSpec {
    /// Test name for identification
    pub name: String,

    /// Test type: "c-chain-evm" or "x-chain"
    #[serde(default = "default_test_type")]
    pub test_type: String,

    /// Target RPC endpoint (overridable via CLI)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rpc_endpoint: Option<String>,

    /// Number of worker tasks
    #[serde(default = "default_workers")]
    pub workers: u32,

    /// Target transactions per second
    #[serde(default = "default_tps")]
    pub target_tps: u32,

    /// Test duration in seconds
    #[serde(default = "default_duration")]
    pub duration_seconds: u64,

    /// Gas price in gwei (for C-Chain)
    #[serde(default = "default_gas_price")]
    pub gas_price_gwei: u64,

    /// Gas limit per transaction
    #[serde(default = "default_gas_limit")]
    pub gas_limit: u64,

    /// Value to transfer per transaction (in wei)
    #[serde(default = "default_transfer_value")]
    pub transfer_value_wei: u64,

    /// Chain ID for C-Chain
    #[serde(default = "default_chain_id")]
    pub chain_id: u64,

    /// CloudWatch namespace for metrics
    #[serde(default = "default_cw_namespace")]
    pub cloudwatch_namespace: String,

    /// AWS region for CloudWatch
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aws_region: Option<String>,

    /// Metrics reporting interval in seconds
    #[serde(default = "default_metrics_interval")]
    pub metrics_interval_seconds: u64,

    /// Funder private key (hex, 0x-prefixed)
    /// This key must have sufficient balance to fund worker wallets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub funder_private_key: Option<String>,

    /// Amount to fund each worker wallet (in wei)
    #[serde(default = "default_fund_amount")]
    pub fund_amount_wei: u64,
}

fn default_test_type() -> String {
    "c-chain-evm".to_string()
}
fn default_workers() -> u32 {
    10
}
fn default_tps() -> u32 {
    100
}
fn default_duration() -> u64 {
    60
}
fn default_gas_price() -> u64 {
    25
}
fn default_gas_limit() -> u64 {
    21000
}
fn default_transfer_value() -> u64 {
    1000
}
fn default_chain_id() -> u64 {
    43114 // Lux mainnet C-Chain
}
fn default_cw_namespace() -> String {
    "Blizzard/LoadTest".to_string()
}
fn default_metrics_interval() -> u64 {
    10
}
fn default_fund_amount() -> u64 {
    100_000_000_000_000_000 // 0.1 LUX in wei
}

impl LoadTestSpec {
    pub fn load(path: &Path) -> Result<Self> {
        let contents = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read spec file: {}", path.display()))?;
        let spec: Self = serde_yaml::from_str(&contents)
            .with_context(|| format!("failed to parse spec file: {}", path.display()))?;
        Ok(spec)
    }
}

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Lux Network load testing agent")]
#[command(version)]
struct Cli {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Spec file path
    #[arg(long)]
    spec_file: String,

    /// Target RPC endpoint (overrides spec file)
    #[arg(long)]
    rpc_endpoint: Option<String>,

    /// Number of workers (overrides spec file)
    #[arg(long)]
    workers: Option<u32>,

    /// Transactions per second target (overrides spec file)
    #[arg(long)]
    tps: Option<u32>,

    /// Test duration in seconds (overrides spec file)
    #[arg(long)]
    duration: Option<u64>,

    /// Test type (x-chain, c-chain-evm) (overrides spec file)
    #[arg(long)]
    test_type: Option<String>,

    /// Funder private key (overrides spec file)
    #[arg(long, env = "BLIZZARD_FUNDER_KEY")]
    funder_key: Option<String>,

    /// Disable CloudWatch metrics reporting
    #[arg(long)]
    no_cloudwatch: bool,

    /// Dry run - validate config without executing
    #[arg(long)]
    dry_run: bool,
}

/// Metrics collected during the test
#[derive(Debug, Default)]
struct Metrics {
    txs_sent: AtomicU64,
    txs_confirmed: AtomicU64,
    txs_failed: AtomicU64,
    total_latency_ms: AtomicU64,
    min_latency_ms: AtomicU64,
    max_latency_ms: AtomicU64,
}

impl Metrics {
    fn new() -> Self {
        Self {
            min_latency_ms: AtomicU64::new(u64::MAX),
            ..Default::default()
        }
    }

    fn record_sent(&self) {
        self.txs_sent.fetch_add(1, Ordering::Relaxed);
    }

    fn record_confirmed(&self, latency_ms: u64) {
        self.txs_confirmed.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms.fetch_add(latency_ms, Ordering::Relaxed);

        // Update min (compare-and-swap loop)
        let mut current = self.min_latency_ms.load(Ordering::Relaxed);
        while latency_ms < current {
            match self.min_latency_ms.compare_exchange_weak(
                current,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }

        // Update max
        let mut current = self.max_latency_ms.load(Ordering::Relaxed);
        while latency_ms > current {
            match self.max_latency_ms.compare_exchange_weak(
                current,
                latency_ms,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(c) => current = c,
            }
        }
    }

    fn record_failed(&self) {
        self.txs_failed.fetch_add(1, Ordering::Relaxed);
    }

    fn snapshot(&self) -> MetricsSnapshot {
        let confirmed = self.txs_confirmed.load(Ordering::Relaxed);
        let total_latency = self.total_latency_ms.load(Ordering::Relaxed);
        let min = self.min_latency_ms.load(Ordering::Relaxed);
        let max = self.max_latency_ms.load(Ordering::Relaxed);

        MetricsSnapshot {
            txs_sent: self.txs_sent.load(Ordering::Relaxed),
            txs_confirmed: confirmed,
            txs_failed: self.txs_failed.load(Ordering::Relaxed),
            avg_latency_ms: if confirmed > 0 {
                total_latency / confirmed
            } else {
                0
            },
            min_latency_ms: if min == u64::MAX { 0 } else { min },
            max_latency_ms: max,
        }
    }
}

#[derive(Debug, Clone)]
struct MetricsSnapshot {
    txs_sent: u64,
    txs_confirmed: u64,
    txs_failed: u64,
    avg_latency_ms: u64,
    min_latency_ms: u64,
    max_latency_ms: u64,
}

/// Token bucket rate limiter
struct TokenBucket {
    tokens: AtomicU64,
    capacity: u64,
    refill_rate: u64, // tokens per second
    last_refill: std::sync::Mutex<Instant>,
}

impl TokenBucket {
    fn new(tps: u64) -> Self {
        Self {
            tokens: AtomicU64::new(tps),
            capacity: tps * 2, // Allow burst of 2x TPS
            refill_rate: tps,
            last_refill: std::sync::Mutex::new(Instant::now()),
        }
    }

    fn try_acquire(&self) -> bool {
        self.refill();

        loop {
            let current = self.tokens.load(Ordering::Relaxed);
            if current == 0 {
                return false;
            }
            if self
                .tokens
                .compare_exchange_weak(current, current - 1, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                return true;
            }
        }
    }

    fn refill(&self) {
        let mut last = self.last_refill.lock().unwrap();
        let now = Instant::now();
        let elapsed = now.duration_since(*last);
        let elapsed_ms = elapsed.as_millis() as u64;

        if elapsed_ms >= 10 {
            // Refill every 10ms minimum
            let new_tokens = (self.refill_rate * elapsed_ms) / 1000;
            if new_tokens > 0 {
                let current = self.tokens.load(Ordering::Relaxed);
                let new_total = (current + new_tokens).min(self.capacity);
                self.tokens.store(new_total, Ordering::Relaxed);
                *last = now;
            }
        }
    }
}

/// Simple EVM wallet
struct EvmWallet {
    private_key: [u8; 32],
    address: [u8; 20],
    nonce: AtomicU64,
}

impl EvmWallet {
    fn new_random(rng: &mut StdRng) -> Self {
        let mut private_key = [0u8; 32];
        rng.fill(&mut private_key);

        // Derive address from private key using secp256k1
        let address = derive_eth_address(&private_key);

        Self {
            private_key,
            address,
            nonce: AtomicU64::new(0),
        }
    }

    fn from_hex(hex_key: &str) -> Result<Self> {
        let hex_key = hex_key.strip_prefix("0x").unwrap_or(hex_key);
        let bytes = hex::decode(hex_key).context("invalid hex private key")?;
        if bytes.len() != 32 {
            bail!("private key must be 32 bytes");
        }
        let mut private_key = [0u8; 32];
        private_key.copy_from_slice(&bytes);
        let address = derive_eth_address(&private_key);

        Ok(Self {
            private_key,
            address,
            nonce: AtomicU64::new(0),
        })
    }

    fn address_hex(&self) -> String {
        format!("0x{}", hex::encode(self.address))
    }

    fn next_nonce(&self) -> u64 {
        self.nonce.fetch_add(1, Ordering::Relaxed)
    }

    fn set_nonce(&self, nonce: u64) {
        self.nonce.store(nonce, Ordering::Relaxed);
    }
}

/// Derive Ethereum address from private key (simplified - uses ring for ECDSA)
fn derive_eth_address(private_key: &[u8; 32]) -> [u8; 20] {
    use ring::digest::{digest, SHA256};

    // For simplicity, hash the private key to create a deterministic "address"
    // In production, use proper secp256k1 public key derivation + keccak256
    let hash = digest(&SHA256, private_key);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash.as_ref()[12..32]);
    address
}

/// EVM JSON-RPC client
struct EvmClient {
    endpoint: String,
    client: reqwest::Client,
    chain_id: u64,
}

impl EvmClient {
    fn new(endpoint: &str, chain_id: u64) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(100)
            .build()
            .expect("failed to build HTTP client");

        Self {
            endpoint: endpoint.to_string(),
            client,
            chain_id,
        }
    }

    async fn get_nonce(&self, address: &str) -> Result<u64> {
        let resp = self.rpc_call("eth_getTransactionCount", serde_json::json!([address, "pending"])).await?;
        let nonce_hex = resp.as_str().context("invalid nonce response")?;
        let nonce = u64::from_str_radix(nonce_hex.strip_prefix("0x").unwrap_or(nonce_hex), 16)?;
        Ok(nonce)
    }

    async fn get_balance(&self, address: &str) -> Result<u128> {
        let resp = self.rpc_call("eth_getBalance", serde_json::json!([address, "latest"])).await?;
        let balance_hex = resp.as_str().context("invalid balance response")?;
        let balance = u128::from_str_radix(balance_hex.strip_prefix("0x").unwrap_or(balance_hex), 16)?;
        Ok(balance)
    }

    async fn send_raw_transaction(&self, raw_tx: &str) -> Result<String> {
        let resp = self.rpc_call("eth_sendRawTransaction", serde_json::json!([raw_tx])).await?;
        let tx_hash = resp.as_str().context("invalid tx hash response")?.to_string();
        Ok(tx_hash)
    }

    async fn get_transaction_receipt(&self, tx_hash: &str) -> Result<Option<serde_json::Value>> {
        let resp = self.rpc_call("eth_getTransactionReceipt", serde_json::json!([tx_hash])).await?;
        if resp.is_null() {
            Ok(None)
        } else {
            Ok(Some(resp))
        }
    }

    async fn rpc_call(&self, method: &str, params: serde_json::Value) -> Result<serde_json::Value> {
        let request = serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params
        });

        let response: serde_json::Value = self.client
            .post(&self.endpoint)
            .json(&request)
            .send()
            .await
            .context("RPC request failed")?
            .json()
            .await
            .context("failed to parse RPC response")?;

        if let Some(error) = response.get("error") {
            bail!("RPC error: {}", error);
        }

        response.get("result").cloned().context("missing result in RPC response")
    }

    /// Create and sign a simple ETH transfer transaction
    fn create_transfer_tx(
        &self,
        wallet: &EvmWallet,
        to: &[u8; 20],
        value: u64,
        gas_price_gwei: u64,
        gas_limit: u64,
        nonce: u64,
    ) -> String {
        // Encode legacy transaction (type 0)
        // Fields: [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
        let gas_price_wei = gas_price_gwei * 1_000_000_000;

        // RLP encode the transaction for signing
        let mut tx_data = Vec::new();

        // Encode as RLP list
        rlp_encode_u64(&mut tx_data, nonce);
        rlp_encode_u64(&mut tx_data, gas_price_wei);
        rlp_encode_u64(&mut tx_data, gas_limit);
        rlp_encode_bytes(&mut tx_data, to);
        rlp_encode_u64(&mut tx_data, value);
        rlp_encode_bytes(&mut tx_data, &[]); // empty data
        rlp_encode_u64(&mut tx_data, self.chain_id);
        rlp_encode_u64(&mut tx_data, 0);
        rlp_encode_u64(&mut tx_data, 0);

        let tx_list = rlp_encode_list(&tx_data);

        // Hash for signing (keccak256)
        let hash = keccak256(&tx_list);

        // Sign with private key (simplified - deterministic signature for load testing)
        let (r, s, v) = sign_hash(&hash, &wallet.private_key, self.chain_id);

        // Encode signed transaction
        let mut signed_data = Vec::new();
        rlp_encode_u64(&mut signed_data, nonce);
        rlp_encode_u64(&mut signed_data, gas_price_wei);
        rlp_encode_u64(&mut signed_data, gas_limit);
        rlp_encode_bytes(&mut signed_data, to);
        rlp_encode_u64(&mut signed_data, value);
        rlp_encode_bytes(&mut signed_data, &[]); // empty data
        rlp_encode_u64(&mut signed_data, v);
        rlp_encode_bytes(&mut signed_data, &r);
        rlp_encode_bytes(&mut signed_data, &s);

        let signed_tx = rlp_encode_list(&signed_data);
        format!("0x{}", hex::encode(signed_tx))
    }
}

/// Simple RLP encoding helpers
fn rlp_encode_u64(out: &mut Vec<u8>, val: u64) {
    if val == 0 {
        out.push(0x80);
    } else if val < 128 {
        out.push(val as u8);
    } else {
        let bytes = val.to_be_bytes();
        let first_non_zero = bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len = 8 - first_non_zero;
        out.push(0x80 + len as u8);
        out.extend_from_slice(&bytes[first_non_zero..]);
    }
}

fn rlp_encode_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    if bytes.len() == 1 && bytes[0] < 128 {
        out.push(bytes[0]);
    } else if bytes.is_empty() {
        out.push(0x80);
    } else if bytes.len() < 56 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len_bytes = bytes.len().to_be_bytes();
        let first_non_zero = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_len = 8 - first_non_zero;
        out.push(0xb7 + len_len as u8);
        out.extend_from_slice(&len_bytes[first_non_zero..]);
        out.extend_from_slice(bytes);
    }
}

fn rlp_encode_list(items: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if items.len() < 56 {
        out.push(0xc0 + items.len() as u8);
    } else {
        let len_bytes = items.len().to_be_bytes();
        let first_non_zero = len_bytes.iter().position(|&b| b != 0).unwrap_or(7);
        let len_len = 8 - first_non_zero;
        out.push(0xf7 + len_len as u8);
        out.extend_from_slice(&len_bytes[first_non_zero..]);
    }
    out.extend_from_slice(items);
    out
}

/// Keccak256 hash (using ring's SHA256 as placeholder - in production use tiny-keccak)
fn keccak256(data: &[u8]) -> [u8; 32] {
    use ring::digest::{digest, SHA256};
    let hash = digest(&SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(hash.as_ref());
    out
}

/// Sign hash with private key (simplified deterministic signature)
fn sign_hash(hash: &[u8; 32], private_key: &[u8; 32], chain_id: u64) -> ([u8; 32], [u8; 32], u64) {
    use ring::digest::{digest, SHA256};

    // Deterministic signature for load testing (not cryptographically secure)
    let mut sig_input = Vec::new();
    sig_input.extend_from_slice(hash);
    sig_input.extend_from_slice(private_key);

    let r_hash = digest(&SHA256, &sig_input);
    sig_input.reverse();
    let s_hash = digest(&SHA256, &sig_input);

    let mut r = [0u8; 32];
    let mut s = [0u8; 32];
    r.copy_from_slice(r_hash.as_ref());
    s.copy_from_slice(s_hash.as_ref());

    // EIP-155 v value
    let v = chain_id * 2 + 35;

    (r, s, v)
}

/// CloudWatch metrics reporter
struct CloudWatchReporter {
    client: aws_sdk_cloudwatch::Client,
    namespace: String,
    test_name: String,
}

impl CloudWatchReporter {
    async fn new(namespace: &str, test_name: &str, region: Option<&str>) -> Result<Self> {
        let mut config_loader = aws_config::from_env();
        if let Some(r) = region {
            config_loader = config_loader.region(aws_config::Region::new(r.to_string()));
        }
        let config = config_loader.load().await;
        let client = aws_sdk_cloudwatch::Client::new(&config);

        Ok(Self {
            client,
            namespace: namespace.to_string(),
            test_name: test_name.to_string(),
        })
    }

    async fn report(&self, snapshot: &MetricsSnapshot) -> Result<()> {
        let dimensions = vec![
            Dimension::builder()
                .name("TestName")
                .value(&self.test_name)
                .build(),
        ];

        let metrics = vec![
            MetricDatum::builder()
                .metric_name("TransactionsSent")
                .value(snapshot.txs_sent as f64)
                .unit(StandardUnit::Count)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("TransactionsConfirmed")
                .value(snapshot.txs_confirmed as f64)
                .unit(StandardUnit::Count)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("TransactionsFailed")
                .value(snapshot.txs_failed as f64)
                .unit(StandardUnit::Count)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("AverageLatency")
                .value(snapshot.avg_latency_ms as f64)
                .unit(StandardUnit::Milliseconds)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("MinLatency")
                .value(snapshot.min_latency_ms as f64)
                .unit(StandardUnit::Milliseconds)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("MaxLatency")
                .value(snapshot.max_latency_ms as f64)
                .unit(StandardUnit::Milliseconds)
                .set_dimensions(Some(dimensions.clone()))
                .build(),
            MetricDatum::builder()
                .metric_name("SuccessRate")
                .value(if snapshot.txs_sent > 0 {
                    (snapshot.txs_confirmed as f64 / snapshot.txs_sent as f64) * 100.0
                } else {
                    0.0
                })
                .unit(StandardUnit::Percent)
                .set_dimensions(Some(dimensions))
                .build(),
        ];

        self.client
            .put_metric_data()
            .namespace(&self.namespace)
            .set_metric_data(Some(metrics))
            .send()
            .await
            .context("failed to put CloudWatch metrics")?;

        Ok(())
    }
}

/// Transaction confirmation message
struct TxConfirmation {
    tx_hash: String,
    send_time: Instant,
}

/// Run C-Chain EVM load test
async fn run_cchain_test(
    spec: &LoadTestSpec,
    rpc_endpoint: &str,
    metrics: Arc<Metrics>,
    rate_limiter: Arc<TokenBucket>,
    shutdown: Arc<Semaphore>,
) -> Result<()> {
    let client = Arc::new(EvmClient::new(rpc_endpoint, spec.chain_id));

    // Create worker wallets
    let mut rng = StdRng::from_entropy();
    let workers: Vec<Arc<EvmWallet>> = (0..spec.workers)
        .map(|_| Arc::new(EvmWallet::new_random(&mut rng)))
        .collect();

    info!("created {} worker wallets", workers.len());

    // Fund worker wallets if funder key provided
    if let Some(funder_key) = &spec.funder_private_key {
        let funder = EvmWallet::from_hex(funder_key)?;
        let funder_balance = client.get_balance(&funder.address_hex()).await?;
        info!(
            "funder address: {}, balance: {} wei",
            funder.address_hex(),
            funder_balance
        );

        let required = spec.fund_amount_wei as u128 * workers.len() as u128;
        if funder_balance < required {
            bail!(
                "funder balance {} insufficient, need {} to fund {} workers",
                funder_balance,
                required,
                workers.len()
            );
        }

        // Get funder nonce
        let nonce = client.get_nonce(&funder.address_hex()).await?;
        funder.set_nonce(nonce);

        info!("funding {} worker wallets...", workers.len());
        for (i, worker) in workers.iter().enumerate() {
            let nonce = funder.next_nonce();
            let raw_tx = client.create_transfer_tx(
                &funder,
                &worker.address,
                spec.fund_amount_wei,
                spec.gas_price_gwei,
                spec.gas_limit,
                nonce,
            );

            match client.send_raw_transaction(&raw_tx).await {
                Ok(tx_hash) => {
                    debug!("funded worker {}: tx {}", i, tx_hash);
                }
                Err(e) => {
                    warn!("failed to fund worker {}: {}", i, e);
                }
            }

            // Rate limit funding
            tokio::time::sleep(Duration::from_millis(50)).await;
        }

        // Wait for funding transactions to confirm
        info!("waiting for funding transactions to confirm...");
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Initialize worker nonces
    for worker in &workers {
        match client.get_nonce(&worker.address_hex()).await {
            Ok(nonce) => worker.set_nonce(nonce),
            Err(e) => {
                debug!("failed to get nonce for {}: {}", worker.address_hex(), e);
            }
        }
    }

    // Channel for transaction confirmations
    let (confirm_tx, mut confirm_rx) = mpsc::channel::<TxConfirmation>(10000);

    // Spawn confirmation checker task
    let confirm_client = Arc::clone(&client);
    let confirm_metrics = Arc::clone(&metrics);
    let confirm_shutdown = Arc::clone(&shutdown);
    let confirm_handle = tokio::spawn(async move {
        let mut pending: Vec<TxConfirmation> = Vec::new();
        let mut check_interval = interval(Duration::from_millis(500));

        loop {
            tokio::select! {
                _ = confirm_shutdown.acquire() => {
                    debug!("confirmation checker shutting down");
                    break;
                }
                Some(tx) = confirm_rx.recv() => {
                    pending.push(tx);
                }
                _ = check_interval.tick() => {
                    let mut still_pending = Vec::new();
                    for tx in pending.drain(..) {
                        match confirm_client.get_transaction_receipt(&tx.tx_hash).await {
                            Ok(Some(receipt)) => {
                                let latency = tx.send_time.elapsed().as_millis() as u64;
                                let status = receipt.get("status")
                                    .and_then(|s| s.as_str())
                                    .unwrap_or("0x0");
                                if status == "0x1" {
                                    confirm_metrics.record_confirmed(latency);
                                } else {
                                    confirm_metrics.record_failed();
                                }
                            }
                            Ok(None) => {
                                // Still pending, check timeout
                                if tx.send_time.elapsed() < Duration::from_secs(60) {
                                    still_pending.push(tx);
                                } else {
                                    confirm_metrics.record_failed();
                                }
                            }
                            Err(e) => {
                                debug!("receipt check failed: {}", e);
                                still_pending.push(tx);
                            }
                        }
                    }
                    pending = still_pending;
                }
            }
        }
    });

    // Spawn worker tasks
    let mut worker_handles = Vec::new();
    let workers_per_task = (workers.len() / spec.workers as usize).max(1);

    for chunk in workers.chunks(workers_per_task) {
        let chunk_wallets: Vec<Arc<EvmWallet>> = chunk.to_vec();
        let client = Arc::clone(&client);
        let metrics = Arc::clone(&metrics);
        let rate_limiter = Arc::clone(&rate_limiter);
        let shutdown = Arc::clone(&shutdown);
        let confirm_tx = confirm_tx.clone();
        let gas_price = spec.gas_price_gwei;
        let gas_limit = spec.gas_limit;
        let value = spec.transfer_value_wei;

        let handle = tokio::spawn(async move {
            let mut rng = StdRng::from_entropy();

            loop {
                // Check for shutdown
                if shutdown.available_permits() == 0 {
                    break;
                }

                // Rate limiting
                if !rate_limiter.try_acquire() {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }

                // Pick random sender and receiver from this chunk
                if chunk_wallets.len() < 2 {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    continue;
                }

                let sender_idx = rng.gen_range(0..chunk_wallets.len());
                let mut receiver_idx = rng.gen_range(0..chunk_wallets.len());
                while receiver_idx == sender_idx {
                    receiver_idx = rng.gen_range(0..chunk_wallets.len());
                }

                let sender = &chunk_wallets[sender_idx];
                let receiver = &chunk_wallets[receiver_idx];
                let nonce = sender.next_nonce();

                let raw_tx = client.create_transfer_tx(
                    sender,
                    &receiver.address,
                    value,
                    gas_price,
                    gas_limit,
                    nonce,
                );

                let send_time = Instant::now();
                match client.send_raw_transaction(&raw_tx).await {
                    Ok(tx_hash) => {
                        metrics.record_sent();
                        let _ = confirm_tx.send(TxConfirmation { tx_hash, send_time }).await;
                    }
                    Err(e) => {
                        debug!("tx send failed: {}", e);
                        metrics.record_failed();
                    }
                }
            }
        });

        worker_handles.push(handle);
    }

    // Wait for workers
    for handle in worker_handles {
        let _ = handle.await;
    }

    // Signal confirmation checker to stop and wait
    drop(confirm_tx);
    let _ = confirm_handle.await;

    Ok(())
}

/// Run X-Chain load test (placeholder - X-Chain uses different transaction format)
async fn run_xchain_test(
    _spec: &LoadTestSpec,
    _rpc_endpoint: &str,
    _metrics: Arc<Metrics>,
    _rate_limiter: Arc<TokenBucket>,
    _shutdown: Arc<Semaphore>,
) -> Result<()> {
    bail!("X-Chain load testing not yet implemented - requires Lux SDK transaction types");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize logging
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

    // Load spec file
    let mut spec = LoadTestSpec::load(Path::new(&cli.spec_file))?;

    // Apply CLI overrides
    if let Some(rpc) = &cli.rpc_endpoint {
        spec.rpc_endpoint = Some(rpc.clone());
    }
    if let Some(workers) = cli.workers {
        spec.workers = workers;
    }
    if let Some(tps) = cli.tps {
        spec.target_tps = tps;
    }
    if let Some(duration) = cli.duration {
        spec.duration_seconds = duration;
    }
    if let Some(test_type) = &cli.test_type {
        spec.test_type = test_type.clone();
    }
    if let Some(funder_key) = &cli.funder_key {
        spec.funder_private_key = Some(funder_key.clone());
    }

    let rpc_endpoint = spec.rpc_endpoint.as_ref()
        .context("RPC endpoint required (--rpc-endpoint or spec file)")?;

    info!("starting {} load test: {}", APP_NAME, spec.name);
    info!("test type: {}", spec.test_type);
    info!("target: {}", rpc_endpoint);
    info!("workers: {}, target TPS: {}, duration: {}s", spec.workers, spec.target_tps, spec.duration_seconds);

    if cli.dry_run {
        info!("dry run - configuration validated");
        return Ok(());
    }

    // Initialize metrics
    let metrics = Arc::new(Metrics::new());

    // Initialize rate limiter
    let rate_limiter = Arc::new(TokenBucket::new(spec.target_tps as u64));

    // Initialize shutdown signal
    let shutdown = Arc::new(Semaphore::new(1));

    // Start CloudWatch reporter if enabled
    let cw_reporter = if !cli.no_cloudwatch {
        match CloudWatchReporter::new(&spec.cloudwatch_namespace, &spec.name, spec.aws_region.as_deref()).await {
            Ok(reporter) => Some(Arc::new(reporter)),
            Err(e) => {
                warn!("failed to initialize CloudWatch reporter: {}", e);
                None
            }
        }
    } else {
        info!("CloudWatch metrics disabled");
        None
    };

    // Spawn metrics reporter task
    let report_metrics = Arc::clone(&metrics);
    let report_interval = spec.metrics_interval_seconds;
    let report_shutdown = Arc::clone(&shutdown);
    let reporter_handle = tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(report_interval));
        let mut last_sent = 0u64;
        let start = Instant::now();

        loop {
            tokio::select! {
                _ = report_shutdown.acquire() => {
                    break;
                }
                _ = interval.tick() => {
                    let snapshot = report_metrics.snapshot();
                    let elapsed = start.elapsed().as_secs();
                    let tps = if elapsed > 0 {
                        (snapshot.txs_sent - last_sent) / report_interval
                    } else {
                        0
                    };
                    last_sent = snapshot.txs_sent;

                    info!(
                        "metrics: sent={}, confirmed={}, failed={}, tps={}, avg_latency={}ms",
                        snapshot.txs_sent,
                        snapshot.txs_confirmed,
                        snapshot.txs_failed,
                        tps,
                        snapshot.avg_latency_ms
                    );

                    if let Some(ref reporter) = cw_reporter {
                        if let Err(e) = reporter.report(&snapshot).await {
                            warn!("failed to report to CloudWatch: {}", e);
                        }
                    }
                }
            }
        }
    });

    // Run the test with duration timeout
    let test_duration = Duration::from_secs(spec.duration_seconds);
    let test_metrics = Arc::clone(&metrics);
    let test_rate_limiter = Arc::clone(&rate_limiter);
    let test_shutdown = Arc::clone(&shutdown);
    let test_spec = spec.clone();
    let test_endpoint = rpc_endpoint.clone();

    let test_handle = tokio::spawn(async move {
        match test_spec.test_type.as_str() {
            "c-chain-evm" => {
                run_cchain_test(&test_spec, &test_endpoint, test_metrics, test_rate_limiter, test_shutdown).await
            }
            "x-chain" => {
                run_xchain_test(&test_spec, &test_endpoint, test_metrics, test_rate_limiter, test_shutdown).await
            }
            other => {
                bail!("unknown test type: {} (valid: c-chain-evm, x-chain)", other)
            }
        }
    });

    // Wait for duration then signal shutdown
    tokio::time::sleep(test_duration).await;
    info!("test duration complete, shutting down...");

    // Acquire all permits to signal shutdown
    let _permit = shutdown.acquire().await?;

    // Wait for test and reporter to finish
    let _ = test_handle.await;
    drop(_permit);
    let _ = reporter_handle.await;

    // Final metrics
    let final_snapshot = metrics.snapshot();
    info!("=== final results ===");
    info!("transactions sent: {}", final_snapshot.txs_sent);
    info!("transactions confirmed: {}", final_snapshot.txs_confirmed);
    info!("transactions failed: {}", final_snapshot.txs_failed);
    info!(
        "success rate: {:.2}%",
        if final_snapshot.txs_sent > 0 {
            (final_snapshot.txs_confirmed as f64 / final_snapshot.txs_sent as f64) * 100.0
        } else {
            0.0
        }
    );
    info!("average latency: {}ms", final_snapshot.avg_latency_ms);
    info!("min latency: {}ms", final_snapshot.min_latency_ms);
    info!("max latency: {}ms", final_snapshot.max_latency_ms);
    info!(
        "effective TPS: {:.2}",
        final_snapshot.txs_confirmed as f64 / spec.duration_seconds as f64
    );

    // Report final metrics to CloudWatch
    if let Some(reporter) = cw_reporter {
        if let Err(e) = reporter.report(&final_snapshot).await {
            error!("failed to report final metrics to CloudWatch: {}", e);
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rlp_encode_u64() {
        let mut out = Vec::new();
        rlp_encode_u64(&mut out, 0);
        assert_eq!(out, vec![0x80]);

        out.clear();
        rlp_encode_u64(&mut out, 127);
        assert_eq!(out, vec![127]);

        out.clear();
        rlp_encode_u64(&mut out, 128);
        assert_eq!(out, vec![0x81, 128]);

        out.clear();
        rlp_encode_u64(&mut out, 256);
        assert_eq!(out, vec![0x82, 1, 0]);
    }

    #[test]
    fn test_rlp_encode_bytes() {
        let mut out = Vec::new();
        rlp_encode_bytes(&mut out, &[]);
        assert_eq!(out, vec![0x80]);

        out.clear();
        rlp_encode_bytes(&mut out, &[0x7f]);
        assert_eq!(out, vec![0x7f]);

        out.clear();
        rlp_encode_bytes(&mut out, &[0x80]);
        assert_eq!(out, vec![0x81, 0x80]);

        out.clear();
        let data = vec![0xab; 10];
        rlp_encode_bytes(&mut out, &data);
        assert_eq!(out[0], 0x80 + 10);
        assert_eq!(&out[1..], &data[..]);
    }

    #[test]
    fn test_token_bucket() {
        let bucket = TokenBucket::new(10);

        // Should be able to acquire up to capacity
        for _ in 0..10 {
            assert!(bucket.try_acquire());
        }

        // Should fail when empty (without refill time)
        assert!(!bucket.try_acquire());
    }

    #[test]
    fn test_wallet_address() {
        let mut rng = StdRng::seed_from_u64(42);
        let wallet = EvmWallet::new_random(&mut rng);
        let addr = wallet.address_hex();
        assert!(addr.starts_with("0x"));
        assert_eq!(addr.len(), 42); // 0x + 40 hex chars
    }

    #[test]
    fn test_metrics() {
        let metrics = Metrics::new();

        metrics.record_sent();
        metrics.record_sent();
        metrics.record_confirmed(100);
        metrics.record_confirmed(200);
        metrics.record_failed();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.txs_sent, 2);
        assert_eq!(snapshot.txs_confirmed, 2);
        assert_eq!(snapshot.txs_failed, 1);
        assert_eq!(snapshot.avg_latency_ms, 150);
        assert_eq!(snapshot.min_latency_ms, 100);
        assert_eq!(snapshot.max_latency_ms, 200);
    }

    #[test]
    fn test_spec_defaults() {
        let yaml = r#"
name: test
"#;
        let spec: LoadTestSpec = serde_yaml::from_str(yaml).unwrap();
        assert_eq!(spec.name, "test");
        assert_eq!(spec.test_type, "c-chain-evm");
        assert_eq!(spec.workers, 10);
        assert_eq!(spec.target_tps, 100);
        assert_eq!(spec.duration_seconds, 60);
    }
}
