//! Lux Faucet - Devnet Token Distribution Service
//!
//! HTTP server that distributes test LUX tokens on devnets.

use alloy_consensus::TxLegacy;
use alloy_network::TxSignerSync;
use alloy_primitives::{Address, Bytes, TxKind, U256};
use alloy_signer_local::PrivateKeySigner;
use axum::{
    extract::{ConnectInfo, State},
    http::{HeaderMap, StatusCode},
    response::Json,
    routing::{get, post},
    Router,
};
use clap::Parser;
use governor::{
    clock::DefaultClock,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    num::NonZeroU32,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "lux-faucet";

/// LUX uses 18 decimals (same as ETH).
const LUX_DECIMALS: u32 = 18;

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Lux Network devnet faucet")]
#[command(version)]
struct Cli {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// HTTP host:port
    #[arg(long, default_value = "0.0.0.0:3000")]
    http_host: String,

    /// C-Chain RPC endpoint
    #[arg(long)]
    rpc_endpoint: String,

    /// Faucet private key (hex, for testing only)
    #[arg(long, env = "FAUCET_PRIVATE_KEY")]
    private_key: String,

    /// Amount to drip per request (in LUX)
    #[arg(long, default_value = "1")]
    drip_amount: u64,

    /// Rate limit requests per minute per IP
    #[arg(long, default_value = "5")]
    rate_limit: u32,

    /// C-Chain chain ID
    #[arg(long, default_value = "96369")]
    chain_id: u64,
}

#[derive(Clone)]
struct AppState {
    rpc_endpoint: String,
    signer: PrivateKeySigner,
    drip_amount_wei: U256,
    drip_count: Arc<RwLock<u64>>,
    chain_id: u64,
    rate_limiters: Arc<RwLock<HashMap<String, Arc<RateLimiter<NotKeyed, InMemoryState, DefaultClock>>>>>,
    requests_per_minute: u32,
    http_client: reqwest::Client,
}

#[derive(Deserialize)]
struct DripRequest {
    address: String,
}

#[derive(Serialize)]
struct DripResponse {
    success: bool,
    tx_hash: Option<String>,
    message: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: String,
    drip_count: u64,
    faucet_address: String,
}

/// JSON-RPC request structure.
#[derive(Serialize)]
struct JsonRpcRequest<T: Serialize> {
    jsonrpc: &'static str,
    method: &'static str,
    params: T,
    id: u64,
}

/// JSON-RPC response structure.
#[derive(Deserialize)]
struct JsonRpcResponse<T> {
    result: Option<T>,
    error: Option<JsonRpcError>,
}

#[derive(Deserialize)]
struct JsonRpcError {
    message: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
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

    info!("Starting {} on {}", APP_NAME, cli.http_host);
    info!("RPC endpoint: {}", cli.rpc_endpoint);
    info!("Drip amount: {} LUX", cli.drip_amount);
    info!("Chain ID: {}", cli.chain_id);
    info!("Rate limit: {} requests/minute per IP", cli.rate_limit);

    let private_key_bytes = parse_private_key(&cli.private_key)?;
    let signer = PrivateKeySigner::from_slice(&private_key_bytes)
        .map_err(|e| anyhow::anyhow!("Invalid private key: {}", e))?;

    info!("Faucet address: {}", signer.address());

    let drip_amount_wei = U256::from(cli.drip_amount) * U256::from(10).pow(U256::from(LUX_DECIMALS));

    let state = AppState {
        rpc_endpoint: cli.rpc_endpoint,
        signer,
        drip_amount_wei,
        drip_count: Arc::new(RwLock::new(0)),
        chain_id: cli.chain_id,
        rate_limiters: Arc::new(RwLock::new(HashMap::new())),
        requests_per_minute: cli.rate_limit,
        http_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?,
    };

    let app = Router::new()
        .route("/health", get(health))
        .route("/drip", post(drip))
        .with_state(state);

    let addr: SocketAddr = cli.http_host.parse()?;
    let listener = tokio::net::TcpListener::bind(addr).await?;

    info!("Faucet listening on {}", addr);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

/// Parse hex private key (with or without 0x prefix).
fn parse_private_key(s: &str) -> anyhow::Result<[u8; 32]> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(s)?;
    if bytes.len() != 32 {
        anyhow::bail!("Private key must be 32 bytes, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(arr)
}

/// Validate Ethereum address format.
fn validate_address(addr: &str) -> Result<Address, &'static str> {
    let addr = addr.trim();
    if !addr.starts_with("0x") && !addr.starts_with("0X") {
        return Err("Address must start with 0x");
    }
    if addr.len() != 42 {
        return Err("Address must be 42 characters (0x + 40 hex chars)");
    }
    let hex_part = &addr[2..];
    if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("Address must contain only hexadecimal characters");
    }
    addr.parse::<Address>()
        .map_err(|_| "Invalid address format")
}

/// Extract client IP from request headers or connection info.
fn extract_client_ip(headers: &HeaderMap, connect_info: &ConnectInfo<SocketAddr>) -> String {
    // Check X-Forwarded-For header first (for reverse proxies).
    if let Some(xff) = headers.get("x-forwarded-for") {
        if let Ok(xff_str) = xff.to_str() {
            // X-Forwarded-For can contain multiple IPs; take the first one.
            if let Some(first_ip) = xff_str.split(',').next() {
                let ip = first_ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }
    // Check X-Real-IP header.
    if let Some(xri) = headers.get("x-real-ip") {
        if let Ok(ip) = xri.to_str() {
            let ip = ip.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }
    // Fall back to direct connection IP.
    connect_info.0.ip().to_string()
}

/// Check rate limit for the given IP.
async fn check_rate_limit(state: &AppState, ip: &str) -> bool {
    let limiter = {
        let limiters = state.rate_limiters.read().await;
        limiters.get(ip).cloned()
    };

    let limiter = match limiter {
        Some(l) => l,
        None => {
            let quota = Quota::per_minute(
                NonZeroU32::new(state.requests_per_minute).unwrap_or(NonZeroU32::MIN),
            );
            let new_limiter = Arc::new(RateLimiter::direct(quota));
            let mut limiters = state.rate_limiters.write().await;
            limiters.insert(ip.to_string(), new_limiter.clone());
            new_limiter
        }
    };

    limiter.check().is_ok()
}

/// Get the current nonce for an address.
async fn get_nonce(state: &AppState, address: Address) -> anyhow::Result<u64> {
    let request = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_getTransactionCount",
        params: (format!("{:?}", address), "pending"),
        id: 1,
    };

    let response = state
        .http_client
        .post(&state.rpc_endpoint)
        .json(&request)
        .send()
        .await?
        .json::<JsonRpcResponse<String>>()
        .await?;

    if let Some(err) = response.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    let nonce_hex = response.result.ok_or_else(|| anyhow::anyhow!("No result"))?;
    let nonce = u64::from_str_radix(nonce_hex.trim_start_matches("0x"), 16)?;
    Ok(nonce)
}

/// Get the current gas price.
async fn get_gas_price(state: &AppState) -> anyhow::Result<u128> {
    let request = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_gasPrice",
        params: (),
        id: 1,
    };

    let response = state
        .http_client
        .post(&state.rpc_endpoint)
        .json(&request)
        .send()
        .await?
        .json::<JsonRpcResponse<String>>()
        .await?;

    if let Some(err) = response.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    let gas_hex = response.result.ok_or_else(|| anyhow::anyhow!("No result"))?;
    let gas_price = u128::from_str_radix(gas_hex.trim_start_matches("0x"), 16)?;
    Ok(gas_price)
}

/// Send a raw signed transaction.
async fn send_raw_transaction(state: &AppState, raw_tx: &[u8]) -> anyhow::Result<String> {
    let raw_tx_hex = format!("0x{}", hex::encode(raw_tx));

    let request = JsonRpcRequest {
        jsonrpc: "2.0",
        method: "eth_sendRawTransaction",
        params: (raw_tx_hex,),
        id: 1,
    };

    let response = state
        .http_client
        .post(&state.rpc_endpoint)
        .json(&request)
        .send()
        .await?
        .json::<JsonRpcResponse<String>>()
        .await?;

    if let Some(err) = response.error {
        anyhow::bail!("RPC error: {}", err.message);
    }

    response
        .result
        .ok_or_else(|| anyhow::anyhow!("No transaction hash returned"))
}

/// Wait for transaction confirmation.
async fn wait_for_confirmation(
    state: &AppState,
    tx_hash: &str,
    timeout_secs: u64,
) -> anyhow::Result<bool> {
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);

    loop {
        if start.elapsed() > timeout {
            return Ok(false);
        }

        let request = JsonRpcRequest {
            jsonrpc: "2.0",
            method: "eth_getTransactionReceipt",
            params: (tx_hash,),
            id: 1,
        };

        let response = state
            .http_client
            .post(&state.rpc_endpoint)
            .json(&request)
            .send()
            .await?
            .json::<JsonRpcResponse<serde_json::Value>>()
            .await?;

        if let Some(receipt) = response.result {
            if !receipt.is_null() {
                if let Some(status) = receipt.get("status") {
                    let status_str = status.as_str().unwrap_or("0x0");
                    return Ok(status_str == "0x1");
                }
            }
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    let count = *state.drip_count.read().await;
    Json(HealthResponse {
        status: "ok".to_string(),
        drip_count: count,
        faucet_address: format!("{:?}", state.signer.address()),
    })
}

async fn drip(
    State(state): State<AppState>,
    headers: HeaderMap,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<DripRequest>,
) -> Result<Json<DripResponse>, StatusCode> {
    let client_ip = extract_client_ip(&headers, &ConnectInfo(addr));
    info!("Drip request from {} for address: {}", client_ip, request.address);

    // Validate address format.
    let to_address = match validate_address(&request.address) {
        Ok(addr) => addr,
        Err(msg) => {
            warn!("Invalid address from {}: {}", client_ip, msg);
            return Ok(Json(DripResponse {
                success: false,
                tx_hash: None,
                message: msg.to_string(),
            }));
        }
    };

    // Check rate limit.
    if !check_rate_limit(&state, &client_ip).await {
        warn!("Rate limit exceeded for {}", client_ip);
        return Ok(Json(DripResponse {
            success: false,
            tx_hash: None,
            message: "Rate limit exceeded. Please wait before requesting again.".to_string(),
        }));
    }

    // Get nonce and gas price.
    let nonce = match get_nonce(&state, state.signer.address()).await {
        Ok(n) => n,
        Err(e) => {
            error!("Failed to get nonce: {}", e);
            return Ok(Json(DripResponse {
                success: false,
                tx_hash: None,
                message: "Failed to get nonce from network".to_string(),
            }));
        }
    };

    let gas_price = match get_gas_price(&state).await {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to get gas price: {}", e);
            return Ok(Json(DripResponse {
                success: false,
                tx_hash: None,
                message: "Failed to get gas price from network".to_string(),
            }));
        }
    };

    // Build legacy transaction (simple transfer).
    let tx = TxLegacy {
        chain_id: Some(state.chain_id),
        nonce,
        gas_price,
        gas_limit: 21000, // Standard transfer gas.
        to: TxKind::Call(to_address),
        value: state.drip_amount_wei,
        input: Bytes::new(),
    };

    // Sign the transaction.
    let signature = match state.signer.sign_transaction_sync(&tx) {
        Ok(sig) => sig,
        Err(e) => {
            error!("Failed to sign transaction: {}", e);
            return Ok(Json(DripResponse {
                success: false,
                tx_hash: None,
                message: "Failed to sign transaction".to_string(),
            }));
        }
    };

    // Encode the signed transaction (RLP encoding with signature).
    let signed_tx = encode_signed_legacy_tx(&tx, &signature);

    // Send the transaction.
    let tx_hash = match send_raw_transaction(&state, &signed_tx).await {
        Ok(hash) => hash,
        Err(e) => {
            error!("Failed to send transaction: {}", e);
            return Ok(Json(DripResponse {
                success: false,
                tx_hash: None,
                message: format!("Failed to send transaction: {}", e),
            }));
        }
    };

    info!("Transaction sent: {} for {}", tx_hash, request.address);

    // Wait for confirmation (max 30 seconds).
    match wait_for_confirmation(&state, &tx_hash, 30).await {
        Ok(true) => {
            info!("Transaction confirmed: {}", tx_hash);
            let mut count = state.drip_count.write().await;
            *count += 1;
            Ok(Json(DripResponse {
                success: true,
                tx_hash: Some(tx_hash),
                message: format!("Sent {} LUX", state.drip_amount_wei / U256::from(10).pow(U256::from(LUX_DECIMALS))),
            }))
        }
        Ok(false) => {
            warn!("Transaction not confirmed within timeout: {}", tx_hash);
            Ok(Json(DripResponse {
                success: true,
                tx_hash: Some(tx_hash),
                message: "Transaction sent but confirmation timed out. Check explorer.".to_string(),
            }))
        }
        Err(e) => {
            error!("Error waiting for confirmation: {}", e);
            Ok(Json(DripResponse {
                success: true,
                tx_hash: Some(tx_hash),
                message: "Transaction sent but confirmation check failed.".to_string(),
            }))
        }
    }
}

/// RLP-encode a signed legacy transaction.
fn encode_signed_legacy_tx(tx: &TxLegacy, sig: &alloy_primitives::Signature) -> Vec<u8> {
    use alloy_consensus::SignableTransaction;

    // For legacy transactions, we need to RLP encode:
    // [nonce, gasPrice, gasLimit, to, value, data, v, r, s]
    let mut buf = Vec::new();

    // Calculate v value for legacy transaction.
    // v = chain_id * 2 + 35 + recovery_id
    let v = if let Some(chain_id) = tx.chain_id {
        chain_id * 2 + 35 + sig.v().to_u64()
    } else {
        27 + sig.v().to_u64()
    };

    // Get r and s as bytes.
    let r = sig.r();
    let s = sig.s();

    // RLP encode the transaction.
    // First, calculate the total length.
    let nonce_rlp = rlp_encode_u64(tx.nonce);
    let gas_price_rlp = rlp_encode_u128(tx.gas_price);
    let gas_limit_rlp = rlp_encode_u64(tx.gas_limit);
    let to_rlp = match tx.to {
        TxKind::Call(addr) => rlp_encode_bytes(addr.as_slice()),
        TxKind::Create => rlp_encode_bytes(&[]),
    };
    let value_rlp = rlp_encode_u256(tx.value);
    let data_rlp = rlp_encode_bytes(&tx.input);
    let v_rlp = rlp_encode_u64(v);
    let r_rlp = rlp_encode_u256(r);
    let s_rlp = rlp_encode_u256(s);

    let total_len = nonce_rlp.len()
        + gas_price_rlp.len()
        + gas_limit_rlp.len()
        + to_rlp.len()
        + value_rlp.len()
        + data_rlp.len()
        + v_rlp.len()
        + r_rlp.len()
        + s_rlp.len();

    // Encode list header.
    if total_len < 56 {
        buf.push(0xc0 + total_len as u8);
    } else {
        let len_bytes = encode_length_bytes(total_len);
        buf.push(0xf7 + len_bytes.len() as u8);
        buf.extend_from_slice(&len_bytes);
    }

    buf.extend_from_slice(&nonce_rlp);
    buf.extend_from_slice(&gas_price_rlp);
    buf.extend_from_slice(&gas_limit_rlp);
    buf.extend_from_slice(&to_rlp);
    buf.extend_from_slice(&value_rlp);
    buf.extend_from_slice(&data_rlp);
    buf.extend_from_slice(&v_rlp);
    buf.extend_from_slice(&r_rlp);
    buf.extend_from_slice(&s_rlp);

    buf
}

fn encode_length_bytes(len: usize) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut n = len;
    while n > 0 {
        bytes.push((n & 0xff) as u8);
        n >>= 8;
    }
    bytes.reverse();
    bytes
}

fn rlp_encode_u64(n: u64) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(8);
    let significant = &bytes[first_nonzero..];
    if significant.len() == 1 && significant[0] < 0x80 {
        vec![significant[0]]
    } else {
        let mut result = vec![0x80 + significant.len() as u8];
        result.extend_from_slice(significant);
        result
    }
}

fn rlp_encode_u128(n: u128) -> Vec<u8> {
    if n == 0 {
        return vec![0x80];
    }
    let bytes = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(16);
    let significant = &bytes[first_nonzero..];
    if significant.len() == 1 && significant[0] < 0x80 {
        vec![significant[0]]
    } else {
        let mut result = vec![0x80 + significant.len() as u8];
        result.extend_from_slice(significant);
        result
    }
}

fn rlp_encode_u256(n: U256) -> Vec<u8> {
    if n.is_zero() {
        return vec![0x80];
    }
    let bytes: [u8; 32] = n.to_be_bytes();
    let first_nonzero = bytes.iter().position(|&b| b != 0).unwrap_or(32);
    let significant = &bytes[first_nonzero..];
    if significant.len() == 1 && significant[0] < 0x80 {
        vec![significant[0]]
    } else {
        let mut result = vec![0x80 + significant.len() as u8];
        result.extend_from_slice(significant);
        result
    }
}

fn rlp_encode_bytes(data: &[u8]) -> Vec<u8> {
    if data.is_empty() {
        return vec![0x80];
    }
    if data.len() == 1 && data[0] < 0x80 {
        return vec![data[0]];
    }
    if data.len() < 56 {
        let mut result = vec![0x80 + data.len() as u8];
        result.extend_from_slice(data);
        result
    } else {
        let len_bytes = encode_length_bytes(data.len());
        let mut result = vec![0xb7 + len_bytes.len() as u8];
        result.extend_from_slice(&len_bytes);
        result.extend_from_slice(data);
        result
    }
}
