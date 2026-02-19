//! Lux Network Kubernetes Operator
//!
//! This operator manages Lux Network deployments on Kubernetes, including:
//! - LuxNetwork custom resources
//! - LuxChain custom resources
//! - Validator node lifecycle
//! - Integration with Lux MPC for key management

mod controller;
mod crd;
mod error;

use axum::{routing::get, Router};
use clap::Parser;
use kube::Client;
use std::net::SocketAddr;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Parser, Debug)]
#[command(name = "lux-operator")]
#[command(about = "Kubernetes operator for Lux Network", long_about = None)]
struct Args {
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// Namespace to watch (empty for all namespaces)
    #[arg(long, default_value = "")]
    namespace: String,

    /// Metrics port
    #[arg(long, default_value = "8080")]
    metrics_port: u16,

    /// Health check port
    #[arg(long, default_value = "8081")]
    health_port: u16,

    /// Enable leader election
    #[arg(long, default_value = "true")]
    leader_election: bool,

    /// Lux MPC endpoint (optional)
    #[arg(long)]
    mpc_endpoint: Option<String>,
}

async fn healthz() -> &'static str {
    "ok"
}

async fn readyz() -> &'static str {
    "ok"
}

async fn metrics() -> &'static str {
    // TODO: expose prometheus metrics
    ""
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    // Initialize logging
    let level = match args.log_level.to_lowercase().as_str() {
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

    info!("Starting Lux Network Operator");
    info!("Log level: {}", args.log_level);
    info!(
        "Namespace: {}",
        if args.namespace.is_empty() {
            "all"
        } else {
            &args.namespace
        }
    );

    // Initialize Kubernetes client
    let client = Client::try_default().await?;
    info!("Connected to Kubernetes cluster");

    // Health server
    let health_addr = SocketAddr::from(([0, 0, 0, 0], args.health_port));
    let health_app = Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz));
    info!("Health server listening on {}", health_addr);

    // Metrics server
    let metrics_addr = SocketAddr::from(([0, 0, 0, 0], args.metrics_port));
    let metrics_app = Router::new().route("/metrics", get(metrics));
    info!("Metrics server listening on {}", metrics_addr);

    // Run controllers + servers concurrently
    let network_client = client.clone();
    let chain_client = client.clone();
    let network_ns = args.namespace.clone();
    let chain_ns = args.namespace.clone();
    let mpc_endpoint = args.mpc_endpoint.clone();

    tokio::select! {
        res = controller::run_network_controller(network_client, network_ns, mpc_endpoint) => {
            if let Err(e) = res {
                tracing::error!("Network controller exited with error: {:?}", e);
            }
        }
        res = controller::run_chain_controller(chain_client, chain_ns) => {
            if let Err(e) = res {
                tracing::error!("Chain controller exited with error: {:?}", e);
            }
        }
        res = axum::serve(
            tokio::net::TcpListener::bind(health_addr).await.unwrap(),
            health_app.into_make_service(),
        ) => {
            if let Err(e) = res {
                tracing::error!("Health server exited with error: {:?}", e);
            }
        }
        res = axum::serve(
            tokio::net::TcpListener::bind(metrics_addr).await.unwrap(),
            metrics_app.into_make_service(),
        ) => {
            if let Err(e) = res {
                tracing::error!("Metrics server exited with error: {:?}", e);
            }
        }
    }

    Ok(())
}
