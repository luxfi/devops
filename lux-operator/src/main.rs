//! Lux Network Kubernetes Operator
//!
//! This operator manages Lux Network deployments on Kubernetes, including:
//! - LuxNetwork custom resources
//! - LuxSubnet custom resources
//! - Validator node lifecycle
//! - Integration with Lux MPC for key management

mod controller;
mod crd;
mod error;

use clap::Parser;
use kube::Client;
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
    info!("Namespace: {}", if args.namespace.is_empty() { "all" } else { &args.namespace });

    // Initialize Kubernetes client
    let client = Client::try_default().await?;
    info!("Connected to Kubernetes cluster");

    // Start the controller
    controller::run(client, args.namespace, args.mpc_endpoint).await?;

    Ok(())
}
