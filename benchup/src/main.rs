//! Blizzardup - Lux Network Load Testing Control Plane
//!
//! Deploys and manages blizzard load testing infrastructure on AWS.

mod apply;
mod default_spec;
mod delete;
mod query;
mod spec;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "blizzardup";

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Lux Network load testing control plane")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate default specification
    DefaultSpec {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Output file
        #[arg(long, default_value = "blizzard-spec.yaml")]
        output: String,

        /// Number of blizzard instances
        #[arg(long, default_value = "3")]
        instances: u32,

        /// AWS regions (comma-separated)
        #[arg(long, default_value = "us-west-2")]
        regions: String,

        /// Target RPC endpoints (comma-separated)
        #[arg(long)]
        rpc_endpoints: Option<String>,

        /// Transactions per second target per instance
        #[arg(long, default_value = "100")]
        tps_per_instance: u32,

        /// Test duration in seconds
        #[arg(long, default_value = "300")]
        duration_seconds: u64,

        /// Test type (x-chain, c-chain-evm)
        #[arg(long, default_value = "c-chain-evm")]
        test_type: String,
    },

    /// Apply/deploy specification
    Apply {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file
        #[arg(long)]
        spec_file: String,

        /// Skip confirmation
        #[arg(long)]
        skip_prompt: bool,
    },

    /// Delete deployment
    Delete {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file
        #[arg(long)]
        spec_file: String,

        /// Skip confirmation
        #[arg(long)]
        skip_prompt: bool,

        /// Delete S3 objects
        #[arg(long)]
        delete_s3_objects: bool,

        /// Delete CloudWatch logs
        #[arg(long)]
        delete_cloudwatch_logs: bool,
    },

    /// Query deployment status and metrics
    Query {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file
        #[arg(long)]
        spec_file: String,

        /// Include CloudWatch metrics
        #[arg(long)]
        include_metrics: bool,

        /// Metrics time range in minutes
        #[arg(long, default_value = "60")]
        metrics_minutes: i64,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::DefaultSpec {
            log_level,
            output,
            instances,
            regions,
            rpc_endpoints,
            tps_per_instance,
            duration_seconds,
            test_type,
        } => {
            init_logging(&log_level)?;
            info!("Generating default spec: {}", output);
            default_spec::execute(
                &output,
                instances,
                &regions,
                rpc_endpoints.as_deref(),
                tps_per_instance,
                duration_seconds,
                &test_type,
            )
            .await?;
        }

        Commands::Apply {
            log_level,
            spec_file,
            skip_prompt,
        } => {
            init_logging(&log_level)?;
            info!("Applying spec: {}", spec_file);
            apply::execute(&spec_file, skip_prompt).await?;
        }

        Commands::Delete {
            log_level,
            spec_file,
            skip_prompt,
            delete_s3_objects,
            delete_cloudwatch_logs,
        } => {
            init_logging(&log_level)?;
            info!("Deleting deployment: {}", spec_file);
            delete::execute(&spec_file, skip_prompt, delete_s3_objects, delete_cloudwatch_logs)
                .await?;
        }

        Commands::Query {
            log_level,
            spec_file,
            include_metrics,
            metrics_minutes,
        } => {
            init_logging(&log_level)?;
            info!("Querying deployment: {}", spec_file);
            query::execute(&spec_file, include_metrics, metrics_minutes).await?;
        }
    }

    Ok(())
}

fn init_logging(level: &str) -> anyhow::Result<()> {
    let level = match level.to_lowercase().as_str() {
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
    Ok(())
}
