//! Luxup - Lux Network Deployment Control Plane
//!
//! Command-line tool for deploying and managing Lux networks on AWS or Kubernetes.

mod apply;
mod default_spec;
mod delete;
mod endpoints;
mod validators;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "luxup";

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Lux Network deployment control plane")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate default specification file
    DefaultSpec {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Output file path
        #[arg(long, default_value = "spec.yaml")]
        output: String,

        /// Deployment target (aws or k8s)
        #[arg(long, default_value = "k8s")]
        target: String,

        /// Network name
        #[arg(long)]
        network_name: Option<String>,

        /// Number of anchor nodes
        #[arg(long, default_value = "1")]
        anchor_nodes: u32,

        /// Number of non-anchor nodes
        #[arg(long, default_value = "2")]
        non_anchor_nodes: u32,

        /// AWS regions (comma-separated)
        #[arg(long, default_value = "us-west-2")]
        regions: String,
    },

    /// Apply/deploy a specification
    Apply {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file path
        #[arg(long)]
        spec_file: String,

        /// Skip confirmation
        #[arg(long)]
        skip_prompt: bool,
    },

    /// Delete a deployment
    Delete {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file path
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

    /// Show endpoints for a deployment
    Endpoints {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file path
        #[arg(long)]
        spec_file: String,
    },

    /// Manage validators
    Validators {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Spec file path
        #[arg(long)]
        spec_file: String,

        #[command(subcommand)]
        action: ValidatorAction,
    },
}

#[derive(Subcommand)]
enum ValidatorAction {
    /// Add validators to the primary network
    Add {
        /// Number of validators to add
        #[arg(long)]
        count: u32,

        /// Staking amount in LUX
        #[arg(long, default_value = "2000")]
        stake_amount: u64,

        /// Staking duration in days
        #[arg(long, default_value = "365")]
        stake_days: u64,
    },

    /// List current validators
    List,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::DefaultSpec {
            log_level,
            output,
            target,
            network_name,
            anchor_nodes,
            non_anchor_nodes,
            regions,
        } => {
            init_logging(&log_level)?;
            info!("Generating default spec");
            default_spec::execute(
                &output,
                &target,
                network_name.as_deref(),
                anchor_nodes,
                non_anchor_nodes,
                &regions,
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
            delete::execute(
                &spec_file,
                skip_prompt,
                delete_s3_objects,
                delete_cloudwatch_logs,
            )
            .await?;
        }

        Commands::Endpoints {
            log_level,
            spec_file,
        } => {
            init_logging(&log_level)?;
            endpoints::execute(&spec_file).await?;
        }

        Commands::Validators {
            log_level,
            spec_file,
            action,
        } => {
            init_logging(&log_level)?;
            match action {
                ValidatorAction::Add {
                    count,
                    stake_amount,
                    stake_days,
                } => {
                    validators::add(&spec_file, count, stake_amount, stake_days).await?;
                }
                ValidatorAction::List => {
                    validators::list(&spec_file).await?;
                }
            }
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
