//! Lux Network Daemon
//!
//! Agent that runs on cloud instances to manage Lux node lifecycle

mod agent;
mod install;

use clap::{Parser, Subcommand};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

pub const APP_NAME: &str = "luxd-daemon";

#[derive(Parser)]
#[command(name = APP_NAME)]
#[command(about = "Lux Network daemon agent for cloud deployments")]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the agent daemon
    Agent {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// Use default config
        #[arg(long)]
        use_default_config: bool,

        /// Publish periodic node info
        #[arg(long)]
        publish_periodic_node_info: bool,
    },

    /// Install artifacts (luxd binary, plugins)
    Install {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// S3 region
        #[arg(long)]
        s3_region: String,

        /// S3 bucket
        #[arg(long)]
        s3_bucket: String,

        /// Luxd S3 key
        #[arg(long)]
        luxd_s3_key: Option<String>,

        /// Luxd local path
        #[arg(long)]
        luxd_local_path: Option<String>,

        /// Luxd release tag
        #[arg(long)]
        luxd_release_tag: Option<String>,

        /// OS type
        #[arg(long, default_value = "ubuntu22.04")]
        os_type: String,
    },

    /// Install subnet VM
    InstallSubnet {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// S3 region
        #[arg(long)]
        s3_region: String,

        /// S3 bucket
        #[arg(long)]
        s3_bucket: String,

        /// Subnet config S3 key
        #[arg(long)]
        subnet_config_s3_key: Option<String>,

        /// Subnet config local path
        #[arg(long)]
        subnet_config_local_path: Option<String>,

        /// VM binary S3 key
        #[arg(long)]
        vm_binary_s3_key: String,

        /// VM binary local path
        #[arg(long)]
        vm_binary_local_path: String,

        /// Subnet ID to track
        #[arg(long)]
        subnet_id: String,

        /// Luxd config path
        #[arg(long)]
        luxd_config_path: String,
    },

    /// Install chain config
    InstallChain {
        /// Log level
        #[arg(long, default_value = "info")]
        log_level: String,

        /// S3 region
        #[arg(long)]
        s3_region: String,

        /// S3 bucket
        #[arg(long)]
        s3_bucket: String,

        /// Chain config S3 key
        #[arg(long)]
        chain_config_s3_key: String,

        /// Chain config local path
        #[arg(long)]
        chain_config_local_path: String,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Agent {
            log_level,
            use_default_config,
            publish_periodic_node_info,
        } => {
            init_logging(&log_level)?;
            info!("Starting {} agent", APP_NAME);
            agent::run(use_default_config, publish_periodic_node_info).await?;
        }

        Commands::Install {
            log_level,
            s3_region,
            s3_bucket,
            luxd_s3_key,
            luxd_local_path,
            luxd_release_tag,
            os_type,
        } => {
            init_logging(&log_level)?;
            info!("Installing artifacts");
            install::install_artifacts(
                &s3_region,
                &s3_bucket,
                luxd_s3_key.as_deref(),
                luxd_local_path.as_deref(),
                luxd_release_tag.as_deref(),
                &os_type,
            )
            .await?;
        }

        Commands::InstallSubnet {
            log_level,
            s3_region,
            s3_bucket,
            subnet_config_s3_key,
            subnet_config_local_path,
            vm_binary_s3_key,
            vm_binary_local_path,
            subnet_id,
            luxd_config_path,
        } => {
            init_logging(&log_level)?;
            info!("Installing subnet");
            install::install_subnet(
                &s3_region,
                &s3_bucket,
                subnet_config_s3_key.as_deref(),
                subnet_config_local_path.as_deref(),
                &vm_binary_s3_key,
                &vm_binary_local_path,
                &subnet_id,
                &luxd_config_path,
            )
            .await?;
        }

        Commands::InstallChain {
            log_level,
            s3_region,
            s3_bucket,
            chain_config_s3_key,
            chain_config_local_path,
        } => {
            init_logging(&log_level)?;
            info!("Installing chain config");
            install::install_chain(
                &s3_region,
                &s3_bucket,
                &chain_config_s3_key,
                &chain_config_local_path,
            )
            .await?;
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
