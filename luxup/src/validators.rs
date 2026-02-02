//! Validator management

use anyhow::Result;
use lux_core::spec::Spec;
use std::path::Path;
use tracing::info;

pub async fn add(spec_file: &str, count: u32, stake_amount: u64, stake_days: u64) -> Result<()> {
    let spec = Spec::load(Path::new(spec_file))?;

    info!(
        "Adding {} validators with {} LUX stake for {} days",
        count, stake_amount, stake_days
    );

    // TODO: Implement validator addition
    // 1. Generate or get keys (from Lux MPC if configured)
    // 2. Fund addresses
    // 3. Issue AddValidator transactions
    // 4. Wait for confirmation

    let _ = spec;

    println!("Validator addition not yet implemented");
    Ok(())
}

pub async fn list(spec_file: &str) -> Result<()> {
    let spec = Spec::load(Path::new(spec_file))?;

    info!("Listing validators for: {}", spec.id);

    // TODO: Query P-chain for current validators

    if let Some(nodes) = &spec.created_nodes {
        println!("Known nodes:");
        for node in nodes {
            println!("  {} - {} ({})",
                node.node_id,
                if node.is_anchor { "Anchor" } else { "Non-anchor" },
                node.region
            );
        }
    } else {
        println!("No nodes found");
    }

    Ok(())
}
