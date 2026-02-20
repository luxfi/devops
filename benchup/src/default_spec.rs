//! Generate default blizzard specification

use crate::spec::{BlizzardSpec, TestType};
use anyhow::Result;
use std::path::Path;
use tracing::info;

pub async fn execute(
    output: &str,
    instances: u32,
    regions: &str,
    rpc_endpoints: Option<&str>,
    tps_per_instance: u32,
    duration_seconds: u64,
    test_type: &str,
) -> Result<()> {
    let id = format!("blizzard-{}", &uuid::Uuid::new_v4().to_string()[..8]);
    let region_list: Vec<String> = regions.split(',').map(|s| s.trim().to_string()).collect();

    info!("Generating spec with id: {}", id);
    info!("Regions: {:?}", region_list);
    info!("Instances per region: {}", instances);

    let s3_bucket = format!("{}-bucket", id);

    let mut spec = BlizzardSpec::new(id.clone(), region_list, s3_bucket);

    spec.load_test.instances_per_region = instances;
    spec.load_test.tps_per_instance = tps_per_instance;
    spec.load_test.duration_seconds = duration_seconds;
    spec.load_test.test_type = test_type.parse().unwrap_or(TestType::CChainEvm);

    if let Some(endpoints) = rpc_endpoints {
        spec.load_test.rpc_endpoints = endpoints
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
    }

    let path = Path::new(output);
    spec.save(path)?;

    info!("Spec saved to: {}", output);
    println!("Generated spec file: {}", output);
    println!();
    println!("Configuration:");
    println!("  ID: {}", spec.id);
    println!("  Regions: {:?}", spec.aws.regions);
    println!(
        "  Instances per region: {}",
        spec.load_test.instances_per_region
    );
    println!("  Total instances: {}", spec.total_instances());
    println!("  TPS per instance: {}", spec.load_test.tps_per_instance);
    println!("  Aggregate TPS target: {}", spec.aggregate_tps());
    println!("  Duration: {}s", spec.load_test.duration_seconds);
    println!("  Test type: {:?}", spec.load_test.test_type);
    println!();
    println!("Next steps:");
    println!("  1. Edit {} to configure RPC endpoints", output);
    println!("  2. Run: blizzardup apply --spec-file {}", output);

    Ok(())
}
