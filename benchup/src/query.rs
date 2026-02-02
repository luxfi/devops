//! Query blizzard deployment status and metrics

use crate::spec::BlizzardSpec;
use anyhow::Result;
use aws_sdk_cloudformation::types::StackStatus;
use aws_sdk_cloudwatch::types::{Dimension, Metric, MetricStat, MetricDataQuery, Statistic};
use aws_sdk_ec2::types::Filter;
use chrono::{DateTime, Duration, Utc};
use std::collections::BTreeMap;
use std::path::Path;
use tracing::info;

/// Aggregated metrics from CloudWatch
#[derive(Debug, Default)]
pub struct AggregatedMetrics {
    pub total_transactions: u64,
    pub successful_transactions: u64,
    pub failed_transactions: u64,
    pub avg_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub avg_tps: f64,
    pub max_tps: f64,
}

/// Instance status
#[derive(Debug)]
pub struct InstanceStatus {
    pub instance_id: String,
    pub state: String,
    pub public_ip: Option<String>,
    pub private_ip: Option<String>,
    pub launch_time: Option<String>,
}

pub async fn execute(spec_file: &str, include_metrics: bool, metrics_minutes: i64) -> Result<()> {
    let spec = BlizzardSpec::load(Path::new(spec_file))?;

    info!("Querying blizzard deployment: {}", spec.id);

    let state = match &spec.state {
        Some(s) => s,
        None => {
            println!("No deployment state found. Run 'apply' first.");
            return Ok(());
        }
    };

    println!("Blizzard Deployment Status");
    println!("==========================");
    println!("ID: {}", spec.id);
    println!("Deployed at: {}", state.deployed_at.as_deref().unwrap_or("unknown"));
    println!();

    // Query each region
    for region in &spec.aws.regions {
        println!("Region: {}", region);
        println!("--------");

        // Query CloudFormation stack status
        query_stack_status(&spec, region, state).await?;

        // Query instance status
        let instances = query_instances(&spec, region).await?;
        print_instance_status(&instances);

        // Query CloudWatch metrics if requested
        if include_metrics {
            let metrics = query_metrics(&spec, region, metrics_minutes).await?;
            print_metrics(&metrics);
        }

        println!();
    }

    // Summary
    println!("Summary");
    println!("-------");
    println!("Total instances configured: {}", spec.total_instances());
    println!("Target aggregate TPS: {}", spec.aggregate_tps());
    println!("Test duration: {}s", spec.load_test.duration_seconds);
    println!("RPC endpoints: {:?}", spec.load_test.rpc_endpoints);

    Ok(())
}

async fn query_stack_status(
    spec: &BlizzardSpec,
    region: &str,
    state: &crate::spec::DeploymentState,
) -> Result<()> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_cloudformation::config::Region::new(region.to_string()))
        .load()
        .await;

    let client = aws_sdk_cloudformation::Client::new(&config);

    if let Some(stacks) = state.cloudformation_stacks.get(region) {
        println!("CloudFormation Stacks:");

        for (name, stack_name) in [
            ("VPC", &stacks.vpc_stack),
            ("IAM", &stacks.iam_stack),
            ("ASG", &stacks.asg_stack),
        ] {
            if let Some(stack) = stack_name {
                let status = get_stack_status(&client, stack).await;
                println!("  {}: {} ({})", name, stack, status);
            }
        }
    } else {
        println!("No stacks found for region");
    }

    let _ = spec;
    Ok(())
}

async fn get_stack_status(client: &aws_sdk_cloudformation::Client, name: &str) -> String {
    match client.describe_stacks().stack_name(name).send().await {
        Ok(resp) => {
            if let Some(stack) = resp.stacks().first() {
                match stack.stack_status() {
                    Some(StackStatus::CreateComplete) => "CREATE_COMPLETE".to_string(),
                    Some(StackStatus::CreateInProgress) => "CREATE_IN_PROGRESS".to_string(),
                    Some(StackStatus::DeleteComplete) => "DELETE_COMPLETE".to_string(),
                    Some(StackStatus::DeleteInProgress) => "DELETE_IN_PROGRESS".to_string(),
                    Some(s) => format!("{:?}", s),
                    None => "UNKNOWN".to_string(),
                }
            } else {
                "NOT_FOUND".to_string()
            }
        }
        Err(_) => "NOT_FOUND".to_string(),
    }
}

async fn query_instances(spec: &BlizzardSpec, region: &str) -> Result<Vec<InstanceStatus>> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_ec2::config::Region::new(region.to_string()))
        .load()
        .await;

    let client = aws_sdk_ec2::Client::new(&config);

    let filter = Filter::builder()
        .name("tag:ID")
        .values(&spec.id)
        .build();

    let resp = client
        .describe_instances()
        .filters(filter)
        .send()
        .await?;

    let mut instances = Vec::new();

    for reservation in resp.reservations() {
        for instance in reservation.instances() {
            let state = instance
                .state()
                .and_then(|s| s.name())
                .map(|n| n.as_str().to_string())
                .unwrap_or_else(|| "unknown".to_string());

            let launch_time = instance
                .launch_time()
                .map(|t| t.to_string());

            instances.push(InstanceStatus {
                instance_id: instance.instance_id().unwrap_or("unknown").to_string(),
                state,
                public_ip: instance.public_ip_address().map(|s| s.to_string()),
                private_ip: instance.private_ip_address().map(|s| s.to_string()),
                launch_time,
            });
        }
    }

    Ok(instances)
}

fn print_instance_status(instances: &[InstanceStatus]) {
    println!("Instances: {}", instances.len());
    for inst in instances {
        println!(
            "  {} - {} (public: {}, private: {})",
            inst.instance_id,
            inst.state,
            inst.public_ip.as_deref().unwrap_or("none"),
            inst.private_ip.as_deref().unwrap_or("none")
        );
    }
}

async fn query_metrics(
    spec: &BlizzardSpec,
    region: &str,
    minutes: i64,
) -> Result<AggregatedMetrics> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_cloudwatch::config::Region::new(region.to_string()))
        .load()
        .await;

    let client = aws_sdk_cloudwatch::Client::new(&config);

    let end_time: DateTime<Utc> = Utc::now();
    let start_time = end_time - Duration::minutes(minutes);

    let namespace = format!("Blizzard/{}", spec.id);

    // Define metrics to query
    let metric_queries = vec![
        create_metric_query("m1", &namespace, "TransactionsTotal", Statistic::Sum),
        create_metric_query("m2", &namespace, "TransactionsSuccess", Statistic::Sum),
        create_metric_query("m3", &namespace, "TransactionsFailed", Statistic::Sum),
        create_metric_query("m4", &namespace, "LatencyMs", Statistic::Average),
        create_metric_query("m5", &namespace, "TPS", Statistic::Average),
        create_metric_query("m6", &namespace, "TPS", Statistic::Maximum),
    ];

    let resp = client
        .get_metric_data()
        .start_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(
            start_time.timestamp(),
        ))
        .end_time(aws_sdk_cloudwatch::primitives::DateTime::from_secs(
            end_time.timestamp(),
        ))
        .set_metric_data_queries(Some(metric_queries))
        .send()
        .await;

    let mut metrics = AggregatedMetrics::default();

    match resp {
        Ok(data) => {
            for result in data.metric_data_results() {
                let id = result.id().unwrap_or("");
                let values = result.values();

                if values.is_empty() {
                    continue;
                }

                let sum: f64 = values.iter().sum();
                let avg = sum / values.len() as f64;
                let max = values.iter().cloned().fold(f64::MIN, f64::max);

                match id {
                    "m1" => metrics.total_transactions = sum as u64,
                    "m2" => metrics.successful_transactions = sum as u64,
                    "m3" => metrics.failed_transactions = sum as u64,
                    "m4" => metrics.avg_latency_ms = avg,
                    "m5" => metrics.avg_tps = avg,
                    "m6" => metrics.max_tps = max,
                    _ => {}
                }
            }
        }
        Err(e) => {
            info!("Could not fetch CloudWatch metrics: {}", e);
        }
    }

    Ok(metrics)
}

fn create_metric_query(
    id: &str,
    namespace: &str,
    metric_name: &str,
    stat: Statistic,
) -> MetricDataQuery {
    let metric = Metric::builder()
        .namespace(namespace)
        .metric_name(metric_name)
        .build();

    let metric_stat = MetricStat::builder()
        .metric(metric)
        .period(60)
        .stat(stat.as_str())
        .build();

    MetricDataQuery::builder()
        .id(id)
        .metric_stat(metric_stat)
        .build()
}

fn print_metrics(metrics: &AggregatedMetrics) {
    println!("Metrics (from CloudWatch):");
    println!("  Total transactions: {}", metrics.total_transactions);
    println!(
        "  Successful: {} ({:.1}%)",
        metrics.successful_transactions,
        if metrics.total_transactions > 0 {
            (metrics.successful_transactions as f64 / metrics.total_transactions as f64) * 100.0
        } else {
            0.0
        }
    );
    println!("  Failed: {}", metrics.failed_transactions);
    println!("  Avg latency: {:.2}ms", metrics.avg_latency_ms);
    println!("  Avg TPS: {:.2}", metrics.avg_tps);
    println!("  Max TPS: {:.2}", metrics.max_tps);
}
