//! Delete blizzard load testing infrastructure

use crate::spec::BlizzardSpec;
use anyhow::Result;
use aws_sdk_cloudformation::types::StackStatus;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

const STACK_POLL_INTERVAL: Duration = Duration::from_secs(10);
const STACK_TIMEOUT_SECS: u64 = 600; // 10 minutes

pub async fn execute(
    spec_file: &str,
    skip_prompt: bool,
    delete_s3_objects: bool,
    delete_cloudwatch_logs: bool,
) -> Result<()> {
    let mut spec = BlizzardSpec::load(Path::new(spec_file))?;

    info!("Deleting blizzard deployment: {}", spec.id);

    let state = match &spec.state {
        Some(s) => s.clone(),
        None => {
            println!("No deployment state found. Nothing to delete.");
            return Ok(());
        }
    };

    if !skip_prompt {
        println!("About to delete blizzard deployment:");
        println!("  ID: {}", spec.id);
        println!("  Regions: {:?}", spec.aws.regions);
        println!("  Delete S3 objects: {}", delete_s3_objects);
        println!("  Delete CloudWatch logs: {}", delete_cloudwatch_logs);
        println!();
        print!("Are you sure? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Delete resources in each region
    for region in &spec.aws.regions.clone() {
        info!("Deleting resources in region: {}", region);
        delete_region(&spec, region, &state, delete_s3_objects, delete_cloudwatch_logs).await?;
    }

    // Clear deployment state
    spec.state = None;
    spec.save(Path::new(spec_file))?;

    println!();
    println!("Deletion complete!");

    Ok(())
}

async fn delete_region(
    spec: &BlizzardSpec,
    region: &str,
    state: &crate::spec::DeploymentState,
    delete_s3: bool,
    delete_logs: bool,
) -> Result<()> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_cloudformation::config::Region::new(region.to_string()))
        .load()
        .await;

    let cfn_client = aws_sdk_cloudformation::Client::new(&config);

    // Delete stacks in reverse order (ASG -> IAM -> VPC)
    if let Some(stacks) = state.cloudformation_stacks.get(region) {
        // Delete ASG stack first
        if let Some(asg_stack) = &stacks.asg_stack {
            delete_stack(&cfn_client, asg_stack).await?;
        }

        // Delete IAM stack
        if let Some(iam_stack) = &stacks.iam_stack {
            delete_stack(&cfn_client, iam_stack).await?;
        }

        // Delete VPC stack
        if let Some(vpc_stack) = &stacks.vpc_stack {
            delete_stack(&cfn_client, vpc_stack).await?;
        }
    }

    // Delete EC2 key pair
    if let Some(key_name) = spec.aws.ec2_key_names.get(region) {
        let ec2_client = aws_sdk_ec2::Client::new(&config);
        info!("Deleting key pair: {}", key_name);
        match ec2_client.delete_key_pair().key_name(key_name).send().await {
            Ok(_) => info!("Key pair deleted: {}", key_name),
            Err(e) => warn!("Failed to delete key pair: {}", e),
        }

        // Remove local key file
        let key_path = format!("{}.pem", key_name);
        if std::path::Path::new(&key_path).exists() {
            std::fs::remove_file(&key_path)?;
            info!("Local key file removed: {}", key_path);
        }
    }

    // Delete S3 objects if requested
    if delete_s3 && !spec.aws.keep_resources {
        delete_s3_objects(&config, &spec.aws.s3_bucket, &spec.id).await?;
    }

    // Delete CloudWatch logs if requested
    if delete_logs && !spec.aws.keep_resources {
        delete_cloudwatch_log_group(&config, &spec.id).await?;
    }

    Ok(())
}

async fn delete_stack(client: &aws_sdk_cloudformation::Client, name: &str) -> Result<()> {
    info!("Deleting stack: {}", name);

    // Check if stack exists
    match client.describe_stacks().stack_name(name).send().await {
        Ok(resp) => {
            if resp.stacks().is_empty() {
                info!("Stack does not exist: {}", name);
                return Ok(());
            }
        }
        Err(_) => {
            info!("Stack does not exist: {}", name);
            return Ok(());
        }
    }

    client.delete_stack().stack_name(name).send().await?;

    wait_for_stack_deletion(client, name).await?;

    info!("Stack deleted: {}", name);
    Ok(())
}

async fn wait_for_stack_deletion(
    client: &aws_sdk_cloudformation::Client,
    name: &str,
) -> Result<()> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > STACK_TIMEOUT_SECS {
            anyhow::bail!("Stack deletion timeout: {}", name);
        }

        match client.describe_stacks().stack_name(name).send().await {
            Ok(resp) => {
                if resp.stacks().is_empty() {
                    return Ok(());
                }

                let stack = &resp.stacks()[0];
                let status = stack.stack_status();

                match status {
                    Some(StackStatus::DeleteComplete) => return Ok(()),
                    Some(StackStatus::DeleteInProgress) => {
                        info!("Stack deleting... {}", name);
                    }
                    Some(StackStatus::DeleteFailed) => {
                        let reason = stack.stack_status_reason().unwrap_or("unknown");
                        anyhow::bail!("Stack deletion failed: {} - {}", name, reason);
                    }
                    _ => {
                        warn!("Unexpected status while deleting: {:?}", status);
                    }
                }
            }
            Err(e) => {
                // Stack might not exist (deleted)
                let err_str = e.to_string();
                if err_str.contains("does not exist") {
                    return Ok(());
                }
                return Err(e.into());
            }
        }

        tokio::time::sleep(STACK_POLL_INTERVAL).await;
    }
}

async fn delete_s3_objects(config: &aws_config::SdkConfig, bucket: &str, prefix: &str) -> Result<()> {
    let client = aws_sdk_s3::Client::new(config);

    info!("Deleting S3 objects with prefix: {}/{}", bucket, prefix);

    let mut continuation_token: Option<String> = None;

    loop {
        let mut req = client
            .list_objects_v2()
            .bucket(bucket)
            .prefix(format!("{}/", prefix));

        if let Some(token) = continuation_token {
            req = req.continuation_token(token);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                warn!("Failed to list S3 objects: {}", e);
                return Ok(());
            }
        };

        let objects: Vec<_> = resp.contents().iter().collect();

        if objects.is_empty() {
            break;
        }

        for obj in objects {
            if let Some(key) = obj.key() {
                match client.delete_object().bucket(bucket).key(key).send().await {
                    Ok(_) => info!("Deleted: s3://{}/{}", bucket, key),
                    Err(e) => warn!("Failed to delete {}: {}", key, e),
                }
            }
        }

        if resp.is_truncated() == Some(true) {
            continuation_token = resp.next_continuation_token().map(|s| s.to_string());
        } else {
            break;
        }
    }

    // Try to delete the bucket if empty
    match client.delete_bucket().bucket(bucket).send().await {
        Ok(_) => info!("S3 bucket deleted: {}", bucket),
        Err(e) => warn!("Could not delete bucket (may not be empty): {}", e),
    }

    Ok(())
}

async fn delete_cloudwatch_log_group(config: &aws_config::SdkConfig, log_group: &str) -> Result<()> {
    let client = aws_sdk_cloudwatch::Client::new(config);
    let _ = client; // CloudWatch Logs requires a separate client

    // Use CloudWatch Logs client
    info!("CloudWatch log group deletion requires aws-sdk-cloudwatchlogs");
    info!("Log group to delete: {}", log_group);

    // CloudWatch Logs is a separate service - would need aws-sdk-cloudwatchlogs
    // For now, just log the instruction
    println!(
        "To delete CloudWatch logs manually:\n  aws logs delete-log-group --log-group-name {}",
        log_group
    );

    Ok(())
}
