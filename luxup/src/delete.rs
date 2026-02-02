//! Delete a deployment and clean up resources

use anyhow::{Context, Result};
use aws_sdk_cloudformation::types::StackStatus;
use lux_core::spec::{AwsConfig, DeploymentTarget, K8sConfig, Spec};
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

const STACK_POLL_INTERVAL: Duration = Duration::from_secs(10);

/// Execute the delete command
pub async fn execute(
    spec_file: &str,
    skip_prompt: bool,
    delete_s3_objects: bool,
    delete_cloudwatch_logs: bool,
) -> Result<()> {
    let spec = Spec::load(Path::new(spec_file)).context("Failed to load spec file")?;

    info!(id = %spec.id, "Preparing to delete deployment");

    if !skip_prompt {
        println!("About to delete deployment:");
        println!("  ID: {}", spec.id);
        println!("  Delete S3 objects: {}", delete_s3_objects);
        println!("  Delete CloudWatch logs: {}", delete_cloudwatch_logs);
        println!();

        match &spec.target {
            DeploymentTarget::Aws(aws) => {
                println!("  Target: AWS");
                println!("  Regions: {}", aws.regions.join(", "));
                println!("  S3 bucket: {}", aws.s3_bucket);
                if let Some(kms) = &aws.kms_key {
                    println!("  KMS key: {}", kms.id);
                }
            }
            DeploymentTarget::Kubernetes(k8s) => {
                println!("  Target: Kubernetes");
                println!("  Namespace: {}", k8s.namespace);
            }
        }
        println!();

        print!("This action is IRREVERSIBLE. Type 'yes' to confirm: ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if input.trim() != "yes" {
            println!("Deletion cancelled");
            return Ok(());
        }
    }

    match &spec.target {
        DeploymentTarget::Aws(aws_config) => {
            info!("Deleting AWS resources");
            delete_aws(&spec, aws_config, delete_s3_objects, delete_cloudwatch_logs).await?;
        }
        DeploymentTarget::Kubernetes(k8s_config) => {
            info!("Deleting Kubernetes resources");
            delete_k8s(&spec, k8s_config).await?;
        }
    }

    println!();
    println!("Deletion complete!");
    println!("Spec file {} still exists for reference.", spec_file);

    Ok(())
}

/// Delete AWS resources
async fn delete_aws(
    spec: &Spec,
    config: &AwsConfig,
    delete_s3: bool,
    delete_logs: bool,
) -> Result<()> {
    let primary_region = config
        .regions
        .first()
        .ok_or_else(|| anyhow::anyhow!("No regions specified"))?;

    let aws_config = if config.profile_name.is_empty() {
        aws_config::from_env()
            .region(aws_config::Region::new(primary_region.clone()))
            .load()
            .await
    } else {
        aws_config::from_env()
            .profile_name(&config.profile_name)
            .region(aws_config::Region::new(primary_region.clone()))
            .load()
            .await
    };

    // Delete stacks in each region (reverse order: ASG -> Role -> VPC)
    for region in &config.regions {
        info!(region = %region, "Deleting resources in region");

        let regional_config = aws_config::from_env()
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let cfn_client = aws_sdk_cloudformation::Client::new(&regional_config);
        let ec2_client = aws_sdk_ec2::Client::new(&regional_config);

        // Delete ASG stacks first
        let non_anchor_stack = format!("{}-{}-non-anchor", spec.id, region);
        delete_stack(&cfn_client, &non_anchor_stack).await?;

        let anchor_stack = format!("{}-{}-anchor", spec.id, region);
        delete_stack(&cfn_client, &anchor_stack).await?;

        // Delete role stack
        let role_stack = format!("{}-{}-role", spec.id, region);
        delete_stack(&cfn_client, &role_stack).await?;

        // Delete VPC stack
        let vpc_stack = format!("{}-{}-vpc", spec.id, region);
        delete_stack(&cfn_client, &vpc_stack).await?;

        // Delete EC2 key pair
        let key_name = format!("{}-{}-key", spec.id, region);
        delete_ec2_key_pair(&ec2_client, &key_name).await?;

        // Delete local key file
        let key_path = format!("{}-{}.pem", spec.id, region);
        if std::path::Path::new(&key_path).exists() {
            std::fs::remove_file(&key_path)?;
            info!(path = %key_path, "Deleted local key file");
        }

        // Delete CloudWatch logs if requested
        if delete_logs {
            let logs_client = aws_sdk_cloudwatchlogs::Client::new(&regional_config);
            delete_cloudwatch_log_groups(&logs_client, &spec.id).await?;
        }
    }

    // Delete S3 objects and bucket if requested
    if delete_s3 {
        let s3_client = aws_sdk_s3::Client::new(&aws_config);
        delete_s3_bucket(&s3_client, &config.s3_bucket).await?;
    }

    // Schedule KMS key deletion if exists
    if let Some(kms_key) = &config.kms_key {
        let kms_client = aws_sdk_kms::Client::new(&aws_config);
        schedule_kms_key_deletion(&kms_client, &kms_key.id).await?;
    }

    info!("AWS resources deleted");
    Ok(())
}

/// Delete a CloudFormation stack
async fn delete_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<()> {
    // Check if stack exists
    let existing = client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await;

    let stack_exists = existing.is_ok()
        && existing
            .as_ref()
            .unwrap()
            .stacks()
            .iter()
            .any(|s| {
                !matches!(
                    s.stack_status(),
                    Some(StackStatus::DeleteComplete)
                )
            });

    if !stack_exists {
        info!(stack_name = %stack_name, "Stack does not exist or already deleted");
        return Ok(());
    }

    info!(stack_name = %stack_name, "Deleting CloudFormation stack");

    client
        .delete_stack()
        .stack_name(stack_name)
        .send()
        .await
        .context("Failed to initiate stack deletion")?;

    // Wait for deletion to complete
    wait_for_stack_deletion(client, stack_name).await?;

    info!(stack_name = %stack_name, "Stack deleted");
    Ok(())
}

/// Wait for CloudFormation stack deletion to complete
async fn wait_for_stack_deletion(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<()> {
    loop {
        let result = client
            .describe_stacks()
            .stack_name(stack_name)
            .send()
            .await;

        match result {
            Ok(response) => {
                if let Some(stack) = response.stacks().first() {
                    let status = stack.stack_status();
                    info!(stack_name = %stack_name, status = ?status, "Stack deletion status");

                    match status {
                        Some(StackStatus::DeleteComplete) => return Ok(()),
                        Some(StackStatus::DeleteFailed) => {
                            let reason = stack.stack_status_reason().unwrap_or("Unknown error");
                            anyhow::bail!("Stack deletion failed: {}", reason);
                        }
                        _ => {
                            tokio::time::sleep(STACK_POLL_INTERVAL).await;
                        }
                    }
                } else {
                    return Ok(());
                }
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("does not exist") {
                    return Ok(());
                }
                return Err(e).context("Failed to describe stack");
            }
        }
    }
}

/// Delete EC2 key pair
async fn delete_ec2_key_pair(
    client: &aws_sdk_ec2::Client,
    key_name: &str,
) -> Result<()> {
    let result = client
        .delete_key_pair()
        .key_name(key_name)
        .send()
        .await;

    match result {
        Ok(_) => {
            info!(key_name = %key_name, "EC2 key pair deleted");
        }
        Err(e) => {
            let msg = e.to_string();
            if !msg.contains("does not exist") && !msg.contains("InvalidKeyPair.NotFound") {
                return Err(e).context("Failed to delete EC2 key pair");
            }
            info!(key_name = %key_name, "EC2 key pair does not exist");
        }
    }

    Ok(())
}

/// Delete S3 bucket and all objects
async fn delete_s3_bucket(client: &aws_sdk_s3::Client, bucket: &str) -> Result<()> {
    info!(bucket = %bucket, "Deleting S3 bucket and contents");

    // List and delete all objects
    let mut continuation_token: Option<String> = None;
    loop {
        let mut request = client.list_objects_v2().bucket(bucket);
        if let Some(token) = continuation_token {
            request = request.continuation_token(token);
        }

        let result = match request.send().await {
            Ok(r) => r,
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NoSuchBucket") {
                    info!(bucket = %bucket, "Bucket does not exist");
                    return Ok(());
                }
                return Err(e).context("Failed to list bucket objects");
            }
        };

        let objects: Vec<_> = result
            .contents()
            .iter()
            .filter_map(|o| o.key())
            .collect();

        if objects.is_empty() {
            break;
        }

        for key in &objects {
            client
                .delete_object()
                .bucket(bucket)
                .key(*key)
                .send()
                .await
                .context("Failed to delete S3 object")?;
        }

        info!(count = objects.len(), "Deleted objects from bucket");

        if !result.is_truncated().unwrap_or(false) {
            break;
        }
        continuation_token = result.next_continuation_token().map(|s| s.to_string());
    }

    // Delete all object versions (for versioned buckets)
    let mut key_marker: Option<String> = None;
    let mut version_id_marker: Option<String> = None;
    loop {
        let mut request = client.list_object_versions().bucket(bucket);
        if let Some(km) = key_marker {
            request = request.key_marker(km);
        }
        if let Some(vim) = version_id_marker {
            request = request.version_id_marker(vim);
        }

        let result = match request.send().await {
            Ok(r) => r,
            Err(_) => break,
        };

        let versions: Vec<_> = result.versions().to_vec();
        let delete_markers: Vec<_> = result.delete_markers().to_vec();

        if versions.is_empty() && delete_markers.is_empty() {
            break;
        }

        for version in &versions {
            if let (Some(key), Some(vid)) = (version.key(), version.version_id()) {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .version_id(vid)
                    .send()
                    .await
                    .context("Failed to delete object version")?;
            }
        }

        for marker in &delete_markers {
            if let (Some(key), Some(vid)) = (marker.key(), marker.version_id()) {
                client
                    .delete_object()
                    .bucket(bucket)
                    .key(key)
                    .version_id(vid)
                    .send()
                    .await
                    .context("Failed to delete delete marker")?;
            }
        }

        if !result.is_truncated().unwrap_or(false) {
            break;
        }
        key_marker = result.next_key_marker().map(|s| s.to_string());
        version_id_marker = result.next_version_id_marker().map(|s| s.to_string());
    }

    // Delete the bucket
    client
        .delete_bucket()
        .bucket(bucket)
        .send()
        .await
        .context("Failed to delete S3 bucket")?;

    info!(bucket = %bucket, "S3 bucket deleted");
    Ok(())
}

/// Delete CloudWatch log groups
async fn delete_cloudwatch_log_groups(
    client: &aws_sdk_cloudwatchlogs::Client,
    id: &str,
) -> Result<()> {
    info!(id = %id, "Deleting CloudWatch log groups");

    let prefix = format!("/lux/{}", id);
    let mut next_token: Option<String> = None;

    loop {
        let mut request = client
            .describe_log_groups()
            .log_group_name_prefix(&prefix);
        if let Some(token) = next_token {
            request = request.next_token(token);
        }

        let result = request.send().await?;

        for log_group in result.log_groups() {
            if let Some(name) = log_group.log_group_name() {
                client
                    .delete_log_group()
                    .log_group_name(name)
                    .send()
                    .await?;
                info!(log_group = %name, "Deleted log group");
            }
        }

        next_token = result.next_token().map(|s| s.to_string());
        if next_token.is_none() {
            break;
        }
    }

    Ok(())
}

/// Schedule KMS key for deletion
async fn schedule_kms_key_deletion(
    client: &aws_sdk_kms::Client,
    key_id: &str,
) -> Result<()> {
    info!(key_id = %key_id, "Scheduling KMS key for deletion");

    let result = client
        .schedule_key_deletion()
        .key_id(key_id)
        .pending_window_in_days(7)
        .send()
        .await;

    match result {
        Ok(_) => {
            info!(key_id = %key_id, "KMS key scheduled for deletion in 7 days");
        }
        Err(e) => {
            let msg = e.to_string();
            if msg.contains("is pending deletion") {
                info!(key_id = %key_id, "KMS key already scheduled for deletion");
            } else if msg.contains("NotFoundException") {
                info!(key_id = %key_id, "KMS key not found");
            } else {
                warn!(key_id = %key_id, error = %e, "Failed to schedule KMS key deletion");
            }
        }
    }

    Ok(())
}

/// Delete Kubernetes resources
async fn delete_k8s(spec: &Spec, config: &K8sConfig) -> Result<()> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::{ConfigMap, Namespace, PersistentVolumeClaim, Service};
    use kube::api::{Api, DeleteParams};
    use kube::Client;

    info!(namespace = %config.namespace, "Deleting Kubernetes resources");

    let client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;

    // Delete StatefulSet
    let stateful_sets: Api<StatefulSet> = Api::namespaced(client.clone(), &config.namespace);
    match stateful_sets
        .delete("luxd", &DeleteParams::default())
        .await
    {
        Ok(_) => info!("StatefulSet deleted"),
        Err(kube::Error::Api(e)) if e.code == 404 => {
            info!("StatefulSet not found");
        }
        Err(e) => warn!(error = %e, "Failed to delete StatefulSet"),
    }

    // Wait for pods to terminate
    info!("Waiting for pods to terminate...");
    let pods: Api<k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), &config.namespace);

    for _ in 0..30 {
        let pod_list = pods
            .list(&kube::api::ListParams::default().labels("app=luxd"))
            .await?;

        if pod_list.items.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_secs(5)).await;
    }

    // Delete Services
    let services: Api<Service> = Api::namespaced(client.clone(), &config.namespace);
    match services.delete("luxd", &DeleteParams::default()).await {
        Ok(_) => info!("Service deleted"),
        Err(kube::Error::Api(e)) if e.code == 404 => {
            info!("Service not found");
        }
        Err(e) => warn!(error = %e, "Failed to delete Service"),
    }

    // Delete ConfigMaps
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    match config_maps
        .delete("luxd-config", &DeleteParams::default())
        .await
    {
        Ok(_) => info!("ConfigMap deleted"),
        Err(kube::Error::Api(e)) if e.code == 404 => {
            info!("ConfigMap not found");
        }
        Err(e) => warn!(error = %e, "Failed to delete ConfigMap"),
    }

    // Delete PVCs
    let pvcs: Api<PersistentVolumeClaim> = Api::namespaced(client.clone(), &config.namespace);
    let pvc_list = pvcs.list(&kube::api::ListParams::default()).await?;
    for pvc in pvc_list.items {
        if let Some(name) = pvc.metadata.name {
            if name.starts_with("data-luxd-") {
                match pvcs.delete(&name, &DeleteParams::default()).await {
                    Ok(_) => info!(pvc = %name, "PVC deleted"),
                    Err(e) => warn!(pvc = %name, error = %e, "Failed to delete PVC"),
                }
            }
        }
    }

    // Delete namespace
    let namespaces: Api<Namespace> = Api::all(client.clone());
    match namespaces
        .delete(&config.namespace, &DeleteParams::default())
        .await
    {
        Ok(_) => info!(namespace = %config.namespace, "Namespace deleted"),
        Err(kube::Error::Api(e)) if e.code == 404 => {
            info!(namespace = %config.namespace, "Namespace not found");
        }
        Err(e) => warn!(namespace = %config.namespace, error = %e, "Failed to delete Namespace"),
    }

    info!("Kubernetes resources deleted");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use lux_core::spec::DeploymentTarget;
    use tempfile::tempdir;

    #[test]
    fn test_spec_exists() {
        let dir = tempdir().unwrap();
        let spec_path = dir.path().join("test.yaml");

        let spec = Spec::new(
            "test".to_string(),
            DeploymentTarget::Kubernetes(K8sConfig {
                namespace: "test".to_string(),
                storage_class: String::new(),
                image_repository: "test".to_string(),
                image_tag: "latest".to_string(),
                image_pull_policy: "Always".to_string(),
                image_pull_secrets: vec![],
                service_account: None,
                security_context: None,
                use_lux_mpc: false,
                lux_mpc_endpoint: None,
                metrics_enabled: true,
                metrics_port: 9090,
            }),
        );

        spec.save(&spec_path).unwrap();
        assert!(spec_path.exists());
    }
}
