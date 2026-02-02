//! Apply/deploy a specification to AWS or Kubernetes

use anyhow::{Context, Result};
use aws_sdk_cloudformation::types::{Capability, OnFailure, Parameter, StackStatus};
use aws_sdk_ec2::types::Filter;
use aws_sdk_s3::primitives::ByteStream;
use lux_core::aws::cfn;
use lux_core::spec::{AwsConfig, DeploymentTarget, K8sConfig, KmsKey, RegionalResource, Spec};
use lux_core::types::NodeInfo;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

const STACK_POLL_INTERVAL: Duration = Duration::from_secs(10);
const STACK_TIMEOUT_MINUTES: i32 = 30;

/// Execute the apply command
pub async fn execute(spec_file: &str, skip_prompt: bool) -> Result<()> {
    let mut spec = Spec::load(Path::new(spec_file)).context("Failed to load spec file")?;

    info!(id = %spec.id, "Applying deployment spec");

    if !skip_prompt {
        println!("Deployment plan:");
        println!("  ID: {}", spec.id);
        println!("  Anchor nodes: {}", spec.network.anchor_nodes);
        println!("  Non-anchor nodes: {}", spec.network.non_anchor_nodes);
        println!();

        match &spec.target {
            DeploymentTarget::Aws(aws) => {
                println!("  Target: AWS");
                println!("  Regions: {}", aws.regions.join(", "));
                println!("  S3 bucket: {}", aws.s3_bucket);
            }
            DeploymentTarget::Kubernetes(k8s) => {
                println!("  Target: Kubernetes");
                println!("  Namespace: {}", k8s.namespace);
            }
        }
        println!();

        print!("Proceed with deployment? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Deployment cancelled");
            return Ok(());
        }
    }

    match &spec.target.clone() {
        DeploymentTarget::Aws(aws_config) => {
            info!("Deploying to AWS");
            deploy_aws(&mut spec, aws_config, spec_file).await?;
        }
        DeploymentTarget::Kubernetes(k8s_config) => {
            info!("Deploying to Kubernetes");
            deploy_k8s(&mut spec, k8s_config, spec_file).await?;
        }
    }

    println!();
    println!("Deployment complete!");
    println!("View endpoints: luxup endpoints --spec-file {}", spec_file);

    Ok(())
}

/// Deploy to AWS using CloudFormation
async fn deploy_aws(spec: &mut Spec, config: &AwsConfig, spec_file: &str) -> Result<()> {
    let primary_region = config
        .regions
        .first()
        .ok_or_else(|| anyhow::anyhow!("No regions specified"))?;

    // Load AWS config
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

    // Verify identity
    let sts_client = aws_sdk_sts::Client::new(&aws_config);
    let identity = sts_client
        .get_caller_identity()
        .send()
        .await
        .context("Failed to verify AWS identity")?;

    let account_id = identity.account().unwrap_or("unknown").to_string();
    let user_id = identity.user_id().unwrap_or("unknown").to_string();
    info!(account_id = %account_id, user_id = %user_id, "AWS identity verified");

    // Create S3 bucket
    let s3_client = aws_sdk_s3::Client::new(&aws_config);
    create_s3_bucket(&s3_client, &config.s3_bucket, primary_region).await?;

    // Upload spec to S3
    upload_spec_to_s3(&s3_client, &config.s3_bucket, &spec.id, spec).await?;

    // Create KMS key if not exists
    let kms_key = if config.kms_key.is_some() {
        config.kms_key.clone()
    } else {
        let kms_client = aws_sdk_kms::Client::new(&aws_config);
        Some(create_kms_key(&kms_client, &spec.id, &account_id).await?)
    };

    // Deploy to each region
    let mut all_nodes = Vec::new();
    let mut updated_regional_resources = config.regional_resources.clone();

    for region in &config.regions {
        info!(region = %region, "Deploying to region");

        let regional_config = aws_config::from_env()
            .region(aws_config::Region::new(region.clone()))
            .load()
            .await;

        let cfn_client = aws_sdk_cloudformation::Client::new(&regional_config);
        let ec2_client = aws_sdk_ec2::Client::new(&regional_config);

        // Create EC2 key pair
        let key_name = format!("{}-{}-key", spec.id, region);
        let key_path = format!("{}-{}.pem", spec.id, region);
        create_ec2_key_pair(&ec2_client, &key_name, &key_path).await?;

        // Deploy VPC stack
        let vpc_stack_name = format!("{}-{}-vpc", spec.id, region);
        let vpc_outputs = deploy_vpc_stack(
            &cfn_client,
            &vpc_stack_name,
            &spec.id,
            &user_id,
            &config.ingress_ipv4_cidr,
        )
        .await?;

        let vpc_id = vpc_outputs
            .get("VpcId")
            .ok_or_else(|| anyhow::anyhow!("VPC stack missing VpcId output"))?
            .clone();
        let security_group_id = vpc_outputs
            .get("SecurityGroupId")
            .ok_or_else(|| anyhow::anyhow!("VPC stack missing SecurityGroupId output"))?
            .clone();
        let public_subnet_ids = vpc_outputs
            .get("PublicSubnetIds")
            .ok_or_else(|| anyhow::anyhow!("VPC stack missing PublicSubnetIds output"))?
            .clone();

        // Deploy EC2 instance role stack
        let role_stack_name = format!("{}-{}-role", spec.id, region);
        let role_outputs = deploy_instance_role_stack(
            &cfn_client,
            &role_stack_name,
            &spec.id,
            &config.s3_bucket,
            kms_key.as_ref().map(|k| k.arn.as_str()).unwrap_or(""),
        )
        .await?;

        let instance_profile_arn = role_outputs
            .get("InstanceProfileArn")
            .ok_or_else(|| anyhow::anyhow!("Role stack missing InstanceProfileArn output"))?
            .clone();

        // Deploy anchor nodes ASG
        let anchor_asg_name = format!("{}-{}-anchor", spec.id, region);
        let anchor_outputs = if spec.network.anchor_nodes > 0 {
            Some(
                deploy_asg_stack(
                    &cfn_client,
                    &anchor_asg_name,
                    &spec.id,
                    &user_id,
                    spec.network.network_id.0,
                    "anchor",
                    kms_key.as_ref().map(|k| k.arn.as_str()).unwrap_or(""),
                    &spec.aad_tag,
                    primary_region,
                    &config.s3_bucket,
                    &key_name,
                    &instance_profile_arn,
                    &public_subnet_ids,
                    &security_group_id,
                    &vpc_id,
                    &spec.machine,
                    spec.network.anchor_nodes,
                    spec.luxd_release_tag
                        .as_deref()
                        .unwrap_or("v1.0.0"),
                )
                .await?,
            )
        } else {
            None
        };

        // Deploy non-anchor nodes ASG
        let non_anchor_asg_name = format!("{}-{}-non-anchor", spec.id, region);
        let non_anchor_outputs = if spec.network.non_anchor_nodes > 0 {
            Some(
                deploy_asg_stack(
                    &cfn_client,
                    &non_anchor_asg_name,
                    &spec.id,
                    &user_id,
                    spec.network.network_id.0,
                    "non-anchor",
                    kms_key.as_ref().map(|k| k.arn.as_str()).unwrap_or(""),
                    &spec.aad_tag,
                    primary_region,
                    &config.s3_bucket,
                    &key_name,
                    &instance_profile_arn,
                    &public_subnet_ids,
                    &security_group_id,
                    &vpc_id,
                    &spec.machine,
                    spec.network.non_anchor_nodes,
                    spec.luxd_release_tag
                        .as_deref()
                        .unwrap_or("v1.0.0"),
                )
                .await?,
            )
        } else {
            None
        };

        // Update regional resources
        updated_regional_resources.insert(
            region.clone(),
            RegionalResource {
                region: region.clone(),
                ec2_key_name: key_name,
                ec2_key_path: key_path,
                vpc_id: Some(vpc_id),
                security_group_id: Some(security_group_id),
                cloudformation_asg_anchor: anchor_outputs.map(|_| anchor_asg_name),
                cloudformation_asg_non_anchor: non_anchor_outputs.map(|_| non_anchor_asg_name),
            },
        );

        // Wait for instances and collect node info
        tokio::time::sleep(Duration::from_secs(30)).await;
        let nodes = collect_node_info(&ec2_client, &spec.id, region).await?;
        all_nodes.extend(nodes);
    }

    // Update spec with deployment state
    if let DeploymentTarget::Aws(ref mut aws) = spec.target {
        aws.regional_resources = updated_regional_resources;
        aws.kms_key = kms_key;
    }
    spec.created_nodes = Some(all_nodes);

    // Save updated spec
    spec.save(Path::new(spec_file))
        .context("Failed to save updated spec")?;

    info!("AWS deployment complete");
    Ok(())
}

/// Create S3 bucket if it doesn't exist
async fn create_s3_bucket(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    region: &str,
) -> Result<()> {
    let head_result = client.head_bucket().bucket(bucket).send().await;
    if head_result.is_ok() {
        info!(bucket = %bucket, "S3 bucket already exists");
        return Ok(());
    }

    info!(bucket = %bucket, "Creating S3 bucket");

    let mut request = client.create_bucket().bucket(bucket);

    // us-east-1 doesn't require LocationConstraint
    if region != "us-east-1" {
        let constraint = aws_sdk_s3::types::BucketLocationConstraint::from(region);
        let config = aws_sdk_s3::types::CreateBucketConfiguration::builder()
            .location_constraint(constraint)
            .build();
        request = request.create_bucket_configuration(config);
    }

    request
        .send()
        .await
        .context("Failed to create S3 bucket")?;

    // Enable versioning
    client
        .put_bucket_versioning()
        .bucket(bucket)
        .versioning_configuration(
            aws_sdk_s3::types::VersioningConfiguration::builder()
                .status(aws_sdk_s3::types::BucketVersioningStatus::Enabled)
                .build(),
        )
        .send()
        .await
        .context("Failed to enable bucket versioning")?;

    // Block public access
    client
        .put_public_access_block()
        .bucket(bucket)
        .public_access_block_configuration(
            aws_sdk_s3::types::PublicAccessBlockConfiguration::builder()
                .block_public_acls(true)
                .block_public_policy(true)
                .ignore_public_acls(true)
                .restrict_public_buckets(true)
                .build(),
        )
        .send()
        .await
        .context("Failed to block public access")?;

    Ok(())
}

/// Upload spec to S3
async fn upload_spec_to_s3(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    id: &str,
    spec: &Spec,
) -> Result<()> {
    let key = format!("{}/spec.yaml", id);
    let body = serde_yaml::to_string(spec)?;

    client
        .put_object()
        .bucket(bucket)
        .key(&key)
        .body(ByteStream::from(body.into_bytes()))
        .content_type("application/yaml")
        .send()
        .await
        .context("Failed to upload spec to S3")?;

    info!(key = %key, "Spec uploaded to S3");
    Ok(())
}

/// Create KMS key for encryption
async fn create_kms_key(
    client: &aws_sdk_kms::Client,
    id: &str,
    account_id: &str,
) -> Result<KmsKey> {
    let policy = format!(
        r#"{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Sid": "Enable IAM User Permissions",
                    "Effect": "Allow",
                    "Principal": {{"AWS": "arn:aws:iam::{}:root"}},
                    "Action": "kms:*",
                    "Resource": "*"
                }}
            ]
        }}"#,
        account_id
    );

    let result = client
        .create_key()
        .description(format!("Lux Network encryption key for {}", id))
        .policy(policy)
        .tags(
            aws_sdk_kms::types::Tag::builder()
                .tag_key("Name")
                .tag_value(format!("{}-kms", id))
                .build()?,
        )
        .send()
        .await
        .context("Failed to create KMS key")?;

    let metadata = result
        .key_metadata()
        .ok_or_else(|| anyhow::anyhow!("KMS key creation returned no metadata"))?;

    let key = KmsKey {
        id: metadata.key_id().to_string(),
        arn: metadata.arn().unwrap_or("").to_string(),
    };

    // Create alias
    client
        .create_alias()
        .alias_name(format!("alias/{}-key", id))
        .target_key_id(&key.id)
        .send()
        .await
        .context("Failed to create KMS alias")?;

    info!(key_id = %key.id, "KMS key created");
    Ok(key)
}

/// Create EC2 key pair
async fn create_ec2_key_pair(
    client: &aws_sdk_ec2::Client,
    key_name: &str,
    key_path: &str,
) -> Result<()> {
    // Check if key exists
    let existing = client
        .describe_key_pairs()
        .key_names(key_name)
        .send()
        .await;

    if existing.is_ok() {
        info!(key_name = %key_name, "EC2 key pair already exists");
        return Ok(());
    }

    let result = client
        .create_key_pair()
        .key_name(key_name)
        .key_type(aws_sdk_ec2::types::KeyType::Rsa)
        .send()
        .await
        .context("Failed to create EC2 key pair")?;

    if let Some(material) = result.key_material() {
        std::fs::write(key_path, material).context("Failed to write key file")?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o400))?;
        }
        info!(key_name = %key_name, path = %key_path, "EC2 key pair created");
    }

    Ok(())
}

/// Deploy VPC CloudFormation stack
async fn deploy_vpc_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
    id: &str,
    user_id: &str,
    ingress_cidr: &str,
) -> Result<BTreeMap<String, String>> {
    let template = cfn::get_template(cfn::templates::VPC)
        .ok_or_else(|| anyhow::anyhow!("VPC template not found"))?;

    let parameters = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(id)
            .build(),
        Parameter::builder()
            .parameter_key("UserId")
            .parameter_value(user_id)
            .build(),
        Parameter::builder()
            .parameter_key("SshPortIngressIpv4Range")
            .parameter_value(ingress_cidr)
            .build(),
        Parameter::builder()
            .parameter_key("HttpPortIngressIpv4Range")
            .parameter_value(ingress_cidr)
            .build(),
        Parameter::builder()
            .parameter_key("StakingPortIngressIpv4Range")
            .parameter_value(ingress_cidr)
            .build(),
    ];

    deploy_stack(client, stack_name, &template, parameters).await
}

/// Deploy EC2 instance role CloudFormation stack
async fn deploy_instance_role_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
    id: &str,
    s3_bucket: &str,
    kms_key_arn: &str,
) -> Result<BTreeMap<String, String>> {
    let template = cfn::get_template(cfn::templates::EC2_INSTANCE_ROLE)
        .ok_or_else(|| anyhow::anyhow!("EC2 instance role template not found"))?;

    let parameters = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(id)
            .build(),
        Parameter::builder()
            .parameter_key("S3BucketName")
            .parameter_value(s3_bucket)
            .build(),
        Parameter::builder()
            .parameter_key("KmsKeyArn")
            .parameter_value(kms_key_arn)
            .build(),
    ];

    deploy_stack(client, stack_name, &template, parameters).await
}

/// Deploy ASG CloudFormation stack
#[allow(clippy::too_many_arguments)]
async fn deploy_asg_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
    id: &str,
    user_id: &str,
    network_id: u32,
    node_kind: &str,
    kms_key_arn: &str,
    aad_tag: &str,
    s3_region: &str,
    s3_bucket: &str,
    ec2_key_name: &str,
    instance_profile_arn: &str,
    public_subnet_ids: &str,
    security_group_id: &str,
    vpc_id: &str,
    machine: &lux_core::spec::MachineConfig,
    desired_capacity: u32,
    luxd_release_tag: &str,
) -> Result<BTreeMap<String, String>> {
    let template = cfn::get_template(cfn::templates::ASG_UBUNTU)
        .ok_or_else(|| anyhow::anyhow!("ASG template not found"))?;

    let volume_size = if node_kind == "anchor" {
        machine.anchor_volume_size_gb
    } else {
        machine.non_anchor_volume_size_gb
    };

    let parameters = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(id)
            .build(),
        Parameter::builder()
            .parameter_key("UserId")
            .parameter_value(user_id)
            .build(),
        Parameter::builder()
            .parameter_key("NetworkId")
            .parameter_value(network_id.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("NodeKind")
            .parameter_value(node_kind)
            .build(),
        Parameter::builder()
            .parameter_key("KmsKeyArn")
            .parameter_value(kms_key_arn)
            .build(),
        Parameter::builder()
            .parameter_key("AadTag")
            .parameter_value(aad_tag)
            .build(),
        Parameter::builder()
            .parameter_key("S3Region")
            .parameter_value(s3_region)
            .build(),
        Parameter::builder()
            .parameter_key("S3BucketName")
            .parameter_value(s3_bucket)
            .build(),
        Parameter::builder()
            .parameter_key("Ec2KeyPairName")
            .parameter_value(ec2_key_name)
            .build(),
        Parameter::builder()
            .parameter_key("InstanceProfileArn")
            .parameter_value(instance_profile_arn)
            .build(),
        Parameter::builder()
            .parameter_key("PublicSubnetIds")
            .parameter_value(public_subnet_ids)
            .build(),
        Parameter::builder()
            .parameter_key("SecurityGroupId")
            .parameter_value(security_group_id)
            .build(),
        Parameter::builder()
            .parameter_key("NlbVpcId")
            .parameter_value(vpc_id)
            .build(),
        Parameter::builder()
            .parameter_key("AsgName")
            .parameter_value(stack_name)
            .build(),
        Parameter::builder()
            .parameter_key("AsgDesiredCapacity")
            .parameter_value(desired_capacity.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("AsgMinSize")
            .parameter_value("0")
            .build(),
        Parameter::builder()
            .parameter_key("AsgMaxSize")
            .parameter_value((desired_capacity + 1).to_string())
            .build(),
        Parameter::builder()
            .parameter_key("VolumeSize")
            .parameter_value(volume_size.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("VolumeType")
            .parameter_value(&machine.volume_type)
            .build(),
        Parameter::builder()
            .parameter_key("VolumeIops")
            .parameter_value(machine.volume_iops.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("VolumeThroughput")
            .parameter_value(machine.volume_throughput.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("ArchType")
            .parameter_value(&machine.arch)
            .build(),
        Parameter::builder()
            .parameter_key("AvalancheGoReleaseTag")
            .parameter_value(luxd_release_tag)
            .build(),
    ];

    deploy_stack(client, stack_name, &template, parameters).await
}

/// Deploy a CloudFormation stack and wait for completion
async fn deploy_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
    template: &str,
    parameters: Vec<Parameter>,
) -> Result<BTreeMap<String, String>> {
    info!(stack_name = %stack_name, "Deploying CloudFormation stack");

    // Check if stack exists
    let existing = client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await;

    let is_update = existing.is_ok()
        && existing
            .as_ref()
            .unwrap()
            .stacks()
            .iter()
            .any(|s| {
                !matches!(
                    s.stack_status(),
                    Some(StackStatus::DeleteComplete) | Some(StackStatus::DeleteInProgress)
                )
            });

    if is_update {
        info!(stack_name = %stack_name, "Updating existing stack");
        let result = client
            .update_stack()
            .stack_name(stack_name)
            .template_body(template)
            .set_parameters(Some(parameters))
            .capabilities(Capability::CapabilityIam)
            .capabilities(Capability::CapabilityNamedIam)
            .send()
            .await;

        match result {
            Ok(_) => {}
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No updates are to be performed") {
                    info!(stack_name = %stack_name, "No updates needed");
                    return get_stack_outputs(client, stack_name).await;
                }
                return Err(e).context("Failed to update stack");
            }
        }
    } else {
        client
            .create_stack()
            .stack_name(stack_name)
            .template_body(template)
            .set_parameters(Some(parameters))
            .capabilities(Capability::CapabilityIam)
            .capabilities(Capability::CapabilityNamedIam)
            .on_failure(OnFailure::Delete)
            .timeout_in_minutes(STACK_TIMEOUT_MINUTES)
            .send()
            .await
            .context("Failed to create stack")?;
    }

    // Wait for stack completion
    wait_for_stack(client, stack_name).await?;

    get_stack_outputs(client, stack_name).await
}

/// Wait for CloudFormation stack to complete
async fn wait_for_stack(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<()> {
    loop {
        let result = client
            .describe_stacks()
            .stack_name(stack_name)
            .send()
            .await
            .context("Failed to describe stack")?;

        let stack = result
            .stacks()
            .first()
            .ok_or_else(|| anyhow::anyhow!("Stack not found"))?;

        let status = stack.stack_status();
        info!(stack_name = %stack_name, status = ?status, "Stack status");

        match status {
            Some(StackStatus::CreateComplete) | Some(StackStatus::UpdateComplete) => {
                return Ok(());
            }
            Some(StackStatus::CreateFailed)
            | Some(StackStatus::RollbackComplete)
            | Some(StackStatus::RollbackFailed)
            | Some(StackStatus::UpdateRollbackComplete)
            | Some(StackStatus::UpdateRollbackFailed)
            | Some(StackStatus::DeleteComplete)
            | Some(StackStatus::DeleteFailed) => {
                let reason = stack.stack_status_reason().unwrap_or("Unknown error");
                anyhow::bail!("Stack {} failed: {}", stack_name, reason);
            }
            _ => {
                tokio::time::sleep(STACK_POLL_INTERVAL).await;
            }
        }
    }
}

/// Get CloudFormation stack outputs
async fn get_stack_outputs(
    client: &aws_sdk_cloudformation::Client,
    stack_name: &str,
) -> Result<BTreeMap<String, String>> {
    let result = client
        .describe_stacks()
        .stack_name(stack_name)
        .send()
        .await
        .context("Failed to describe stack")?;

    let stack = result
        .stacks()
        .first()
        .ok_or_else(|| anyhow::anyhow!("Stack not found"))?;

    let mut outputs = BTreeMap::new();
    for output in stack.outputs() {
        if let (Some(key), Some(value)) = (output.output_key(), output.output_value()) {
            outputs.insert(key.to_string(), value.to_string());
        }
    }

    Ok(outputs)
}

/// Collect node info from running EC2 instances
async fn collect_node_info(
    client: &aws_sdk_ec2::Client,
    id: &str,
    region: &str,
) -> Result<Vec<NodeInfo>> {
    let result = client
        .describe_instances()
        .filters(
            Filter::builder()
                .name("tag:ID")
                .values(id)
                .build(),
        )
        .filters(
            Filter::builder()
                .name("instance-state-name")
                .values("running")
                .build(),
        )
        .send()
        .await
        .context("Failed to describe instances")?;

    let mut nodes = Vec::new();
    for reservation in result.reservations() {
        for instance in reservation.instances() {
            let instance_id = instance.instance_id().unwrap_or("unknown").to_string();
            let public_ip = instance
                .public_ip_address()
                .unwrap_or("unknown")
                .to_string();

            let mut is_anchor = false;
            for tag in instance.tags() {
                if tag.key() == Some("NODE_KIND") && tag.value() == Some("anchor") {
                    is_anchor = true;
                    break;
                }
            }

            nodes.push(NodeInfo {
                machine_id: instance_id.clone(),
                node_id: format!("NodeID-{}", &instance_id[..8.min(instance_id.len())]),
                public_ip,
                http_port: 9650,
                staking_port: 9651,
                region: region.to_string(),
                is_anchor,
            });
        }
    }

    info!(count = nodes.len(), region = %region, "Collected node info");
    Ok(nodes)
}

/// Deploy to Kubernetes
async fn deploy_k8s(spec: &mut Spec, config: &K8sConfig, spec_file: &str) -> Result<()> {
    use k8s_openapi::api::apps::v1::StatefulSet;
    use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Service};
    use kube::api::{Api, PostParams};
    use kube::Client;

    info!(namespace = %config.namespace, "Deploying to Kubernetes");

    let client = Client::try_default()
        .await
        .context("Failed to create Kubernetes client")?;

    // Create namespace
    let namespaces: Api<Namespace> = Api::all(client.clone());
    let ns = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Namespace",
        "metadata": {
            "name": config.namespace,
            "labels": {
                "app.kubernetes.io/name": "lux",
                "app.kubernetes.io/instance": spec.id
            }
        }
    }))?;

    match namespaces.create(&PostParams::default(), &ns).await {
        Ok(_) => info!(namespace = %config.namespace, "Namespace created"),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!(namespace = %config.namespace, "Namespace already exists");
        }
        Err(e) => return Err(e).context("Failed to create namespace"),
    }

    // Create ConfigMap with luxd config
    let config_maps: Api<ConfigMap> = Api::namespaced(client.clone(), &config.namespace);
    let luxd_config = serde_json::to_string_pretty(&spec.luxd_config)?;
    let cm = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "ConfigMap",
        "metadata": {
            "name": "luxd-config",
            "namespace": config.namespace
        },
        "data": {
            "config.json": luxd_config
        }
    }))?;

    match config_maps.create(&PostParams::default(), &cm).await {
        Ok(_) => info!("ConfigMap created"),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!("ConfigMap already exists, updating");
            config_maps
                .replace("luxd-config", &PostParams::default(), &cm)
                .await?;
        }
        Err(e) => return Err(e).context("Failed to create ConfigMap"),
    }

    // Create headless service for StatefulSet
    let services: Api<Service> = Api::namespaced(client.clone(), &config.namespace);
    let svc = serde_json::from_value(serde_json::json!({
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": {
            "name": "luxd",
            "namespace": config.namespace,
            "labels": {
                "app": "luxd"
            }
        },
        "spec": {
            "clusterIP": "None",
            "selector": {
                "app": "luxd"
            },
            "ports": [
                {
                    "name": "http",
                    "port": 9650,
                    "targetPort": 9650
                },
                {
                    "name": "staking",
                    "port": 9651,
                    "targetPort": 9651
                }
            ]
        }
    }))?;

    match services.create(&PostParams::default(), &svc).await {
        Ok(_) => info!("Service created"),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!("Service already exists");
        }
        Err(e) => return Err(e).context("Failed to create Service"),
    }

    // Create StatefulSet
    let total_nodes = spec.network.anchor_nodes + spec.network.non_anchor_nodes;
    let stateful_sets: Api<StatefulSet> = Api::namespaced(client.clone(), &config.namespace);
    let sts = serde_json::from_value(serde_json::json!({
        "apiVersion": "apps/v1",
        "kind": "StatefulSet",
        "metadata": {
            "name": "luxd",
            "namespace": config.namespace
        },
        "spec": {
            "serviceName": "luxd",
            "replicas": total_nodes,
            "selector": {
                "matchLabels": {
                    "app": "luxd"
                }
            },
            "template": {
                "metadata": {
                    "labels": {
                        "app": "luxd"
                    }
                },
                "spec": {
                    "containers": [{
                        "name": "luxd",
                        "image": format!("{}:{}", config.image_repository, config.image_tag),
                        "imagePullPolicy": config.image_pull_policy,
                        "ports": [
                            {"containerPort": 9650, "name": "http"},
                            {"containerPort": 9651, "name": "staking"}
                        ],
                        "volumeMounts": [
                            {
                                "name": "data",
                                "mountPath": "/data"
                            },
                            {
                                "name": "config",
                                "mountPath": "/etc/luxd"
                            }
                        ],
                        "resources": {
                            "requests": {
                                "cpu": "1",
                                "memory": "4Gi"
                            },
                            "limits": {
                                "cpu": "4",
                                "memory": "8Gi"
                            }
                        },
                        "readinessProbe": {
                            "httpGet": {
                                "path": "/ext/health",
                                "port": 9650
                            },
                            "initialDelaySeconds": 30,
                            "periodSeconds": 10
                        },
                        "livenessProbe": {
                            "httpGet": {
                                "path": "/ext/health",
                                "port": 9650
                            },
                            "initialDelaySeconds": 60,
                            "periodSeconds": 30
                        }
                    }],
                    "volumes": [{
                        "name": "config",
                        "configMap": {
                            "name": "luxd-config"
                        }
                    }]
                }
            },
            "volumeClaimTemplates": [{
                "metadata": {
                    "name": "data"
                },
                "spec": {
                    "accessModes": ["ReadWriteOnce"],
                    "storageClassName": if config.storage_class.is_empty() { serde_json::Value::Null } else { serde_json::Value::String(config.storage_class.clone()) },
                    "resources": {
                        "requests": {
                            "storage": "200Gi"
                        }
                    }
                }
            }]
        }
    }))?;

    match stateful_sets.create(&PostParams::default(), &sts).await {
        Ok(_) => info!("StatefulSet created"),
        Err(kube::Error::Api(e)) if e.code == 409 => {
            info!("StatefulSet already exists, updating");
            stateful_sets
                .replace("luxd", &PostParams::default(), &sts)
                .await?;
        }
        Err(e) => return Err(e).context("Failed to create StatefulSet"),
    }

    // Wait for pods to be ready
    info!("Waiting for pods to be ready...");
    let pods: Api<k8s_openapi::api::core::v1::Pod> =
        Api::namespaced(client.clone(), &config.namespace);

    for i in 0..60 {
        let pod_list = pods
            .list(&kube::api::ListParams::default().labels("app=luxd"))
            .await?;

        let ready_count = pod_list
            .items
            .iter()
            .filter(|p| {
                p.status
                    .as_ref()
                    .and_then(|s| s.conditions.as_ref())
                    .map(|c| c.iter().any(|cond| cond.type_ == "Ready" && cond.status == "True"))
                    .unwrap_or(false)
            })
            .count();

        info!(ready = ready_count, total = total_nodes, "Pod status");
        if ready_count >= total_nodes as usize {
            break;
        }
        if i == 59 {
            warn!("Timeout waiting for pods, continuing anyway");
        }
        tokio::time::sleep(Duration::from_secs(10)).await;
    }

    // Collect node info
    let pod_list = pods
        .list(&kube::api::ListParams::default().labels("app=luxd"))
        .await?;

    let nodes: Vec<NodeInfo> = pod_list
        .items
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = p.metadata.name.clone().unwrap_or_default();
            let pod_ip = p
                .status
                .as_ref()
                .and_then(|s| s.pod_ip.clone())
                .unwrap_or_default();
            NodeInfo {
                machine_id: name.clone(),
                node_id: format!("NodeID-{}", name),
                public_ip: pod_ip,
                http_port: 9650,
                staking_port: 9651,
                region: "kubernetes".to_string(),
                is_anchor: i < spec.network.anchor_nodes as usize,
            }
        })
        .collect();

    spec.created_nodes = Some(nodes);
    spec.save(Path::new(spec_file))
        .context("Failed to save updated spec")?;

    info!("Kubernetes deployment complete");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_spec_loading() {
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
        let loaded = Spec::load(&spec_path).unwrap();
        assert_eq!(loaded.id, "test");
    }
}
