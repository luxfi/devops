//! Deploy blizzard load testing infrastructure

use crate::spec::{BlizzardSpec, DeploymentState, RegionalStacks};
use anyhow::{bail, Result};
use aws_sdk_cloudformation::types::{Capability, OnFailure, Parameter, StackStatus};
use aws_sdk_s3::primitives::ByteStream;
use rust_embed::RustEmbed;
use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::Path;
use std::time::Duration;
use tracing::{info, warn};

#[derive(RustEmbed)]
#[folder = "cfn-templates"]
struct CfnTemplates;

const STACK_POLL_INTERVAL: Duration = Duration::from_secs(10);
const STACK_TIMEOUT_SECS: u64 = 900; // 15 minutes

pub async fn execute(spec_file: &str, skip_prompt: bool) -> Result<()> {
    let mut spec = BlizzardSpec::load(Path::new(spec_file))?;

    info!("Applying blizzard spec: {}", spec.id);

    if spec.load_test.rpc_endpoints.is_empty() {
        bail!("No RPC endpoints configured. Edit spec file to add rpc_endpoints.");
    }

    if !skip_prompt {
        println!("About to deploy blizzard load testing infrastructure:");
        println!("  ID: {}", spec.id);
        println!("  Regions: {:?}", spec.aws.regions);
        println!(
            "  Instances per region: {}",
            spec.load_test.instances_per_region
        );
        println!("  Total instances: {}", spec.total_instances());
        println!("  Target RPC endpoints: {:?}", spec.load_test.rpc_endpoints);
        println!("  Aggregate TPS target: {}", spec.aggregate_tps());
        println!();
        print!("Continue? [y/N] ");
        io::stdout().flush()?;

        let mut input = String::new();
        io::stdin().read_line(&mut input)?;
        if !input.trim().eq_ignore_ascii_case("y") {
            println!("Aborted.");
            return Ok(());
        }
    }

    // Initialize deployment state
    spec.state = Some(DeploymentState {
        cloudformation_stacks: BTreeMap::new(),
        instance_ids: BTreeMap::new(),
        s3_blizzard_path: None,
        deployed_at: Some(chrono::Utc::now().to_rfc3339()),
    });

    // Deploy to each region
    for region in &spec.aws.regions.clone() {
        info!("Deploying to region: {}", region);
        deploy_region(&mut spec, region).await?;
    }

    // Save updated spec with deployment state
    spec.save(Path::new(spec_file))?;
    info!("Spec updated with deployment state");

    println!();
    println!("Deployment complete!");
    println!("  Total instances: {}", spec.total_instances());
    println!("  Aggregate TPS target: {}", spec.aggregate_tps());
    println!();
    println!("Query status: blizzardup query --spec-file {}", spec_file);

    Ok(())
}

async fn deploy_region(spec: &mut BlizzardSpec, region: &str) -> Result<()> {
    let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_cloudformation::config::Region::new(
            region.to_string(),
        ))
        .load()
        .await;

    let cfn_client = aws_sdk_cloudformation::Client::new(&config);
    let s3_client = aws_sdk_s3::Client::new(&config);
    let ec2_client = aws_sdk_ec2::Client::new(&config);

    let state = spec.state.as_mut().expect("state initialized");

    // Create S3 bucket if needed
    create_s3_bucket_if_needed(&s3_client, &spec.aws.s3_bucket, region).await?;

    // Upload bench spec to S3 (release mutable borrow temporarily)
    let _ = state;
    upload_spec_to_s3(&s3_client, spec, region).await?;
    let state = spec.state.as_mut().expect("state initialized");

    // Deploy VPC stack
    let vpc_stack_name = format!("{}-vpc", spec.id);
    info!("Creating VPC stack: {}", vpc_stack_name);

    let vpc_template = CfnTemplates::get("vpc.yaml")
        .ok_or_else(|| anyhow::anyhow!("vpc.yaml template not found"))?;
    let vpc_template_body = String::from_utf8_lossy(&vpc_template.data).to_string();

    let vpc_params = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(&spec.id)
            .build(),
        Parameter::builder()
            .parameter_key("SshPortIngressIpv4Range")
            .parameter_value(&spec.aws.ingress_ipv4_cidr)
            .build(),
    ];

    create_stack(&cfn_client, &vpc_stack_name, &vpc_template_body, vpc_params).await?;
    wait_for_stack(&cfn_client, &vpc_stack_name).await?;

    let vpc_outputs = get_stack_outputs(&cfn_client, &vpc_stack_name).await?;
    let vpc_id = vpc_outputs
        .get("VpcId")
        .ok_or_else(|| anyhow::anyhow!("VpcId not found in stack outputs"))?;
    let security_group_id = vpc_outputs
        .get("SecurityGroupId")
        .ok_or_else(|| anyhow::anyhow!("SecurityGroupId not found"))?;
    let public_subnet_ids = vpc_outputs
        .get("PublicSubnetIds")
        .ok_or_else(|| anyhow::anyhow!("PublicSubnetIds not found"))?;

    info!("VPC created: {}", vpc_id);

    // Deploy IAM stack
    let iam_stack_name = format!("{}-iam", spec.id);
    info!("Creating IAM stack: {}", iam_stack_name);

    let iam_template = CfnTemplates::get("ec2_instance_role.yaml")
        .ok_or_else(|| anyhow::anyhow!("ec2_instance_role.yaml template not found"))?;
    let iam_template_body = String::from_utf8_lossy(&iam_template.data).to_string();

    let iam_params = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(&spec.id)
            .build(),
        Parameter::builder()
            .parameter_key("S3BucketName")
            .parameter_value(&spec.aws.s3_bucket)
            .build(),
    ];

    create_stack_with_capabilities(
        &cfn_client,
        &iam_stack_name,
        &iam_template_body,
        iam_params,
        vec![Capability::CapabilityNamedIam],
    )
    .await?;
    wait_for_stack(&cfn_client, &iam_stack_name).await?;

    let iam_outputs = get_stack_outputs(&cfn_client, &iam_stack_name).await?;
    let instance_profile_arn = iam_outputs
        .get("InstanceProfileArn")
        .ok_or_else(|| anyhow::anyhow!("InstanceProfileArn not found"))?;

    info!("IAM role created");

    // Get or create EC2 key pair
    let ec2_key_name = get_or_create_key_pair(&ec2_client, &spec.id, region).await?;
    spec.aws
        .ec2_key_names
        .insert(region.to_string(), ec2_key_name.clone());

    // Deploy ASG stack
    let asg_stack_name = format!("{}-asg", spec.id);
    info!("Creating ASG stack: {}", asg_stack_name);

    let asg_template = CfnTemplates::get("asg_ubuntu.yaml")
        .ok_or_else(|| anyhow::anyhow!("asg_ubuntu.yaml template not found"))?;
    let asg_template_body = String::from_utf8_lossy(&asg_template.data).to_string();

    let on_demand_pct = match spec.machine.instance_mode {
        crate::spec::InstanceMode::Spot => "0",
        crate::spec::InstanceMode::OnDemand => "100",
    };

    let asg_params = vec![
        Parameter::builder()
            .parameter_key("Id")
            .parameter_value(&spec.id)
            .build(),
        Parameter::builder()
            .parameter_key("NodeKind")
            .parameter_value("worker")
            .build(),
        Parameter::builder()
            .parameter_key("S3BucketName")
            .parameter_value(&spec.aws.s3_bucket)
            .build(),
        Parameter::builder()
            .parameter_key("Ec2KeyPairName")
            .parameter_value(&ec2_key_name)
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
            .parameter_key("ArchType")
            .parameter_value(&spec.machine.arch)
            .build(),
        Parameter::builder()
            .parameter_key("OsType")
            .parameter_value(&spec.machine.os)
            .build(),
        Parameter::builder()
            .parameter_key("InstanceTypes")
            .parameter_value(&spec.machine.instance_types.join(","))
            .build(),
        Parameter::builder()
            .parameter_key("InstanceTypesCount")
            .parameter_value(&spec.machine.instance_types.len().to_string())
            .build(),
        Parameter::builder()
            .parameter_key("AsgName")
            .parameter_value(&format!("{}-asg", spec.id))
            .build(),
        Parameter::builder()
            .parameter_key("AsgMinSize")
            .parameter_value(&spec.load_test.instances_per_region.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("AsgMaxSize")
            .parameter_value(&spec.load_test.instances_per_region.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("AsgDesiredCapacity")
            .parameter_value(&spec.load_test.instances_per_region.to_string())
            .build(),
        Parameter::builder()
            .parameter_key("OnDemandPercentageAboveBaseCapacity")
            .parameter_value(on_demand_pct)
            .build(),
        Parameter::builder()
            .parameter_key("BlizzardDownloadSource")
            .parameter_value("s3")
            .build(),
    ];

    create_stack(&cfn_client, &asg_stack_name, &asg_template_body, asg_params).await?;
    wait_for_stack(&cfn_client, &asg_stack_name).await?;

    info!("ASG stack created");

    // Record stack names
    state.cloudformation_stacks.insert(
        region.to_string(),
        RegionalStacks {
            vpc_stack: Some(vpc_stack_name),
            iam_stack: Some(iam_stack_name),
            asg_stack: Some(asg_stack_name),
        },
    );

    Ok(())
}

async fn create_s3_bucket_if_needed(
    client: &aws_sdk_s3::Client,
    bucket: &str,
    region: &str,
) -> Result<()> {
    match client.head_bucket().bucket(bucket).send().await {
        Ok(_) => {
            info!("S3 bucket already exists: {}", bucket);
            Ok(())
        }
        Err(_) => {
            info!("Creating S3 bucket: {}", bucket);
            let mut builder = client.create_bucket().bucket(bucket);

            // LocationConstraint not needed for us-east-1
            if region != "us-east-1" {
                use aws_sdk_s3::types::{BucketLocationConstraint, CreateBucketConfiguration};
                let constraint = BucketLocationConstraint::from(region);
                let config = CreateBucketConfiguration::builder()
                    .location_constraint(constraint)
                    .build();
                builder = builder.create_bucket_configuration(config);
            }

            builder.send().await?;
            info!("S3 bucket created: {}", bucket);
            Ok(())
        }
    }
}

async fn upload_spec_to_s3(
    client: &aws_sdk_s3::Client,
    spec: &BlizzardSpec,
    _region: &str,
) -> Result<()> {
    let spec_yaml = serde_yaml::to_string(spec)?;
    let key = format!("{}/blizzardup.yaml", spec.id);

    info!("Uploading spec to s3://{}/{}", spec.aws.s3_bucket, key);

    client
        .put_object()
        .bucket(&spec.aws.s3_bucket)
        .key(&key)
        .body(ByteStream::from(spec_yaml.into_bytes()))
        .content_type("text/yaml")
        .send()
        .await?;

    Ok(())
}

async fn get_or_create_key_pair(
    client: &aws_sdk_ec2::Client,
    id: &str,
    region: &str,
) -> Result<String> {
    let key_name = format!("{}-{}", id, region);

    match client
        .describe_key_pairs()
        .key_names(&key_name)
        .send()
        .await
    {
        Ok(resp) if !resp.key_pairs().is_empty() => {
            info!("Using existing key pair: {}", key_name);
            Ok(key_name)
        }
        _ => {
            info!("Creating key pair: {}", key_name);
            let resp = client
                .create_key_pair()
                .key_name(&key_name)
                .key_type(aws_sdk_ec2::types::KeyType::Ed25519)
                .send()
                .await?;

            if let Some(material) = resp.key_material() {
                let key_path = format!("{}.pem", key_name);
                std::fs::write(&key_path, material)?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o400))?;
                }
                info!("Private key saved to: {}", key_path);
            }

            Ok(key_name)
        }
    }
}

async fn create_stack(
    client: &aws_sdk_cloudformation::Client,
    name: &str,
    template: &str,
    params: Vec<Parameter>,
) -> Result<()> {
    create_stack_with_capabilities(client, name, template, params, vec![]).await
}

async fn create_stack_with_capabilities(
    client: &aws_sdk_cloudformation::Client,
    name: &str,
    template: &str,
    params: Vec<Parameter>,
    capabilities: Vec<Capability>,
) -> Result<()> {
    let mut builder = client
        .create_stack()
        .stack_name(name)
        .template_body(template)
        .on_failure(OnFailure::Delete)
        .timeout_in_minutes((STACK_TIMEOUT_SECS / 60) as i32);

    for param in params {
        builder = builder.parameters(param);
    }

    for cap in capabilities {
        builder = builder.capabilities(cap);
    }

    builder.send().await?;
    Ok(())
}

async fn wait_for_stack(client: &aws_sdk_cloudformation::Client, name: &str) -> Result<()> {
    let start = std::time::Instant::now();

    loop {
        if start.elapsed().as_secs() > STACK_TIMEOUT_SECS {
            bail!("Stack creation timeout: {}", name);
        }

        let resp = client.describe_stacks().stack_name(name).send().await?;

        let stack = resp
            .stacks()
            .first()
            .ok_or_else(|| anyhow::anyhow!("Stack not found: {}", name))?;

        let status = stack
            .stack_status()
            .ok_or_else(|| anyhow::anyhow!("No status"))?;

        match status {
            StackStatus::CreateComplete => {
                info!("Stack ready: {}", name);
                return Ok(());
            }
            StackStatus::CreateInProgress => {
                info!("Stack creating... {}", name);
            }
            StackStatus::CreateFailed
            | StackStatus::RollbackComplete
            | StackStatus::RollbackFailed
            | StackStatus::DeleteComplete
            | StackStatus::DeleteFailed => {
                let reason = stack.stack_status_reason().unwrap_or("unknown");
                bail!("Stack creation failed: {} - {}", name, reason);
            }
            _ => {
                warn!("Unexpected stack status: {:?}", status);
            }
        }

        tokio::time::sleep(STACK_POLL_INTERVAL).await;
    }
}

async fn get_stack_outputs(
    client: &aws_sdk_cloudformation::Client,
    name: &str,
) -> Result<BTreeMap<String, String>> {
    let resp = client.describe_stacks().stack_name(name).send().await?;

    let stack = resp
        .stacks()
        .first()
        .ok_or_else(|| anyhow::anyhow!("Stack not found: {}", name))?;

    let mut outputs = BTreeMap::new();
    for output in stack.outputs() {
        if let (Some(key), Some(value)) = (output.output_key(), output.output_value()) {
            outputs.insert(key.to_string(), value.to_string());
        }
    }

    Ok(outputs)
}
