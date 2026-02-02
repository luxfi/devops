//! Generate default specification for Lux Network deployments

use anyhow::{Context, Result};
use lux_core::spec::{
    AwsConfig, DeploymentTarget, K8sConfig, MachineConfig, NetworkConfig, RegionalResource, Spec,
    SPEC_VERSION,
};
use lux_core::NetworkId;
use std::collections::BTreeMap;
use std::path::Path;
use tracing::info;

/// Default instance types for AWS regions
fn default_instance_types() -> Vec<String> {
    vec![
        "c6a.xlarge".to_string(),
        "m6a.xlarge".to_string(),
        "m5.xlarge".to_string(),
        "c5.xlarge".to_string(),
    ]
}

/// Execute the default-spec command
pub async fn execute(
    output: &str,
    target: &str,
    network_name: Option<&str>,
    anchor_nodes: u32,
    non_anchor_nodes: u32,
    regions: &str,
) -> Result<()> {
    let id = network_name
        .map(|s| s.to_string())
        .unwrap_or_else(|| format!("lux-{}", &uuid::Uuid::new_v4().to_string()[..8]));

    info!(id = %id, target = %target, "Generating deployment spec");

    let region_list: Vec<String> = regions
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if region_list.is_empty() {
        anyhow::bail!("At least one region must be specified");
    }

    let deployment_target = match target {
        "aws" => build_aws_target(&id, &region_list)?,
        "k8s" | "kubernetes" => build_k8s_target(),
        _ => anyhow::bail!("Unknown target: {}. Use 'aws' or 'k8s'", target),
    };

    let mut instance_types = BTreeMap::new();
    for region in &region_list {
        instance_types.insert(region.clone(), default_instance_types());
    }

    let spec = Spec {
        version: SPEC_VERSION,
        id: id.clone(),
        aad_tag: format!("{}-aad", id),
        target: deployment_target,
        network: NetworkConfig {
            network_id: NetworkId::LOCAL,
            anchor_nodes,
            non_anchor_nodes,
            validate_period_in_days: 365,
        },
        machine: MachineConfig {
            arch: "amd64".to_string(),
            os: "ubuntu22.04".to_string(),
            instance_types,
            anchor_volume_size_gb: 400,
            non_anchor_volume_size_gb: 300,
            volume_type: "gp3".to_string(),
            volume_iops: 3000,
            volume_throughput: 125,
        },
        luxd_config: Default::default(),
        c_chain_config: Default::default(),
        genesis_template: None,
        prefunded_keys: None,
        upload_artifacts: None,
        luxd_release_tag: Some("v1.0.0".to_string()),
        created_nodes: None,
    };

    let path = Path::new(output);
    spec.save(path).context("Failed to write spec file")?;

    info!(path = %output, "Spec file saved");
    println!("Generated spec file: {}", output);
    println!();
    println!("Deployment ID: {}", id);
    println!("Target: {}", target);
    println!("Anchor nodes: {}", anchor_nodes);
    println!("Non-anchor nodes: {}", non_anchor_nodes);
    println!("Regions: {}", region_list.join(", "));
    println!();
    println!("Next steps:");
    println!("  1. Review and customize: {}", output);
    println!("  2. Deploy: luxup apply --spec-file {}", output);

    Ok(())
}

/// Build AWS deployment target configuration
fn build_aws_target(id: &str, regions: &[String]) -> Result<DeploymentTarget> {
    let mut regional_resources = BTreeMap::new();
    for region in regions {
        regional_resources.insert(
            region.clone(),
            RegionalResource {
                region: region.clone(),
                ec2_key_name: format!("{}-{}-key", id, region),
                ec2_key_path: format!("{}-{}.pem", id, region),
                vpc_id: None,
                security_group_id: None,
                cloudformation_asg_anchor: None,
                cloudformation_asg_non_anchor: None,
            },
        );
    }

    Ok(DeploymentTarget::Aws(AwsConfig {
        profile_name: String::new(),
        regions: regions.to_vec(),
        s3_bucket: format!("{}-artifacts", id),
        ingress_ipv4_cidr: "0.0.0.0/0".to_string(),
        kms_key: None,
        regional_resources,
        enable_nlb: false,
        nlb_acm_certificate_arns: BTreeMap::new(),
        keep_resources: false,
        disable_logs_auto_removal: false,
        metrics_fetch_interval_seconds: 60,
    }))
}

/// Build Kubernetes deployment target configuration
fn build_k8s_target() -> DeploymentTarget {
    DeploymentTarget::Kubernetes(K8sConfig {
        namespace: "lux".to_string(),
        storage_class: String::new(),
        image_repository: "ghcr.io/luxfi/luxd".to_string(),
        image_tag: "latest".to_string(),
        image_pull_policy: "IfNotPresent".to_string(),
        image_pull_secrets: vec![],
        service_account: None,
        security_context: None,
        use_lux_mpc: false,
        lux_mpc_endpoint: None,
        metrics_enabled: true,
        metrics_port: 9090,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn test_generate_aws_spec() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("test-spec.yaml");

        execute(
            output.to_str().unwrap(),
            "aws",
            Some("test-network"),
            1,
            2,
            "us-west-2,us-east-1",
        )
        .await
        .unwrap();

        let spec = Spec::load(&output).unwrap();
        assert_eq!(spec.id, "test-network");
        assert_eq!(spec.network.anchor_nodes, 1);
        assert_eq!(spec.network.non_anchor_nodes, 2);

        match &spec.target {
            DeploymentTarget::Aws(aws) => {
                assert_eq!(aws.regions.len(), 2);
                assert!(aws.regions.contains(&"us-west-2".to_string()));
                assert!(aws.regions.contains(&"us-east-1".to_string()));
            }
            _ => panic!("Expected AWS target"),
        }
    }

    #[tokio::test]
    async fn test_generate_k8s_spec() {
        let dir = tempdir().unwrap();
        let output = dir.path().join("test-spec.yaml");

        execute(output.to_str().unwrap(), "k8s", None, 1, 2, "us-west-2")
            .await
            .unwrap();

        let spec = Spec::load(&output).unwrap();
        assert!(spec.id.starts_with("lux-"));

        match &spec.target {
            DeploymentTarget::Kubernetes(k8s) => {
                assert_eq!(k8s.namespace, "lux");
            }
            _ => panic!("Expected K8s target"),
        }
    }
}
