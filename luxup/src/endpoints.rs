//! Show endpoints for a deployment and perform health checks

use anyhow::{Context, Result};
use lux_core::spec::{DeploymentTarget, Spec};
use std::path::Path;
use std::time::Duration;
use tracing::info;

const HEALTH_CHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// Health check result for a node
#[derive(Debug)]
struct HealthStatus {
    node_id: String,
    endpoint: String,
    healthy: bool,
    message: String,
    response_time_ms: u64,
}

/// Execute the endpoints command
pub async fn execute(spec_file: &str) -> Result<()> {
    let spec = Spec::load(Path::new(spec_file)).context("Failed to load spec file")?;

    info!(id = %spec.id, "Getting endpoints");

    println!("Deployment: {}", spec.id);
    println!("Network ID: {}", spec.network.network_id);
    println!();

    match &spec.target {
        DeploymentTarget::Aws(aws) => {
            print_aws_endpoints(&spec, aws).await?;
        }
        DeploymentTarget::Kubernetes(k8s) => {
            print_k8s_endpoints(&spec, k8s).await?;
        }
    }

    Ok(())
}

/// Print AWS endpoints and check health
async fn print_aws_endpoints(
    spec: &Spec,
    aws: &lux_core::spec::AwsConfig,
) -> Result<()> {
    println!("Target: AWS");
    println!("Regions: {}", aws.regions.join(", "));
    println!("S3 Bucket: {}", aws.s3_bucket);
    println!();

    if let Some(nodes) = &spec.created_nodes {
        if nodes.is_empty() {
            println!("No nodes deployed. Run 'luxup apply' first.");
            return Ok(());
        }

        println!("Nodes ({}):", nodes.len());
        println!("{:-<80}", "");

        let mut health_results = Vec::new();

        for node in nodes {
            let health = check_node_health(
                &node.node_id,
                &node.public_ip,
                node.http_port,
            )
            .await;

            let status_icon = if health.healthy { "[OK]" } else { "[FAIL]" };
            let node_type = if node.is_anchor { "anchor" } else { "validator" };

            println!(
                "{} {} ({}) - {} ({})",
                status_icon,
                node.node_id,
                node_type,
                node.region,
                health.message
            );
            println!("    HTTP:    http://{}:{}", node.public_ip, node.http_port);
            println!(
                "    Staking: {}:{}",
                node.public_ip, node.staking_port
            );
            println!(
                "    SSH:     ssh -i {}-{}.pem ubuntu@{}",
                spec.id, node.region, node.public_ip
            );
            println!();

            health_results.push(health);
        }

        // Summary
        let healthy_count = health_results.iter().filter(|h| h.healthy).count();
        let total_count = health_results.len();

        println!("{:-<80}", "");
        println!(
            "Health Summary: {}/{} nodes healthy",
            healthy_count, total_count
        );

        if healthy_count < total_count {
            println!();
            println!("Unhealthy nodes:");
            for health in &health_results {
                if !health.healthy {
                    println!("  {} - {} ({})", health.node_id, health.endpoint, health.message);
                }
            }
        }

        // RPC endpoints
        if healthy_count > 0 {
            let first_healthy = health_results
                .iter()
                .zip(nodes.iter())
                .find(|(h, _)| h.healthy)
                .map(|(_, n)| n);

            if let Some(node) = first_healthy {
                println!();
                println!("RPC Endpoints:");
                println!(
                    "  X-Chain: http://{}:{}/ext/bc/X",
                    node.public_ip, node.http_port
                );
                println!(
                    "  P-Chain: http://{}:{}/ext/bc/P",
                    node.public_ip, node.http_port
                );
                println!(
                    "  C-Chain: http://{}:{}/ext/bc/C/rpc",
                    node.public_ip, node.http_port
                );
                println!(
                    "  C-Chain WS: ws://{}:{}/ext/bc/C/ws",
                    node.public_ip, node.http_port
                );
                println!(
                    "  Health: http://{}:{}/ext/health",
                    node.public_ip, node.http_port
                );
            }
        }
    } else {
        println!("No nodes found. Run 'luxup apply' first.");
    }

    Ok(())
}

/// Print Kubernetes endpoints and check health
async fn print_k8s_endpoints(
    spec: &Spec,
    k8s: &lux_core::spec::K8sConfig,
) -> Result<()> {
    println!("Target: Kubernetes");
    println!("Namespace: {}", k8s.namespace);
    println!("Image: {}:{}", k8s.image_repository, k8s.image_tag);
    println!();

    // Internal services
    println!("Internal Services:");
    println!("{:-<80}", "");
    println!(
        "  HTTP:    luxd.{}.svc.cluster.local:9650",
        k8s.namespace
    );
    println!(
        "  Staking: luxd.{}.svc.cluster.local:9651",
        k8s.namespace
    );

    if k8s.metrics_enabled {
        println!(
            "  Metrics: luxd.{}.svc.cluster.local:{}",
            k8s.namespace, k8s.metrics_port
        );
    }

    println!();
    println!("Pod Endpoints:");
    println!("{:-<80}", "");

    if let Some(nodes) = &spec.created_nodes {
        let mut health_results = Vec::new();

        for (i, node) in nodes.iter().enumerate() {
            let pod_name = format!("luxd-{}", i);
            let pod_dns = format!(
                "{}.luxd.{}.svc.cluster.local",
                pod_name, k8s.namespace
            );

            let health = check_node_health(&node.node_id, &node.public_ip, node.http_port).await;

            let status_icon = if health.healthy { "[OK]" } else { "[FAIL]" };
            let node_type = if node.is_anchor { "anchor" } else { "validator" };

            println!(
                "{} {} ({}) - {}",
                status_icon, pod_name, node_type, health.message
            );
            println!("    DNS:  {}", pod_dns);
            println!("    IP:   {}", node.public_ip);
            println!();

            health_results.push(health);
        }

        // Summary
        let healthy_count = health_results.iter().filter(|h| h.healthy).count();
        let total_count = health_results.len();

        println!("{:-<80}", "");
        println!(
            "Health Summary: {}/{} pods healthy",
            healthy_count, total_count
        );
    } else {
        println!("No pods found. Run 'luxup apply' first.");
    }

    // kubectl commands
    println!();
    println!("Useful Commands:");
    println!("  kubectl get pods -n {}", k8s.namespace);
    println!("  kubectl logs -n {} luxd-0 -f", k8s.namespace);
    println!(
        "  kubectl port-forward -n {} svc/luxd 9650:9650",
        k8s.namespace
    );
    println!("  kubectl exec -n {} -it luxd-0 -- /bin/sh", k8s.namespace);

    Ok(())
}

/// Check node health via HTTP API
async fn check_node_health(node_id: &str, ip: &str, port: u16) -> HealthStatus {
    let endpoint = format!("http://{}:{}/ext/health", ip, port);

    let client = reqwest::Client::builder()
        .timeout(HEALTH_CHECK_TIMEOUT)
        .build()
        .unwrap_or_default();

    let start = std::time::Instant::now();

    match client.get(&endpoint).send().await {
        Ok(response) => {
            let response_time = start.elapsed().as_millis() as u64;

            if response.status().is_success() {
                // Parse health response
                match response.json::<serde_json::Value>().await {
                    Ok(json) => {
                        let healthy = json
                            .get("healthy")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false);

                        if healthy {
                            HealthStatus {
                                node_id: node_id.to_string(),
                                endpoint,
                                healthy: true,
                                message: format!("healthy ({}ms)", response_time),
                                response_time_ms: response_time,
                            }
                        } else {
                            // Extract unhealthy checks
                            let checks = json
                                .get("checks")
                                .and_then(|c| c.as_object())
                                .map(|c| {
                                    c.iter()
                                        .filter(|(_, v)| {
                                            v.get("healthy")
                                                .and_then(|h| h.as_bool())
                                                .map(|h| !h)
                                                .unwrap_or(false)
                                        })
                                        .map(|(k, _)| k.as_str())
                                        .collect::<Vec<_>>()
                                        .join(", ")
                                })
                                .unwrap_or_else(|| "unknown".to_string());

                            HealthStatus {
                                node_id: node_id.to_string(),
                                endpoint,
                                healthy: false,
                                message: format!("unhealthy: {}", checks),
                                response_time_ms: response_time,
                            }
                        }
                    }
                    Err(e) => HealthStatus {
                        node_id: node_id.to_string(),
                        endpoint,
                        healthy: false,
                        message: format!("parse error: {}", e),
                        response_time_ms: response_time,
                    },
                }
            } else {
                HealthStatus {
                    node_id: node_id.to_string(),
                    endpoint,
                    healthy: false,
                    message: format!("HTTP {}", response.status()),
                    response_time_ms: response_time,
                }
            }
        }
        Err(e) => {
            let response_time = start.elapsed().as_millis() as u64;

            let message = if e.is_timeout() {
                "timeout".to_string()
            } else if e.is_connect() {
                "connection refused".to_string()
            } else {
                format!("error: {}", e)
            };

            HealthStatus {
                node_id: node_id.to_string(),
                endpoint,
                healthy: false,
                message,
                response_time_ms: response_time,
            }
        }
    }
}

/// Query bootstrapped status from a node
#[allow(dead_code)]
async fn check_bootstrapped(ip: &str, port: u16, chain: &str) -> Result<bool> {
    let url = format!("http://{}:{}/ext/info", ip, port);

    let client = reqwest::Client::builder()
        .timeout(HEALTH_CHECK_TIMEOUT)
        .build()?;

    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "info.isBootstrapped",
        "params": {
            "chain": chain
        }
    });

    let response = client
        .post(&url)
        .json(&body)
        .send()
        .await?;

    let json: serde_json::Value = response.json().await?;

    Ok(json
        .get("result")
        .and_then(|r| r.get("isBootstrapped"))
        .and_then(|b| b.as_bool())
        .unwrap_or(false))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_health_check_unreachable() {
        let health = check_node_health("test-node", "127.0.0.1", 19650).await;
        assert!(!health.healthy);
        assert!(
            health.message.contains("connection refused")
                || health.message.contains("timeout")
                || health.message.contains("error")
        );
    }
}
