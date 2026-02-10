//! Kubernetes controller for LuxNetwork resources

use crate::crd::{LuxNetwork, LuxNetworkStatus};
use crate::error::{OperatorError, Result};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{StatefulSet, StatefulSetSpec};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, HTTPGetAction, PersistentVolumeClaim,
    PersistentVolumeClaimSpec, Pod, PodSpec, PodTemplateSpec, Probe, ResourceRequirements,
    Service, ServicePort, ServiceSpec as K8sServiceSpec, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{
    api::{Api, DeleteParams, ListParams, Patch, PatchParams},
    runtime::{
        controller::{Action, Controller},
        watcher::Config as WatcherConfig,
    },
    Client, Resource, ResourceExt,
};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tracing::{debug, error, info, warn};

const LUXD_HTTP_PORT: i32 = 9650;
const LUXD_STAKING_PORT: i32 = 9651;
const LUXD_METRICS_PORT: i32 = 9090;

/// Controller context
pub struct Context {
    pub client: Client,
    pub mpc_endpoint: Option<String>,
}

/// Run the controller
pub async fn run(
    client: Client,
    namespace: String,
    mpc_endpoint: Option<String>,
) -> Result<()> {
    let ctx = Arc::new(Context {
        client: client.clone(),
        mpc_endpoint,
    });

    let networks: Api<LuxNetwork> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    info!("Starting LuxNetwork controller");

    Controller::new(networks, WatcherConfig::default())
        .run(reconcile, error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled: {:?}", o),
                Err(e) => error!("Reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

/// Reconcile a LuxNetwork resource
async fn reconcile(network: Arc<LuxNetwork>, ctx: Arc<Context>) -> Result<Action> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling LuxNetwork {}/{}", namespace, name);

    let networks: Api<LuxNetwork> = Api::namespaced(ctx.client.clone(), &namespace);

    // Get current status or create default
    let current_status = network.status.clone().unwrap_or_default();

    // Determine current phase and take action
    let phase = current_status.phase.as_str();

    let new_status = match phase {
        "" | "Pending" => {
            info!("Network {} is pending, starting creation", name);
            create_network(&network, &ctx).await?
        }
        "Creating" => {
            info!("Network {} is creating, checking progress", name);
            check_creation_progress(&network, &ctx).await?
        }
        "Bootstrapping" => {
            info!("Network {} is bootstrapping", name);
            check_bootstrap_progress(&network, &ctx).await?
        }
        "Running" => {
            debug!("Network {} is running, checking health", name);
            check_health(&network, &ctx).await?
        }
        "Degraded" => {
            warn!("Network {} is degraded, attempting recovery", name);
            attempt_recovery(&network, &ctx).await?
        }
        _ => {
            warn!("Network {} has unknown phase: {}", name, phase);
            current_status.clone()
        }
    };

    // Update status if changed
    if new_status.phase != current_status.phase
        || new_status.ready_validators != current_status.ready_validators
    {
        let patch = Patch::Merge(serde_json::json!({
            "status": new_status
        }));
        networks
            .patch_status(&name, &PatchParams::default(), &patch)
            .await
            .map_err(OperatorError::KubeApi)?;
    }

    // Requeue based on phase
    let requeue_after = match new_status.phase.as_str() {
        "Running" => Duration::from_secs(60),
        "Creating" | "Bootstrapping" => Duration::from_secs(10),
        "Degraded" => Duration::from_secs(30),
        _ => Duration::from_secs(15),
    };

    Ok(Action::requeue(requeue_after))
}

/// Create a new network: StatefulSet, Services, ConfigMap
async fn create_network(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let spec = &network.spec;
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());

    info!(
        "Creating network {} with {} validators",
        name, spec.validators
    );

    // Create ConfigMap for luxd config
    create_config_map(network, ctx).await?;

    // Create headless Service for pod discovery
    create_headless_service(network, ctx).await?;

    // Create ClusterIP Service for RPC access
    create_rpc_service(network, ctx).await?;

    // Create StatefulSet for validators
    create_statefulset(network, ctx).await?;

    if let Some(mpc) = &spec.mpc {
        if mpc.enabled {
            info!("MPC enabled for network {}, endpoint: {}", name, mpc.endpoint);
        }
    }

    Ok(LuxNetworkStatus {
        phase: "Creating".to_string(),
        ready_validators: 0,
        total_validators: spec.validators,
        network_id: Some(spec.network_id),
        bootstrap_endpoints: vec![format!(
            "http://{}-0.{}-headless.{}.svc:{}",
            name, name, namespace, LUXD_HTTP_PORT
        )],
        ..Default::default()
    })
}

/// Create ConfigMap with luxd configuration
async fn create_config_map(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let configmaps: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &namespace);

    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    // Build luxd config
    let mut config: BTreeMap<String, serde_json::Value> = BTreeMap::new();
    config.insert("network-id".to_string(), serde_json::json!(spec.network_id));
    config.insert("http-host".to_string(), serde_json::json!("0.0.0.0"));
    config.insert("http-port".to_string(), serde_json::json!(LUXD_HTTP_PORT));
    config.insert("staking-port".to_string(), serde_json::json!(LUXD_STAKING_PORT));
    config.insert("log-level".to_string(), serde_json::json!("info"));
    config.insert("log-display-level".to_string(), serde_json::json!("info"));
    config.insert("api-admin-enabled".to_string(), serde_json::json!(true));
    config.insert("api-health-enabled".to_string(), serde_json::json!(true));
    config.insert("api-info-enabled".to_string(), serde_json::json!(true));

    // Merge user-provided config
    for (k, v) in &spec.config {
        config.insert(k.clone(), v.clone());
    }

    let config_json = serde_json::to_string_pretty(&config)
        .map_err(OperatorError::Serialization)?;

    let mut data = BTreeMap::new();
    data.insert("config.json".to_string(), config_json);

    // Add genesis if provided
    if let Some(genesis) = &spec.genesis {
        let genesis_json = serde_json::to_string_pretty(genesis)
            .map_err(OperatorError::Serialization)?;
        data.insert("genesis.json".to_string(), genesis_json);
    }

    let cm = ConfigMap {
        metadata: kube::core::ObjectMeta {
            name: Some(format!("{}-config", name)),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    apply_resource(&configmaps, &format!("{}-config", name), &cm).await
}

/// Create headless Service for StatefulSet pod discovery
async fn create_headless_service(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());

    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);

    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(format!("{}-headless", name)),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            cluster_ip: Some("None".to_string()),
            selector: Some(labels),
            ports: Some(vec![
                ServicePort {
                    name: Some("http".to_string()),
                    port: LUXD_HTTP_PORT,
                    target_port: Some(IntOrString::Int(LUXD_HTTP_PORT)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("staking".to_string()),
                    port: LUXD_STAKING_PORT,
                    target_port: Some(IntOrString::Int(LUXD_STAKING_PORT)),
                    ..Default::default()
                },
            ]),
            publish_not_ready_addresses: Some(true),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&services, &format!("{}-headless", name), &svc).await
}

/// Create ClusterIP Service for RPC access
async fn create_rpc_service(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);

    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    let mut annotations = spec.service.annotations.clone();
    annotations.insert(
        "lux.network/network-id".to_string(),
        spec.network_id.to_string(),
    );

    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(format!("{}-rpc", name)),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            annotations: Some(annotations),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            type_: Some(spec.service.service_type.clone()),
            selector: Some(labels),
            ports: Some(vec![
                ServicePort {
                    name: Some("http".to_string()),
                    port: LUXD_HTTP_PORT,
                    target_port: Some(IntOrString::Int(LUXD_HTTP_PORT)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("metrics".to_string()),
                    port: LUXD_METRICS_PORT,
                    target_port: Some(IntOrString::Int(LUXD_METRICS_PORT)),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&services, &format!("{}-rpc", name), &svc).await
}

/// Create StatefulSet for validator pods
async fn create_statefulset(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let statefulsets: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), &namespace);

    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    // Build resource requirements
    let resources = build_resource_requirements(&spec.resources);

    // Build container
    let container = Container {
        name: "luxd".to_string(),
        image: Some(format!("{}:{}", spec.image.repository, spec.image.tag)),
        image_pull_policy: Some(spec.image.pull_policy.clone()),
        args: Some({
            let mut args = vec![
                "--config-file=/etc/luxd/config.json".to_string(),
                "--data-dir=/data".to_string(),
            ];
            // Add chain tracking flags
            let tracking = &spec.chain_tracking;
            if tracking.track_all_chains {
                args.push("--track-all-chains".to_string());
            } else if !tracking.tracked_chains.is_empty() {
                args.push(format!("--track-chains={}", tracking.tracked_chains.join(",")));
            }
            args
        }),
        ports: Some(vec![
            ContainerPort {
                name: Some("http".to_string()),
                container_port: LUXD_HTTP_PORT,
                ..Default::default()
            },
            ContainerPort {
                name: Some("staking".to_string()),
                container_port: LUXD_STAKING_PORT,
                ..Default::default()
            },
            ContainerPort {
                name: Some("metrics".to_string()),
                container_port: LUXD_METRICS_PORT,
                ..Default::default()
            },
        ]),
        env: Some(vec![
            EnvVar {
                name: "LUX_NETWORK_ID".to_string(),
                value: Some(spec.network_id.to_string()),
                ..Default::default()
            },
            EnvVar {
                name: "POD_NAME".to_string(),
                value_from: Some(k8s_openapi::api::core::v1::EnvVarSource {
                    field_ref: Some(k8s_openapi::api::core::v1::ObjectFieldSelector {
                        field_path: "metadata.name".to_string(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
        ]),
        volume_mounts: Some(vec![
            VolumeMount {
                name: "config".to_string(),
                mount_path: "/etc/luxd".to_string(),
                read_only: Some(true),
                ..Default::default()
            },
            VolumeMount {
                name: "data".to_string(),
                mount_path: "/data".to_string(),
                ..Default::default()
            },
        ]),
        resources: Some(resources),
        liveness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/ext/health".to_string()),
                port: IntOrString::Int(LUXD_HTTP_PORT),
                ..Default::default()
            }),
            initial_delay_seconds: Some(30),
            period_seconds: Some(30),
            timeout_seconds: Some(10),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        readiness_probe: Some(Probe {
            http_get: Some(HTTPGetAction {
                path: Some("/ext/health".to_string()),
                port: IntOrString::Int(LUXD_HTTP_PORT),
                ..Default::default()
            }),
            initial_delay_seconds: Some(10),
            period_seconds: Some(10),
            timeout_seconds: Some(5),
            failure_threshold: Some(3),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Build PVC template
    let pvc_template = PersistentVolumeClaim {
        metadata: kube::core::ObjectMeta {
            name: Some("data".to_string()),
            ..Default::default()
        },
        spec: Some(PersistentVolumeClaimSpec {
            access_modes: Some(vec!["ReadWriteOnce".to_string()]),
            storage_class_name: spec.storage.storage_class.clone(),
            resources: Some(ResourceRequirements {
                requests: Some({
                    let mut m = BTreeMap::new();
                    m.insert("storage".to_string(), Quantity(spec.storage.size.clone()));
                    m
                }),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Build config volume
    let config_volume = k8s_openapi::api::core::v1::Volume {
        name: "config".to_string(),
        config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
            name: Some(format!("{}-config", name)),
            ..Default::default()
        }),
        ..Default::default()
    };

    let sts = StatefulSet {
        metadata: kube::core::ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(StatefulSetSpec {
            replicas: Some(spec.validators as i32),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            service_name: format!("{}-headless", name),
            template: PodTemplateSpec {
                metadata: Some(kube::core::ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![container],
                    volumes: Some(vec![config_volume]),
                    termination_grace_period_seconds: Some(60),
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![pvc_template]),
            pod_management_policy: Some("Parallel".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&statefulsets, &name, &sts).await
}

/// Check creation progress by querying StatefulSet status
async fn check_creation_progress(
    network: &LuxNetwork,
    ctx: &Context,
) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();

    let statefulsets: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), &namespace);

    let sts = match statefulsets.get(&name).await {
        Ok(sts) => sts,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            warn!("StatefulSet {} not found, recreating", name);
            return create_network(network, ctx).await;
        }
        Err(e) => return Err(OperatorError::KubeApi(e)),
    };

    let sts_status = sts.status.unwrap_or_default();
    let ready_replicas = sts_status.ready_replicas.unwrap_or(0) as u32;
    let desired = spec.validators;

    info!(
        "Network {} StatefulSet: {}/{} pods ready",
        name, ready_replicas, desired
    );

    if ready_replicas >= desired {
        Ok(LuxNetworkStatus {
            phase: "Bootstrapping".to_string(),
            ready_validators: ready_replicas,
            total_validators: desired,
            network_id: status.network_id,
            bootstrap_endpoints: build_bootstrap_endpoints(&name, &namespace, desired),
            ..Default::default()
        })
    } else {
        Ok(LuxNetworkStatus {
            phase: "Creating".to_string(),
            ready_validators: ready_replicas,
            total_validators: desired,
            network_id: status.network_id,
            bootstrap_endpoints: status.bootstrap_endpoints,
            ..Default::default()
        })
    }
}

/// Check bootstrap progress by querying node health API
async fn check_bootstrap_progress(
    network: &LuxNetwork,
    ctx: &Context,
) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = format!("app.kubernetes.io/instance={}", name);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let mut bootstrapped_count = 0u32;

    for pod in &pod_list.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();

        if pod_ip.is_empty() {
            debug!("Pod {} has no IP yet", pod_name);
            continue;
        }

        match check_node_bootstrapped(&pod_ip).await {
            Ok(true) => {
                debug!("Pod {} is bootstrapped", pod_name);
                bootstrapped_count += 1;
            }
            Ok(false) => {
                debug!("Pod {} is not yet bootstrapped", pod_name);
            }
            Err(e) => {
                debug!("Failed to check bootstrap status for {}: {}", pod_name, e);
            }
        }
    }

    info!(
        "Network {} bootstrap status: {}/{} nodes bootstrapped",
        name, bootstrapped_count, spec.validators
    );

    if bootstrapped_count >= spec.validators {
        Ok(LuxNetworkStatus {
            phase: "Running".to_string(),
            ready_validators: spec.validators,
            total_validators: spec.validators,
            network_id: status.network_id,
            bootstrap_endpoints: build_bootstrap_endpoints(&name, &namespace, spec.validators),
            ..Default::default()
        })
    } else {
        Ok(LuxNetworkStatus {
            phase: "Bootstrapping".to_string(),
            ready_validators: bootstrapped_count,
            total_validators: spec.validators,
            network_id: status.network_id,
            bootstrap_endpoints: status.bootstrap_endpoints,
            ..Default::default()
        })
    }
}

/// Check node health via HTTP
async fn check_health(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = format!("app.kubernetes.io/instance={}", name);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let mut healthy_count = 0u32;
    let mut unhealthy_pods: Vec<String> = Vec::new();

    for pod in &pod_list.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();

        if pod_ip.is_empty() {
            unhealthy_pods.push(pod_name);
            continue;
        }

        match check_node_health(&pod_ip).await {
            Ok(true) => {
                healthy_count += 1;
            }
            Ok(false) => {
                warn!("Pod {} is unhealthy", pod_name);
                unhealthy_pods.push(pod_name);
            }
            Err(e) => {
                warn!("Failed to check health for {}: {}", pod_name, e);
                unhealthy_pods.push(pod_name);
            }
        }
    }

    debug!(
        "Network {} health: {}/{} validators healthy",
        name, healthy_count, spec.validators
    );

    // Determine phase based on health
    let threshold = (spec.validators * 2) / 3; // 2/3 quorum
    let phase = if healthy_count >= spec.validators {
        "Running".to_string()
    } else if healthy_count >= threshold {
        warn!(
            "Network {} degraded: only {}/{} healthy",
            name, healthy_count, spec.validators
        );
        "Degraded".to_string()
    } else {
        error!(
            "Network {} critical: only {}/{} healthy, below quorum {}",
            name, healthy_count, spec.validators, threshold
        );
        "Degraded".to_string()
    };

    Ok(LuxNetworkStatus {
        phase,
        ready_validators: healthy_count,
        total_validators: spec.validators,
        network_id: status.network_id,
        bootstrap_endpoints: status.bootstrap_endpoints,
        ..Default::default()
    })
}

/// Attempt recovery by restarting unhealthy pods
async fn attempt_recovery(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = format!("app.kubernetes.io/instance={}", name);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let mut recovered = 0u32;
    let mut healthy = 0u32;

    for pod in &pod_list.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();

        let is_healthy = if pod_ip.is_empty() {
            false
        } else {
            check_node_health(&pod_ip).await.unwrap_or(false)
        };

        if is_healthy {
            healthy += 1;
        } else {
            info!("Deleting unhealthy pod {} for recovery", pod_name);
            match pods.delete(&pod_name, &DeleteParams::default()).await {
                Ok(_) => {
                    info!("Deleted pod {} for recovery", pod_name);
                    recovered += 1;
                }
                Err(e) => {
                    error!("Failed to delete pod {}: {}", pod_name, e);
                }
            }
        }
    }

    info!(
        "Network {} recovery: {} healthy, {} restarted",
        name, healthy, recovered
    );

    // If we triggered restarts, go back to Creating phase to wait for pods
    let phase = if recovered > 0 {
        "Creating".to_string()
    } else if healthy >= spec.validators {
        "Running".to_string()
    } else {
        "Degraded".to_string()
    };

    Ok(LuxNetworkStatus {
        phase,
        ready_validators: healthy,
        total_validators: spec.validators,
        network_id: status.network_id,
        bootstrap_endpoints: status.bootstrap_endpoints,
        ..Default::default()
    })
}

/// Check if a node is bootstrapped via health API
async fn check_node_bootstrapped(pod_ip: &str) -> Result<bool> {
    let url = format!("http://{}:{}/ext/health", pod_ip, LUXD_HTTP_PORT);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| OperatorError::Reconcile(format!("HTTP client error: {}", e)))?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "health.health",
            "params": {}
        }))
        .send()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("Health request failed: {}", e)))?;

    if !resp.status().is_success() {
        return Ok(false);
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("Failed to parse health response: {}", e)))?;

    // Check if the result indicates bootstrapped
    let healthy = body
        .get("result")
        .and_then(|r| r.get("healthy"))
        .and_then(|h| h.as_bool())
        .unwrap_or(false);

    Ok(healthy)
}

/// Check node health via HTTP
async fn check_node_health(pod_ip: &str) -> Result<bool> {
    let url = format!("http://{}:{}/ext/health", pod_ip, LUXD_HTTP_PORT);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| OperatorError::Reconcile(format!("HTTP client error: {}", e)))?;

    let resp = client
        .get(&url)
        .send()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("Health check failed: {}", e)))?;

    Ok(resp.status().is_success())
}

/// Build list of bootstrap endpoints
fn build_bootstrap_endpoints(name: &str, namespace: &str, count: u32) -> Vec<String> {
    (0..count)
        .map(|i| {
            format!(
                "http://{}-{}.{}-headless.{}.svc:{}",
                name, i, name, namespace, LUXD_HTTP_PORT
            )
        })
        .collect()
}

/// Build resource labels for a network
fn resource_labels(name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "luxd".to_string());
    labels.insert("app.kubernetes.io/instance".to_string(), name.to_string());
    labels.insert(
        "app.kubernetes.io/managed-by".to_string(),
        "lux-operator".to_string(),
    );
    labels
}

/// Build owner reference for garbage collection
fn owner_reference(network: &LuxNetwork) -> OwnerReference {
    OwnerReference {
        api_version: LuxNetwork::api_version(&()).to_string(),
        kind: LuxNetwork::kind(&()).to_string(),
        name: network.name_any(),
        uid: network.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Build resource requirements from spec
fn build_resource_requirements(spec: &crate::crd::ResourceSpec) -> ResourceRequirements {
    let mut requests = BTreeMap::new();
    let mut limits = BTreeMap::new();

    if let Some(cpu) = &spec.cpu_request {
        requests.insert("cpu".to_string(), Quantity(cpu.clone()));
    } else {
        requests.insert("cpu".to_string(), Quantity("2".to_string()));
    }

    if let Some(mem) = &spec.memory_request {
        requests.insert("memory".to_string(), Quantity(mem.clone()));
    } else {
        requests.insert("memory".to_string(), Quantity("8Gi".to_string()));
    }

    if let Some(cpu) = &spec.cpu_limit {
        limits.insert("cpu".to_string(), Quantity(cpu.clone()));
    } else {
        limits.insert("cpu".to_string(), Quantity("4".to_string()));
    }

    if let Some(mem) = &spec.memory_limit {
        limits.insert("memory".to_string(), Quantity(mem.clone()));
    } else {
        limits.insert("memory".to_string(), Quantity("16Gi".to_string()));
    }

    ResourceRequirements {
        requests: Some(requests),
        limits: Some(limits),
        ..Default::default()
    }
}

/// Apply a Kubernetes resource (create or update)
async fn apply_resource<T>(api: &Api<T>, name: &str, resource: &T) -> Result<()>
where
    T: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    let params = PatchParams::apply("lux-operator").force();
    let patch = Patch::Apply(resource);
    api.patch(name, &params, &patch)
        .await
        .map_err(OperatorError::KubeApi)?;
    Ok(())
}

/// Error policy for the controller
fn error_policy(network: Arc<LuxNetwork>, error: &OperatorError, _ctx: Arc<Context>) -> Action {
    error!(
        "Error reconciling {}: {:?}",
        network.name_any(),
        error
    );
    Action::requeue(Duration::from_secs(30))
}
