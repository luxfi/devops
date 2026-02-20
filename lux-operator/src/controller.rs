//! Kubernetes controller for LuxNetwork and LuxChain resources

use crate::crd::{
    ChainRef, ChainStatus, LuxChain, LuxChainStatus, LuxExplorer, LuxExplorerStatus, LuxGateway,
    LuxGatewayStatus, LuxIndexer, LuxIndexerStatus, LuxNetwork, LuxNetworkStatus,
};
use crate::error::{OperatorError, Result};
use futures::StreamExt;
use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, StatefulSet, StatefulSetPersistentVolumeClaimRetentionPolicy,
    StatefulSetSpec,
};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule, IngressSpec,
    IngressTLS, ServiceBackendPort,
};
use k8s_openapi::api::core::v1::{
    ConfigMap, Container, ContainerPort, EnvVar, LocalObjectReference,
    PersistentVolumeClaim, PersistentVolumeClaimSpec, Pod, PodSecurityContext, PodSpec,
    PodTemplateSpec, Probe, ResourceRequirements, SecretVolumeSource, Service, ServicePort,
    ServiceSpec as K8sServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::api::rbac::v1::{PolicyRule, Role, RoleBinding, RoleRef, Subject};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::{
    api::{Api, DeleteParams, DynamicObject, ListParams, Patch, PatchParams},
    discovery::ApiResource,
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

const LUXD_METRICS_PORT: i32 = 9090;
const C_CHAIN_VM_ID: &str = "mgj786NP7uDwBCcq6YwThhaN8FLyybkCa4zBWTQbNgmK6k9A6";
const CHAIN_VM_ID: &str = "ag3GReYPNuSR17rUP8acMdZipQBikdXNRKDyFszAysmy3vDXE";

/// Controller context
pub struct Context {
    pub client: Client,
    #[allow(dead_code)]
    pub mpc_endpoint: Option<String>,
}

// ───────────────────────── LuxNetwork Controller ─────────────────────────

/// Run the LuxNetwork controller
pub async fn run_network_controller(
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
        .run(reconcile_network, network_error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled network: {:?}", o),
                Err(e) => error!("Network reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

// ───────────────────────── LuxChain Controller ─────────────────────────

/// Run the LuxChain controller
pub async fn run_chain_controller(client: Client, namespace: String) -> Result<()> {
    let ctx = Arc::new(Context {
        client: client.clone(),
        mpc_endpoint: None,
    });

    let chains: Api<LuxChain> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    info!("Starting LuxChain controller");

    Controller::new(chains, WatcherConfig::default())
        .run(reconcile_chain, chain_error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled chain: {:?}", o),
                Err(e) => error!("Chain reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

// ───────────────────────── LuxIndexer Controller ─────────────────────────

/// Run the LuxIndexer controller
pub async fn run_indexer_controller(client: Client, namespace: String) -> Result<()> {
    let ctx = Arc::new(Context {
        client: client.clone(),
        mpc_endpoint: None,
    });

    let indexers: Api<LuxIndexer> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    info!("Starting LuxIndexer controller");

    Controller::new(indexers, WatcherConfig::default())
        .run(reconcile_indexer, indexer_error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled indexer: {:?}", o),
                Err(e) => error!("Indexer reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

// ───────────────────────── LuxExplorer Controller ─────────────────────────

/// Run the LuxExplorer controller
pub async fn run_explorer_controller(client: Client, namespace: String) -> Result<()> {
    let ctx = Arc::new(Context {
        client: client.clone(),
        mpc_endpoint: None,
    });

    let explorers: Api<LuxExplorer> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    info!("Starting LuxExplorer controller");

    Controller::new(explorers, WatcherConfig::default())
        .run(reconcile_explorer, explorer_error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled explorer: {:?}", o),
                Err(e) => error!("Explorer reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

// ───────────────────────── LuxGateway Controller ─────────────────────────

/// Run the LuxGateway controller
pub async fn run_gateway_controller(client: Client, namespace: String) -> Result<()> {
    let ctx = Arc::new(Context {
        client: client.clone(),
        mpc_endpoint: None,
    });

    let gateways: Api<LuxGateway> = if namespace.is_empty() {
        Api::all(client.clone())
    } else {
        Api::namespaced(client.clone(), &namespace)
    };

    info!("Starting LuxGateway controller");

    Controller::new(gateways, WatcherConfig::default())
        .run(reconcile_gateway, gateway_error_policy, ctx)
        .for_each(|res| async move {
            match res {
                Ok(o) => info!("Reconciled gateway: {:?}", o),
                Err(e) => error!("Gateway reconcile error: {:?}", e),
            }
        })
        .await;

    Ok(())
}

/// Reconcile a LuxChain resource
async fn reconcile_chain(chain: Arc<LuxChain>, ctx: Arc<Context>) -> Result<Action> {
    let name = chain.name_any();
    let namespace = chain.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling LuxChain {}/{}", namespace, name);

    let chains_api: Api<LuxChain> = Api::namespaced(ctx.client.clone(), &namespace);
    let current_status = chain.status.clone().unwrap_or_default();
    let phase = current_status.phase.as_str();

    let new_status = match phase {
        "" | "Pending" => {
            // Check if blockchain_id is set (already deployed)
            if let Some(blockchain_id) = &chain.spec.blockchain_id {
                info!(
                    "Chain {} has blockchain_id {}, updating parent network",
                    name, blockchain_id
                );
                update_parent_network_chains(&chain, &ctx).await?;
                LuxChainStatus {
                    chain_id: chain.spec.chain_id.clone(),
                    blockchain_id: Some(blockchain_id.clone()),
                    phase: "Active".to_string(),
                    ..Default::default()
                }
            } else {
                info!("Chain {} pending deployment (no blockchain_id set yet)", name);
                LuxChainStatus {
                    chain_id: chain.spec.chain_id.clone(),
                    phase: "Pending".to_string(),
                    ..Default::default()
                }
            }
        }
        "Deploying" => {
            // Check if blockchain_id has been set (manually or by external tool)
            if let Some(blockchain_id) = &chain.spec.blockchain_id {
                info!("Chain {} deployed with blockchain_id {}", name, blockchain_id);
                update_parent_network_chains(&chain, &ctx).await?;
                LuxChainStatus {
                    chain_id: chain.spec.chain_id.clone(),
                    blockchain_id: Some(blockchain_id.clone()),
                    phase: "Active".to_string(),
                    ..Default::default()
                }
            } else {
                LuxChainStatus {
                    phase: "Deploying".to_string(),
                    ..current_status.clone()
                }
            }
        }
        "Active" => {
            // Already active, just recheck parent network sync
            current_status.clone()
        }
        _ => current_status.clone(),
    };

    // Update status if changed
    if new_status.phase != current_status.phase
        || new_status.blockchain_id != current_status.blockchain_id
    {
        let patch = Patch::Merge(serde_json::json!({ "status": new_status }));
        chains_api
            .patch_status(&name, &PatchParams::default(), &patch)
            .await
            .map_err(OperatorError::KubeApi)?;
    }

    let requeue_after = match new_status.phase.as_str() {
        "Active" => Duration::from_secs(120),
        "Deploying" => Duration::from_secs(15),
        _ => Duration::from_secs(30),
    };

    Ok(Action::requeue(requeue_after))
}

/// When a chain becomes active, add it to parent LuxNetwork's spec.chains list
/// so the network controller regenerates the startup script with the new chain.
async fn update_parent_network_chains(chain: &LuxChain, ctx: &Context) -> Result<()> {
    let namespace = chain.namespace().unwrap_or_else(|| "default".to_string());
    let network_name = &chain.spec.network_ref;

    let networks: Api<LuxNetwork> = Api::namespaced(ctx.client.clone(), &namespace);
    let network = match networks.get(network_name).await {
        Ok(n) => n,
        Err(kube::Error::Api(err)) if err.code == 404 => {
            warn!(
                "Parent network {} not found for chain {}",
                network_name,
                chain.name_any()
            );
            return Ok(());
        }
        Err(e) => return Err(OperatorError::KubeApi(e)),
    };

    // Check if this chain's blockchain_id is already in the network's chains list
    if let Some(blockchain_id) = &chain.spec.blockchain_id {
        let already_tracked = network
            .spec
            .chains
            .iter()
            .any(|c| c.blockchain_id == *blockchain_id);

        if !already_tracked {
            info!(
                "Adding chain {} (blockchain {}) to network {} spec.chains",
                chain.name_any(),
                blockchain_id,
                network_name
            );

            // Build updated chains list with the new chain appended
            let mut updated_chains: Vec<ChainRef> = network.spec.chains.clone();
            updated_chains.push(ChainRef {
                blockchain_id: blockchain_id.clone(),
                alias: chain
                    .spec
                    .alias
                    .clone()
                    .unwrap_or_else(|| chain.name_any()),
                tracking_id: None, // subnet ID auto-resolved in v1.23.13+
            });

            // Patch spec.chains on the LuxNetwork resource
            let patch = Patch::Merge(serde_json::json!({
                "spec": {
                    "chains": updated_chains
                },
                "metadata": {
                    "annotations": {
                        "lux.network/last-chain-update": chrono::Utc::now().to_rfc3339()
                    }
                }
            }));
            networks
                .patch(network_name, &PatchParams::default(), &patch)
                .await
                .map_err(OperatorError::KubeApi)?;

            info!(
                "Network {} now has {} chains",
                network_name,
                updated_chains.len()
            );
        }
    }

    Ok(())
}

fn chain_error_policy(chain: Arc<LuxChain>, error: &OperatorError, _ctx: Arc<Context>) -> Action {
    error!("Error reconciling chain {}: {:?}", chain.name_any(), error);
    Action::requeue(Duration::from_secs(30))
}

// ───────────────────────── Network Reconciliation ─────────────────────────

/// Reconcile a LuxNetwork resource
async fn reconcile_network(network: Arc<LuxNetwork>, ctx: Arc<Context>) -> Result<Action> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());

    info!("Reconciling LuxNetwork {}/{}", namespace, name);

    let networks: Api<LuxNetwork> = Api::namespaced(ctx.client.clone(), &namespace);

    let current_status = network.status.clone().unwrap_or_default();
    let phase = current_status.phase.as_str();

    let new_status = match phase {
        "" | "Pending" => {
            if network.spec.adopt_existing {
                info!("Network {} adopting existing resources", name);
                adopt_existing(&network, &ctx).await?
            } else {
                info!("Network {} is pending, starting creation", name);
                create_network(&network, &ctx).await?
            }
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

            // Check for scale changes
            if !check_scale_safety(&network, &ctx).await? {
                warn!("Network {} scale-down blocked, skipping reconcile", name);
                let mut s = network.status.clone().unwrap_or_default();
                s.degraded_reasons.push(crate::crd::DegradedCondition {
                    reason: crate::crd::DegradedReason::NodeUnhealthy,
                    message: "Scale-down blocked: set allowValidatorRemoval=true to proceed".to_string(),
                    affected_nodes: vec![],
                });
                s
            } else {
                // Sync StatefulSet replicas if changed
                let statefulsets: Api<StatefulSet> =
                    Api::namespaced(ctx.client.clone(), &namespace);
                if let Ok(sts) = statefulsets.get(&name).await {
                    let current = sts
                        .spec
                        .as_ref()
                        .and_then(|s| s.replicas)
                        .unwrap_or(0) as u32;
                    if current != network.spec.validators {
                        info!(
                            "Network {} scaling: {} -> {} validators",
                            name, current, network.spec.validators
                        );
                        let patch = Patch::Merge(serde_json::json!({
                            "spec": { "replicas": network.spec.validators }
                        }));
                        statefulsets
                            .patch(&name, &PatchParams::default(), &patch)
                            .await
                            .map_err(OperatorError::KubeApi)?;

                        // Also create per-pod LB services for new pods
                        if network.spec.validators > current {
                            create_per_pod_services(&network, &ctx).await?;
                        }
                    }
                }

                let mut health_status = check_health(&network, &ctx).await?;

                // Check if snapshot is due (non-blocking, best-effort)
                if network.spec.snapshot_schedule.enabled && health_status.phase == "Running" {
                    match maybe_take_snapshot(&network, &ctx, &health_status).await {
                        Ok(Some(snap_status)) => {
                            let snap_url = snap_status.url.clone();
                            health_status.last_snapshot_time = Some(snap_status.timestamp);
                            health_status.last_snapshot_url = Some(snap_status.url);
                            health_status.last_snapshot_version = snap_status.version;
                            health_status.snapshot_count = snap_status.count;
                            info!("Network {} snapshot completed: {}", name, snap_url);
                        }
                        Ok(None) => {
                            // Not due yet, preserve existing snapshot status
                            let prev = network.status.clone().unwrap_or_default();
                            health_status.last_snapshot_time = prev.last_snapshot_time;
                            health_status.last_snapshot_url = prev.last_snapshot_url;
                            health_status.last_snapshot_version = prev.last_snapshot_version;
                            health_status.snapshot_count = prev.snapshot_count;
                        }
                        Err(e) => {
                            warn!("Network {} snapshot failed (non-fatal): {}", name, e);
                            let prev = network.status.clone().unwrap_or_default();
                            health_status.last_snapshot_time = prev.last_snapshot_time;
                            health_status.last_snapshot_url = prev.last_snapshot_url;
                            health_status.last_snapshot_version = prev.last_snapshot_version;
                            health_status.snapshot_count = prev.snapshot_count;
                        }
                    }
                } else {
                    // Preserve existing snapshot status
                    let prev = network.status.clone().unwrap_or_default();
                    health_status.last_snapshot_time = prev.last_snapshot_time;
                    health_status.last_snapshot_url = prev.last_snapshot_url;
                    health_status.last_snapshot_version = prev.last_snapshot_version;
                    health_status.snapshot_count = prev.snapshot_count;
                }

                health_status
            }
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
        || new_status.chain_statuses != current_status.chain_statuses
        || new_status.external_ips != current_status.external_ips
        || new_status.last_snapshot_time != current_status.last_snapshot_time
    {
        let patch = Patch::Merge(serde_json::json!({ "status": new_status }));
        networks
            .patch_status(&name, &PatchParams::default(), &patch)
            .await
            .map_err(OperatorError::KubeApi)?;
    }

    let health_interval = network.spec.health_policy.check_interval_seconds;
    let requeue_after = match new_status.phase.as_str() {
        "Running" => Duration::from_secs(health_interval),
        "Creating" | "Bootstrapping" => Duration::from_secs(10),
        "Degraded" => Duration::from_secs(health_interval / 2),
        _ => Duration::from_secs(15),
    };

    Ok(Action::requeue(requeue_after))
}

// ───────────────────────── Adopt Existing ─────────────────────────

/// Adopt existing resources - discover services, set owner refs, check health
async fn adopt_existing(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let http_port = spec.ports.http;

    let statefulsets: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), &namespace);
    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);
    let sts_name = name.clone();

    match statefulsets.get(&sts_name).await {
        Ok(sts) => {
            let sts_status = sts.status.unwrap_or_default();
            let ready = sts_status.ready_replicas.unwrap_or(0) as u32;
            let total = sts_status.replicas as u32;

            info!(
                "Adopted existing StatefulSet {}: {}/{} ready",
                sts_name, ready, total
            );

            // Adopt existing services by setting owner references
            let owner_ref = owner_reference(network);
            adopt_service(&services, &format!("{}-headless", name), &owner_ref).await;
            adopt_service(&services, &format!("{}-rpc", name), &owner_ref).await;
            adopt_service(&services, &name, &owner_ref).await;
            for i in 0..spec.validators {
                adopt_service(&services, &format!("{}-{}", name, i), &owner_ref).await;
            }

            // Discover external IPs from per-pod LB services
            let external_ips = discover_external_ips(&services, &name, spec.validators).await;

            let phase = if ready >= spec.validators {
                "Running".to_string()
            } else if ready > 0 {
                "Bootstrapping".to_string()
            } else {
                "Creating".to_string()
            };

            Ok(LuxNetworkStatus {
                phase,
                ready_validators: ready,
                total_validators: spec.validators,
                network_id: Some(spec.network_id),
                bootstrap_endpoints: build_bootstrap_endpoints(
                    &name, &namespace, spec.validators, http_port,
                ),
                external_ips,
                ..Default::default()
            })
        }
        Err(kube::Error::Api(err)) if err.code == 404 => {
            warn!(
                "adopt_existing: StatefulSet {} not found, falling back to create",
                sts_name
            );
            create_network(network, ctx).await
        }
        Err(e) => Err(OperatorError::KubeApi(e)),
    }
}

/// Try to adopt an existing service by setting owner reference
async fn adopt_service(services: &Api<Service>, name: &str, owner_ref: &OwnerReference) {
    match services.get(name).await {
        Ok(svc) => {
            let has_owner = svc
                .metadata
                .owner_references
                .as_ref()
                .map(|refs| refs.iter().any(|r| r.uid == owner_ref.uid))
                .unwrap_or(false);

            if !has_owner {
                let patch = Patch::Merge(serde_json::json!({
                    "metadata": {
                        "ownerReferences": [owner_ref]
                    }
                }));
                if let Err(e) = services.patch(name, &PatchParams::default(), &patch).await {
                    warn!("Failed to set owner ref on service {}: {}", name, e);
                } else {
                    info!("Adopted service {}", name);
                }
            }
        }
        Err(_) => {
            debug!("Service {} not found, skipping adoption", name);
        }
    }
}

/// Discover external IPs from per-pod LB services
async fn discover_external_ips(
    services: &Api<Service>,
    name: &str,
    validators: u32,
) -> BTreeMap<String, String> {
    let mut ips = BTreeMap::new();
    for i in 0..validators {
        let svc_name = format!("{}-{}", name, i);
        if let Ok(svc) = services.get(&svc_name).await {
            if let Some(status) = svc.status {
                if let Some(lb) = status.load_balancer {
                    if let Some(ingress) = lb.ingress {
                        if let Some(first) = ingress.first() {
                            if let Some(ip) = &first.ip {
                                ips.insert(format!("{}-{}", name, i), ip.clone());
                            }
                        }
                    }
                }
            }
        }
    }
    ips
}

// ───────────────────────── Create Network ─────────────────────────

/// Create a new network: ConfigMaps, Services, PDB, RBAC, StatefulSet
async fn create_network(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let spec = &network.spec;
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let http_port = spec.ports.http;

    info!(
        "Creating network {} with {} validators",
        name, spec.validators
    );

    // Create ConfigMap for luxd config
    create_config_map(network, ctx).await?;

    // Generate startup script ConfigMap (unless user provides their own)
    if network.spec.startup_script.is_none() {
        create_startup_configmap(network, ctx).await?;
    }

    // Create headless Service for pod discovery
    create_headless_service(network, ctx).await?;

    // Create ClusterIP/LoadBalancer Service for RPC access
    create_rpc_service(network, ctx).await?;

    // Create per-pod LoadBalancer services for stable external IPs
    create_per_pod_services(network, ctx).await?;

    // Create KMSSecret for staking keys (if KMS-backed)
    create_kms_secrets(network, ctx).await?;

    // Create RBAC for LB IP discovery from pods
    create_rbac(network, ctx).await?;

    // Create PodDisruptionBudget for volume protection
    create_pdb(network, ctx).await?;

    // Generate gateway config if configured
    if let Some(gw) = &spec.gateway {
        if gw.auto_routes {
            create_gateway_config(network, ctx).await?;
        }
    }

    // Create StatefulSet for validators
    create_statefulset(network, ctx).await?;

    if let Some(mpc) = &spec.mpc {
        if mpc.enabled {
            info!(
                "MPC enabled for network {}, endpoint: {}",
                name, mpc.endpoint
            );
        }
    }

    Ok(LuxNetworkStatus {
        phase: "Creating".to_string(),
        ready_validators: 0,
        total_validators: spec.validators,
        network_id: Some(spec.network_id),
        bootstrap_endpoints: vec![format!(
            "http://{}-0.{}-headless.{}.svc:{}",
            name, name, namespace, http_port
        )],
        ..Default::default()
    })
}

// ───────────────────────── ConfigMap ─────────────────────────

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
    config.insert(
        "network-id".to_string(),
        serde_json::json!(spec.network_id),
    );
    config.insert("http-host".to_string(), serde_json::json!("0.0.0.0"));
    config.insert(
        "http-port".to_string(),
        serde_json::json!(spec.ports.http),
    );
    config.insert(
        "staking-port".to_string(),
        serde_json::json!(spec.ports.staking),
    );
    config.insert("log-level".to_string(), serde_json::json!("info"));
    config.insert(
        "log-display-level".to_string(),
        serde_json::json!("info"),
    );
    config.insert(
        "api-admin-enabled".to_string(),
        serde_json::json!(spec.api.admin_enabled),
    );
    config.insert(
        "api-health-enabled".to_string(),
        serde_json::json!(true),
    );
    config.insert(
        "api-info-enabled".to_string(),
        serde_json::json!(true),
    );

    // Merge user-provided config (overrides defaults)
    for (k, v) in &spec.config {
        config.insert(k.clone(), v.clone());
    }

    let config_json =
        serde_json::to_string_pretty(&config).map_err(OperatorError::Serialization)?;

    let mut data = BTreeMap::new();
    data.insert("config.json".to_string(), config_json);

    // Add genesis if provided inline
    if let Some(genesis) = &spec.genesis {
        let genesis_json =
            serde_json::to_string_pretty(genesis).map_err(OperatorError::Serialization)?;
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

// ───────────────────────── Startup Script ─────────────────────────

/// Generate the startup script ConfigMap programmatically
async fn create_startup_configmap(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());

    let configmaps: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    let script = generate_startup_script(network);

    let mut data = BTreeMap::new();
    data.insert("startup.sh".to_string(), script);

    let cm = ConfigMap {
        metadata: kube::core::ObjectMeta {
            name: Some(format!("{}-startup", name)),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    apply_resource(&configmaps, &format!("{}-startup", name), &cm).await
}

/// Generate the startup shell script from CRD spec
fn generate_startup_script(network: &LuxNetwork) -> String {
    let spec = &network.spec;
    let name = network.name_any();
    let namespace = network
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let http_port = spec.ports.http;
    let staking_port = spec.ports.staking;
    let validators = spec.validators;

    let mut s = String::with_capacity(8192);

    s.push_str("#!/bin/sh\nset -e\n\n");
    s.push_str("POD_INDEX=${HOSTNAME##*-}\n");
    s.push_str(&format!(
        "echo \"=== luxd startup for $HOSTNAME ({}, network-id={}) ===\"\n\n",
        name, spec.network_id
    ));

    // Bootstrap node list (K8s DNS)
    if spec.bootstrap.use_hostnames {
        s.push_str("# Build bootstrap node list excluding self (K8s DNS)\n");
        s.push_str(&format!(
            "DNS_PREFIX=\"{}\"\n",
            name
        ));
        s.push_str(&format!(
            "DNS_SUFFIX=\"{}-headless.{}.svc.cluster.local\"\n",
            name, namespace
        ));
        s.push_str("BOOTSTRAP_NODES=\"\"\n");
        for i in 0..validators {
            s.push_str(&format!(
                "if [ \"$POD_INDEX\" != \"{}\" ]; then\n",
                i
            ));
            s.push_str(&format!(
                "  CUR_HOST=\"${{DNS_PREFIX}}-{}.${{DNS_SUFFIX}}:{}\"\n",
                i, staking_port
            ));
            s.push_str("  if [ -n \"$BOOTSTRAP_NODES\" ]; then\n");
            s.push_str("    BOOTSTRAP_NODES=\"${BOOTSTRAP_NODES},${CUR_HOST}\"\n");
            s.push_str("  else\n");
            s.push_str("    BOOTSTRAP_NODES=\"${CUR_HOST}\"\n");
            s.push_str("  fi\n");
            s.push_str("fi\n");
        }
    } else if !spec.bootstrap.external_ips.is_empty() {
        s.push_str("# Build bootstrap node list from static external IPs\n");
        s.push_str("BOOTSTRAP_NODES=\"\"\n");
        for (i, ip) in spec.bootstrap.external_ips.iter().enumerate() {
            s.push_str(&format!(
                "if [ \"$POD_INDEX\" != \"{}\" ] && [ -n \"{}\" ]; then\n",
                i, ip
            ));
            s.push_str(&format!(
                "  CUR_HOST=\"{}:{}\"\n",
                ip, staking_port
            ));
            s.push_str("  if [ -n \"$BOOTSTRAP_NODES\" ]; then\n");
            s.push_str("    BOOTSTRAP_NODES=\"${BOOTSTRAP_NODES},${CUR_HOST}\"\n");
            s.push_str("  else\n");
            s.push_str("    BOOTSTRAP_NODES=\"${CUR_HOST}\"\n");
            s.push_str("  fi\n");
            s.push_str("fi\n");
        }
    }

    // Public IP discovery
    s.push_str("\n# Discover public IP\nPUBLIC_IP=\"\"\n");
    if !spec.bootstrap.external_ips.is_empty() {
        s.push_str("case \"$POD_INDEX\" in\n");
        for (i, ip) in spec.bootstrap.external_ips.iter().enumerate() {
            s.push_str(&format!("  {}) PUBLIC_IP=\"{}\" ;;\n", i, ip));
        }
        s.push_str("esac\n");
    }

    // LB discovery via K8s API
    s.push_str("\n# If no static IP, discover from per-pod LoadBalancer service\n");
    s.push_str("if [ -z \"$PUBLIC_IP\" ]; then\n");
    s.push_str("  SA_TOKEN_FILE=\"/var/run/secrets/kubernetes.io/serviceaccount/token\"\n");
    s.push_str("  CA_CERT=\"/var/run/secrets/kubernetes.io/serviceaccount/ca.crt\"\n");
    s.push_str("  K8S_API=\"https://kubernetes.default.svc\"\n");
    s.push_str(&format!(
        "  SVC_NAME=\"{}-${{POD_INDEX}}\"\n",
        name
    ));
    s.push_str(&format!("  NAMESPACE=\"{}\"\n\n", namespace));
    s.push_str("  if [ -f \"$SA_TOKEN_FILE\" ]; then\n");
    s.push_str("    TOKEN=$(cat \"$SA_TOKEN_FILE\")\n");
    s.push_str("    echo \"[PUBLIC-IP] Discovering external IP from service ${SVC_NAME}...\"\n");
    s.push_str("    ATTEMPT=0\n");
    s.push_str("    MAX_ATTEMPTS=12\n");
    s.push_str("    while [ \"$ATTEMPT\" -lt \"$MAX_ATTEMPTS\" ]; do\n");
    s.push_str("      SVC_JSON=$(curl -sf -m 5 \\\n");
    s.push_str("        -H \"Authorization: Bearer ${TOKEN}\" \\\n");
    s.push_str("        --cacert \"$CA_CERT\" \\\n");
    s.push_str("        \"${K8S_API}/api/v1/namespaces/${NAMESPACE}/services/${SVC_NAME}\" 2>/dev/null || true)\n\n");
    s.push_str("      if [ -n \"$SVC_JSON\" ]; then\n");
    s.push_str("        LB_IP=$(echo \"$SVC_JSON\" | tr -d ' \\n' | sed -n 's/.*\"loadBalancer\":{\"ingress\":\\[{\"ip\":\"\\([^\"]*\\)\".*/\\1/p')\n");
    s.push_str("        if [ -n \"$LB_IP\" ]; then\n");
    s.push_str("          PUBLIC_IP=\"$LB_IP\"\n");
    s.push_str("          echo \"[PUBLIC-IP] Discovered external IP: $PUBLIC_IP (attempt $((ATTEMPT+1)))\"\n");
    s.push_str("          break\n");
    s.push_str("        fi\n");
    s.push_str("      fi\n\n");
    s.push_str("      ATTEMPT=$((ATTEMPT + 1))\n");
    s.push_str("      if [ \"$ATTEMPT\" -lt \"$MAX_ATTEMPTS\" ]; then\n");
    s.push_str("        echo \"[PUBLIC-IP] LB IP not yet assigned, retrying in 5s... (attempt ${ATTEMPT}/${MAX_ATTEMPTS})\"\n");
    s.push_str("        sleep 5\n");
    s.push_str("      fi\n");
    s.push_str("    done\n");
    s.push_str("  fi\n");
    s.push_str("fi\n\n");

    // Final fallback to pod IP
    s.push_str("if [ -z \"$PUBLIC_IP\" ]; then\n");
    s.push_str("  PUBLIC_IP=$(hostname -i)\n");
    s.push_str("  echo \"[PUBLIC-IP] WARNING: Using pod IP $PUBLIC_IP (no external IP found)\"\n");
    s.push_str("fi\n\n");

    // EVM chain configs for C-chain + other chains
    let all_chain_ids: Vec<&str> = spec
        .chains
        .iter()
        .map(|c| c.blockchain_id.as_str())
        .collect();

    if spec.evm_config.is_some() || !all_chain_ids.is_empty() {
        let evm_cfg = spec.evm_config.as_ref().map_or_else(
            || r#"{"admin-api-enabled":true,"eth-apis":["eth","eth-filter","net","web3","internal-eth","internal-blockchain","internal-transaction","internal-tx-pool","internal-account","internal-personal","debug","internal-debug","admin"],"rpc-gas-cap":50000000,"rpc-tx-fee-cap":100,"pruning-enabled":false,"allow-unfinalized-queries":true,"allow-unprotected-txs":true,"log-level":"info","state-sync-enabled":false,"allow-missing-tries":true}"#.to_string(),
            |v| serde_json::to_string(v).unwrap_or_default(),
        );
        s.push_str("# Write EVM chain configs\n");
        s.push_str(&format!("CHAIN_CFG='{}'\n", evm_cfg));

        // Always include C-chain
        let mut chains = vec!["C".to_string()];
        for id in &all_chain_ids {
            chains.push(id.to_string());
        }
        s.push_str(&format!(
            "for chain in {}; do\n",
            chains.join(" ")
        ));
        s.push_str("  mkdir -p /data/configs/chains/$chain\n");
        s.push_str("  echo \"$CHAIN_CFG\" > /data/configs/chains/$chain/config.json\n");
        s.push_str("done\n");
        s.push_str(&format!(
            "echo \"Chain configs written for {}\"\n\n",
            chains
                .iter()
                .map(|c| if c.len() > 8 { &c[..8] } else { c })
                .collect::<Vec<_>>()
                .join(" + ")
        ));
    }

    s.push_str("echo \"  public-ip: $PUBLIC_IP\"\n");
    s.push_str("echo \"  bootstrap-nodes: $BOOTSTRAP_NODES\"\n\n");

    // Build luxd arguments
    s.push_str("# Build luxd arguments\n");
    s.push_str(&format!(
        "ARGS=\"--network-id={}\"\n",
        spec.network_id
    ));
    s.push_str("ARGS=\"$ARGS --http-host=0.0.0.0\"\n");
    s.push_str(&format!(
        "ARGS=\"$ARGS --http-port={}\"\n",
        http_port
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --http-allowed-hosts={}\"\n",
        spec.api.http_allowed_hosts
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --staking-port={}\"\n",
        staking_port
    ));
    s.push_str("ARGS=\"$ARGS --data-dir=/data\"\n");

    // Genesis file
    if spec.genesis.is_some() || spec.genesis_config_map.is_some() {
        s.push_str("ARGS=\"$ARGS --genesis-file=/genesis/genesis.json\"\n");
    }

    s.push_str(&format!(
        "ARGS=\"$ARGS --db-type={}\"\n",
        spec.db_type
    ));

    // Chain config dir
    if spec.evm_config.is_some() || !spec.chains.is_empty() {
        s.push_str("ARGS=\"$ARGS --chain-config-dir=/data/configs/chains\"\n");
    }

    s.push_str(&format!(
        "ARGS=\"$ARGS --index-enabled={}\"\n",
        spec.api.index_enabled
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --api-admin-enabled={}\"\n",
        spec.api.admin_enabled
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --api-metrics-enabled={}\"\n",
        spec.api.metrics_enabled
    ));
    s.push_str("ARGS=\"$ARGS --api-keystore-enabled=true\"\n");
    s.push_str("ARGS=\"$ARGS --log-level=info\"\n");
    s.push_str("ARGS=\"$ARGS --plugin-dir=/data/plugins\"\n");
    s.push_str("ARGS=\"$ARGS --staking-tls-cert-file=/data/staking/staker.crt\"\n");
    s.push_str("ARGS=\"$ARGS --staking-tls-key-file=/data/staking/staker.key\"\n\n");

    // Signer key (optional)
    s.push_str("if [ -f \"/data/staking/signer.key\" ]; then\n");
    s.push_str("  ARGS=\"$ARGS --staking-signer-key-file=/data/staking/signer.key\"\n");
    s.push_str("fi\n\n");

    // Network compression
    s.push_str(&format!(
        "ARGS=\"$ARGS --network-compression-type={}\"\n",
        spec.network_compression_type
    ));

    // Consensus
    s.push_str(&format!(
        "ARGS=\"$ARGS --consensus-sample-size={}\"\n",
        spec.consensus.sample_size
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --consensus-quorum-size={}\"\n",
        spec.consensus.quorum_size
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --sybil-protection-enabled={}\"\n",
        spec.consensus.sybil_protection_enabled
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --network-require-validator-to-connect={}\"\n",
        spec.consensus.require_validator_to_connect
    ));
    s.push_str(&format!(
        "ARGS=\"$ARGS --network-allow-private-ips={}\"\n\n",
        spec.consensus.allow_private_ips
    ));

    // Chain aliases (inline via --chain-aliases-file-content)
    if let Some(aliases) = &spec.chain_aliases {
        let json = serde_json::to_string(aliases).unwrap_or_default();
        s.push_str("# Chain aliases (base64-encoded)\n");
        s.push_str(&format!(
            "ALIASES_JSON='{}'\n",
            json.replace('\'', "'\"'\"'")
        ));
        s.push_str("ALIASES_B64=$(echo \"$ALIASES_JSON\" | base64 | tr -d '\\n')\n");
        s.push_str("ARGS=\"$ARGS --chain-aliases-file-content=$ALIASES_B64\"\n\n");
    }

    // Built-in chain data import (--import-chain-data flag)
    if let Some(import_path) = &spec.import_chain_data {
        s.push_str(&format!(
            "ARGS=\"$ARGS --import-chain-data={}\"\n",
            import_path
        ));
    }

    s.push('\n');

    // Public IP and bootstrap
    s.push_str("if [ -n \"$PUBLIC_IP\" ]; then\n");
    s.push_str("  ARGS=\"$ARGS --public-ip=$PUBLIC_IP\"\n");
    s.push_str("fi\n\n");
    s.push_str("if [ -n \"$BOOTSTRAP_NODES\" ]; then\n");
    s.push_str("  ARGS=\"$ARGS --bootstrap-nodes=$BOOTSTRAP_NODES\"\n");
    s.push_str("fi\n\n");

    // Chain tracking
    let tracking = &spec.chain_tracking;
    if tracking.track_all_chains {
        s.push_str("ARGS=\"$ARGS --track-all-chains\"\n\n");
    } else if !tracking.tracked_chains.is_empty() {
        s.push_str(&format!(
            "ARGS=\"$ARGS --track-chains={}\"\n\n",
            tracking.tracked_chains.join(",")
        ));
    } else if !spec.chains.is_empty() {
        // Auto-derive tracked chains from chain refs (use tracking_id if available, else blockchain_id)
        let ids: Vec<String> = spec
            .chains
            .iter()
            .map(|cr| {
                cr.tracking_id
                    .clone()
                    .unwrap_or_else(|| cr.blockchain_id.clone())
            })
            .collect();
        s.push_str(&format!(
            "ARGS=\"$ARGS --track-chains={}\"\n\n",
            ids.join(",")
        ));
    }

    // Upgrade config
    if let Some(upgrade) = &spec.upgrade_config {
        let json_str = serde_json::to_string(upgrade).unwrap_or_default();
        // Base64 encode at script level
        s.push_str("# Upgrade config (base64-encoded)\n");
        s.push_str(&format!(
            "UPGRADE_JSON='{}'\n",
            json_str.replace('\'', "'\"'\"'")
        ));
        s.push_str("UPGRADE_B64=$(echo \"$UPGRADE_JSON\" | base64 | tr -d '\\n')\n");
        s.push_str("ARGS=\"$ARGS --upgrade-file-content=$UPGRADE_B64\"\n\n");
    }

    // NOTE: Startup gating is now handled by a dedicated initContainer (startup-gate)
    // in create_statefulset(). The gate runs BEFORE this script, so by the time we get
    // here, peers are already confirmed reachable (or the pod failed and will restart).

    // RLP import: clear C-chain data before starting (to avoid trie corruption)
    if let Some(rlp) = &spec.rlp_import {
        if rlp.enabled {
            if let Some(c_chain_id) = &rlp.c_chain_id {
                s.push_str("# Clear C-chain data to prevent trie corruption on restart\n");
                s.push_str(&format!(
                    "C_CHAIN_DIR=\"/data/chainData/network-{}/{}\"\n",
                    spec.network_id, c_chain_id
                ));
                let marker_name = format!("bootstrap-{}-import", name);
                s.push_str(&format!(
                    "IMPORT_MARKER=\"/data/.{}.done\"\n",
                    marker_name
                ));
                s.push_str("if [ -d \"$C_CHAIN_DIR\" ]; then\n");
                s.push_str("  echo \"[STARTUP] Clearing C-chain data to prevent trie corruption...\"\n");
                s.push_str("  rm -rf \"$C_CHAIN_DIR\"\n");
                s.push_str("  rm -f \"$IMPORT_MARKER\"\n");
                s.push_str("fi\n\n");
            }
        }
    }

    // Start luxd in background
    s.push_str("# Start luxd in background\n");
    s.push_str("/luxd/build/luxd $ARGS &\n");
    s.push_str("LUXD_PID=$!\n\n");

    // Disable set -e for bootstrap section
    s.push_str("set +e\n\n");

    // Wait for health
    s.push_str("# Wait for node health\n");
    s.push_str("echo \"[BOOTSTRAP] Waiting for node health...\"\n");
    s.push_str("i=0\n");
    s.push_str("while [ \"$i\" -lt 180 ]; do\n");
    s.push_str(&format!(
        "  if curl -sf -m 2 http://127.0.0.1:{}/ext/health >/dev/null 2>&1; then\n",
        http_port
    ));
    s.push_str("    echo \"[BOOTSTRAP] Node healthy after ${i}s\"\n");
    s.push_str("    break\n");
    s.push_str("  fi\n");
    s.push_str("  i=$((i + 1))\n");
    s.push_str("  sleep 1\n");
    s.push_str("done\n\n");

    // Chain aliases: map blockchain_id -> human-readable alias via admin.aliasChain
    if !spec.chains.is_empty() {
        s.push_str("# Set up chain aliases\n");
        for chain_ref in &spec.chains {
            s.push_str(&format!(
                "curl -s -m 5 -X POST -H 'Content-Type: application/json' \\\n  --data '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin.aliasChain\",\"params\":{{\"chain\":\"{}\",\"alias\":\"{}\"}}}}' \\\n  http://127.0.0.1:{}/ext/admin >/dev/null 2>&1 || true\n",
                chain_ref.blockchain_id, chain_ref.alias, http_port
            ));
        }
        s.push('\n');
    }

    // RLP import logic (skipped if node was seeded from snapshot)
    if let Some(rlp) = &spec.rlp_import {
        if rlp.enabled {
            let marker_name = format!("bootstrap-{}-import", name);
            let seed_marker = &spec.seed_restore.marker_path;
            s.push_str("# C-Chain RLP import (skipped if seeded from snapshot)\n");
            s.push_str(&format!(
                "MARKER=\"/data/.{}.done\"\n",
                marker_name
            ));
            s.push_str(&format!(
                "SEED_MARKER=\"{}\"\n",
                seed_marker
            ));
            s.push_str("BOOTSTRAP_DIR=\"/data/bootstrap\"\n\n");

            // Skip RLP import if node was seeded (snapshot already has chain data)
            s.push_str("if [ -f \"$SEED_MARKER\" ]; then\n");
            s.push_str("  echo \"[BOOTSTRAP] Node was seeded from snapshot, skipping RLP import\"\n");
            s.push_str("  touch \"$MARKER\"\n");
            s.push_str("el");

            s.push_str("if [ ! -f \"$MARKER\" ]; then\n");
            s.push_str(&format!(
                "  height_hex=$(curl -s -m 10 -X POST -H 'Content-Type: application/json' \\\n    --data '{{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_blockNumber\",\"params\":[]}}' \\\n    http://127.0.0.1:{}/ext/bc/C/rpc | sed -n 's/.*\"result\":\"\\(0x[0-9A-Fa-f]*\\)\".*/\\1/p' | head -n1)\n\n",
                http_port
            ));
            s.push_str("  if [ -z \"$height_hex\" ]; then\n");
            s.push_str("    height_hex=\"0x0\"\n");
            s.push_str("  fi\n\n");
            s.push_str("  height_dec=$(printf '%d' \"$height_hex\" 2>/dev/null || echo 0)\n");
            s.push_str("  echo \"[BOOTSTRAP] C-Chain height: $height_dec (hex: $height_hex)\"\n\n");

            s.push_str(&format!(
                "  if [ \"$height_dec\" -lt \"{}\" ]; then\n",
                rlp.min_height
            ));
            s.push_str(&format!(
                "    echo \"[BOOTSTRAP] C-Chain below target ({}), starting RLP import...\"\n",
                rlp.min_height
            ));
            s.push_str("    mkdir -p \"$BOOTSTRAP_DIR\"\n");
            s.push_str(&format!(
                "    RLP_FILE=\"${{BOOTSTRAP_DIR}}/{}\"\n\n",
                rlp.filename
            ));

            if rlp.multi_part && !rlp.parts.is_empty() {
                s.push_str("    if [ ! -s \"$RLP_FILE\" ]; then\n");
                s.push_str("      echo \"[BOOTSTRAP] Downloading RLP parts...\"\n");
                let base_name = rlp.filename.replace(".rlp", "");
                for part in &rlp.parts {
                    s.push_str(&format!(
                        "      PART_FILE=\"${{BOOTSTRAP_DIR}}/{}.part.{}\"\n",
                        rlp.filename, part
                    ));
                    s.push_str("      if [ ! -s \"$PART_FILE\" ]; then\n");
                    s.push_str(&format!(
                        "        echo \"[BOOTSTRAP] Downloading part {}...\"\n",
                        part
                    ));
                    s.push_str(&format!(
                        "        curl -fL --retry 5 --retry-delay 2 --retry-connrefused -o \"$PART_FILE\" \\\n          \"{}/{}.part.{}\" || true\n",
                        rlp.base_url, base_name, part
                    ));
                    s.push_str("      fi\n");
                }
                s.push_str("      echo \"[BOOTSTRAP] Assembling RLP file...\"\n");
                s.push_str(&format!(
                    "      cat \"${{BOOTSTRAP_DIR}}\"/{}.part.* > \"$RLP_FILE\" 2>/dev/null || true\n",
                    rlp.filename
                ));
                s.push_str("    fi\n");
            } else {
                s.push_str("    if [ ! -s \"$RLP_FILE\" ]; then\n");
                s.push_str("      echo \"[BOOTSTRAP] Downloading RLP...\"\n");
                s.push_str(&format!(
                    "      curl -fL --retry 5 --retry-delay 2 --retry-connrefused -o \"$RLP_FILE\" \\\n        \"{}/{}\" || true\n",
                    rlp.base_url, rlp.filename
                ));
                s.push_str("    fi\n");
            }

            s.push_str("\n    if [ -s \"$RLP_FILE\" ]; then\n");
            s.push_str("      echo \"[BOOTSTRAP] Starting import of $RLP_FILE...\"\n");
            s.push_str("      import_payload=$(printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"admin_importChain\",\"params\":[\"%s\"]}' \"$RLP_FILE\")\n");
            s.push_str(&format!(
                "      import_result=$(curl -s -m {} -X POST -H 'Content-Type: application/json' --data \"$import_payload\" http://127.0.0.1:{}/ext/bc/C/rpc || true)\n",
                rlp.timeout, http_port
            ));
            s.push_str("      echo \"[BOOTSTRAP] Import result: $import_result\"\n");
            s.push_str("      echo \"$import_result\" | grep -q '\"success\":true' && touch \"$MARKER\" && echo \"[BOOTSTRAP] Import complete\" || echo \"[BOOTSTRAP] Import did not return success\"\n");
            s.push_str("    else\n");
            s.push_str("      echo \"[BOOTSTRAP] RLP file missing or empty, skipping\"\n");
            s.push_str("    fi\n");
            s.push_str("  else\n");
            s.push_str("    echo \"[BOOTSTRAP] C-Chain already at height $height_dec, skipping import\"\n");
            s.push_str("    touch \"$MARKER\"\n");
            s.push_str("  fi\n");
            s.push_str("else\n");
            s.push_str("  echo \"[BOOTSTRAP] Import marker exists, skipping bootstrap\"\n");
            s.push_str("fi\n\n");
        }
    }

    // Wait for luxd process
    s.push_str("wait \"$LUXD_PID\"\n");

    s
}

// ───────────────────────── Services ─────────────────────────

/// Create headless Service for StatefulSet pod discovery
async fn create_headless_service(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

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
                    port: spec.ports.http,
                    target_port: Some(IntOrString::Int(spec.ports.http)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("staking".to_string()),
                    port: spec.ports.staking,
                    target_port: Some(IntOrString::Int(spec.ports.staking)),
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

/// Create ClusterIP/LoadBalancer Service for RPC access
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
    annotations.insert(
        "service.beta.kubernetes.io/do-loadbalancer-name".to_string(),
        format!("k8s-{}", name),
    );

    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(name.clone()),
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
                    port: spec.ports.http,
                    target_port: Some(IntOrString::Int(spec.ports.http)),
                    ..Default::default()
                },
                ServicePort {
                    name: Some("staking".to_string()),
                    port: spec.ports.staking,
                    target_port: Some(IntOrString::Int(spec.ports.staking)),
                    ..Default::default()
                },
            ]),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&services, &name, &svc).await
}

/// Create per-pod LoadBalancer services for stable external IPs
async fn create_per_pod_services(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);
    let owner_ref = owner_reference(network);

    // Determine network label for selectors (use name as network identifier)
    let network_label = match spec.network_id {
        1 => "mainnet",
        2 => "testnet",
        3 => "devnet",
        _ => "custom",
    };

    for i in 0..spec.validators {
        let svc_name = format!("{}-{}", name, i);

        let mut labels = resource_labels(&name);
        labels.insert("pod-index".to_string(), i.to_string());

        let mut selector = BTreeMap::new();
        selector.insert(
            "app.kubernetes.io/name".to_string(),
            "luxd".to_string(),
        );
        selector.insert(
            "app.kubernetes.io/instance".to_string(),
            name.clone(),
        );
        selector.insert(
            "statefulset.kubernetes.io/pod-name".to_string(),
            format!("{}-{}", name, i),
        );

        let mut annotations = spec.service.annotations.clone();
        annotations.insert(
            "service.beta.kubernetes.io/do-loadbalancer-name".to_string(),
            format!("k8s-{}-{}-{}", name, network_label, i),
        );

        let svc = Service {
            metadata: kube::core::ObjectMeta {
                name: Some(svc_name.clone()),
                namespace: Some(namespace.clone()),
                labels: Some(labels),
                annotations: Some(annotations),
                owner_references: Some(vec![owner_ref.clone()]),
                ..Default::default()
            },
            spec: Some(K8sServiceSpec {
                type_: Some("LoadBalancer".to_string()),
                selector: Some(selector),
                ports: Some(vec![
                    ServicePort {
                        name: Some("http".to_string()),
                        port: spec.ports.http,
                        target_port: Some(IntOrString::Int(spec.ports.http)),
                        ..Default::default()
                    },
                    ServicePort {
                        name: Some("staking".to_string()),
                        port: spec.ports.staking,
                        target_port: Some(IntOrString::Int(spec.ports.staking)),
                        ..Default::default()
                    },
                ]),
                ..Default::default()
            }),
            ..Default::default()
        };

        apply_resource(&services, &svc_name, &svc).await?;
    }

    info!(
        "Created {} per-pod LoadBalancer services for {}",
        spec.validators, name
    );
    Ok(())
}

// ───────────────────────── KMS Secrets ─────────────────────────

/// Create KMSSecret resources for KMS-backed staking key sync.
/// When staking.kms is configured, creates a KMSSecret that tells the KMS operator
/// to sync staking keys from Hanzo KMS into a K8s Secret.
async fn create_kms_secrets(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let spec = &network.spec;
    let staking = match &spec.staking {
        Some(s) => s,
        None => return Ok(()),
    };
    let kms = match &staking.kms {
        Some(k) => k,
        None => return Ok(()),
    };

    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    let kms_secret_name = format!("{}-staking-kms-sync", name);
    let credentials_ns = kms
        .auth
        .credentials_namespace
        .clone()
        .unwrap_or_else(|| namespace.clone());

    info!(
        "Creating KMSSecret {} for staking keys (project={}, env={}, path={})",
        kms_secret_name, kms.project_slug, kms.env_slug, kms.secrets_path
    );

    // Build KMSSecret as a dynamic object (external CRD from KMS operator)
    let ar = ApiResource {
        group: "secrets.lux.network".to_string(),
        version: "v1alpha1".to_string(),
        api_version: "secrets.lux.network/v1alpha1".to_string(),
        kind: "KMSSecret".to_string(),
        plural: "kmssecrets".to_string(),
    };

    let kms_api: Api<DynamicObject> = Api::namespaced_with(ctx.client.clone(), &namespace, &ar);

    let kms_obj = serde_json::json!({
        "apiVersion": "secrets.lux.network/v1alpha1",
        "kind": "KMSSecret",
        "metadata": {
            "name": kms_secret_name,
            "namespace": namespace,
            "labels": labels,
            "ownerReferences": [owner_ref],
        },
        "spec": {
            "hostAPI": kms.host_api,
            "resyncInterval": kms.resync_interval,
            "authentication": {
                "universalAuth": {
                    "credentialsRef": {
                        "secretName": kms.auth.credentials_secret,
                        "secretNamespace": credentials_ns,
                    },
                    "secretsScope": {
                        "projectSlug": kms.project_slug,
                        "envSlug": kms.env_slug,
                        "secretsPath": kms.secrets_path,
                    }
                }
            },
            "managedKubeSecretReferences": [{
                "creationPolicy": "Owner",
                "secretName": staking.secret_name,
                "secretNamespace": namespace,
                "secretType": "Opaque",
            }]
        }
    });

    let params = PatchParams::apply("lux-operator").force();
    let patch = Patch::Apply(&kms_obj);
    kms_api
        .patch(&kms_secret_name, &params, &patch)
        .await
        .map_err(OperatorError::KubeApi)?;

    info!(
        "KMSSecret {} created/updated -> syncs to Secret {} in {}",
        kms_secret_name, staking.secret_name, namespace
    );

    Ok(())
}

// ───────────────────────── RBAC ─────────────────────────

/// Create RBAC for pods to discover their LB service IPs
async fn create_rbac(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let owner_ref = owner_reference(network);

    let role_name = format!("{}-service-reader", name);

    // Create Role
    let roles: Api<Role> = Api::namespaced(ctx.client.clone(), &namespace);
    let role = Role {
        metadata: kube::core::ObjectMeta {
            name: Some(role_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        rules: Some(vec![PolicyRule {
            api_groups: Some(vec!["".to_string()]),
            resources: Some(vec!["services".to_string()]),
            verbs: vec!["get".to_string()],
            ..Default::default()
        }]),
    };

    apply_resource(&roles, &role_name, &role).await?;

    // Create RoleBinding
    let role_bindings: Api<RoleBinding> = Api::namespaced(ctx.client.clone(), &namespace);
    let binding = RoleBinding {
        metadata: kube::core::ObjectMeta {
            name: Some(role_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        role_ref: RoleRef {
            api_group: "rbac.authorization.k8s.io".to_string(),
            kind: "Role".to_string(),
            name: role_name.clone(),
        },
        subjects: Some(vec![Subject {
            kind: "ServiceAccount".to_string(),
            name: "default".to_string(),
            namespace: Some(namespace.clone()),
            ..Default::default()
        }]),
    };

    apply_resource(&role_bindings, &role_name, &binding).await
}

// ───────────────────────── PDB ─────────────────────────

/// Create PodDisruptionBudget to protect validators
async fn create_pdb(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let owner_ref = owner_reference(network);
    let labels = resource_labels(&name);

    let pdbs: Api<PodDisruptionBudget> = Api::namespaced(ctx.client.clone(), &namespace);

    let pdb_name = format!("{}-pdb", name);
    let pdb = PodDisruptionBudget {
        metadata: kube::core::ObjectMeta {
            name: Some(pdb_name.clone()),
            namespace: Some(namespace.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(PodDisruptionBudgetSpec {
            max_unavailable: Some(IntOrString::Int(1)),
            selector: Some(LabelSelector {
                match_labels: Some(labels),
                ..Default::default()
            }),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&pdbs, &pdb_name, &pdb).await
}

// ───────────────────────── Gateway Config ─────────────────────────

/// Generate KrakenD gateway configuration ConfigMap
async fn create_gateway_config(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let gw = match &spec.gateway {
        Some(gw) => gw,
        None => return Ok(()),
    };

    let configmaps: Api<ConfigMap> = Api::namespaced(ctx.client.clone(), &namespace);
    let owner_ref = owner_reference(network);
    let labels = resource_labels(&name);

    let http_port = spec.ports.http;
    let backend = format!("http://{}-headless.{}.svc:{}", name, namespace, http_port);

    // Build KrakenD-compatible route config
    let mut endpoints = Vec::new();

    // Primary chains: P, X, C
    for chain in &["P", "X", "C"] {
        let path = format!("/ext/bc/{}", chain);
        endpoints.push(serde_json::json!({
            "endpoint": path,
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": &path,
                "host": [&backend],
                "encoding": "no-op"
            }]
        }));
        // RPC subpath for C-chain
        if *chain == "C" {
            let rpc_path = "/ext/bc/C/rpc";
            endpoints.push(serde_json::json!({
                "endpoint": rpc_path,
                "method": "POST",
                "output_encoding": "no-op",
                "backend": [{
                    "url_pattern": rpc_path,
                    "host": [&backend],
                    "encoding": "no-op"
                }]
            }));
            let ws_path = "/ext/bc/C/ws";
            endpoints.push(serde_json::json!({
                "endpoint": ws_path,
                "method": "GET",
                "output_encoding": "no-op",
                "backend": [{
                    "url_pattern": ws_path,
                    "host": [&backend],
                    "encoding": "no-op"
                }]
            }));
        }
    }

    // Additional chains
    for chain_ref in &spec.chains {
        let path = format!("/ext/bc/{}/rpc", chain_ref.alias);
        let backend_path = format!("/ext/bc/{}/rpc", chain_ref.blockchain_id);
        endpoints.push(serde_json::json!({
            "endpoint": &path,
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": &backend_path,
                "host": [&backend],
                "encoding": "no-op"
            }]
        }));
    }

    // Health endpoint
    endpoints.push(serde_json::json!({
        "endpoint": "/ext/health",
        "method": "GET",
        "output_encoding": "no-op",
        "backend": [{
            "url_pattern": "/ext/health",
            "host": [&backend],
            "encoding": "no-op"
        }]
    }));

    let krakend_config = serde_json::json!({
        "version": 3,
        "name": format!("{} Gateway", name),
        "port": 8080,
        "timeout": "30s",
        "endpoints": endpoints
    });

    let config_json =
        serde_json::to_string_pretty(&krakend_config).map_err(OperatorError::Serialization)?;

    let mut data = BTreeMap::new();
    data.insert("krakend.json".to_string(), config_json);

    let cm = ConfigMap {
        metadata: kube::core::ObjectMeta {
            name: Some(gw.config_map.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        data: Some(data),
        ..Default::default()
    };

    apply_resource(&configmaps, &gw.config_map, &cm).await
}

// ───────────────────────── Startup Gate InitContainer ─────────────────────────

/// Build the startup-gate init container script.
/// Runs as an initContainer: pod stays in Init state until peers are reachable.
/// On timeout with on_timeout=Fail, exits 1 → CrashLoopBackOff → retries.
fn build_startup_gate_script(network: &LuxNetwork) -> String {
    let spec = &network.spec;
    let gate = &spec.startup_gate;
    let name = network.name_any();
    let namespace = network
        .namespace()
        .unwrap_or_else(|| "default".to_string());
    let staking_port = spec.ports.staking;
    let http_port = spec.ports.http;
    let validators = spec.validators;
    let min_peers = gate.min_peers.min(validators - 1);

    let mut s = String::with_capacity(2048);
    s.push_str("#!/bin/sh\nset -e\n\n");
    s.push_str("POD_INDEX=${HOSTNAME##*-}\n");
    s.push_str(&format!(
        "echo \"[GATE] Startup gate for $HOSTNAME ({}, network-id={})\"\n",
        name, spec.network_id
    ));
    s.push_str(&format!(
        "DNS_PREFIX=\"{}\"\n",
        name
    ));
    s.push_str(&format!(
        "DNS_SUFFIX=\"{}-headless.{}.svc.cluster.local\"\n",
        name, namespace
    ));
    s.push_str(&format!("GATE_MIN_PEERS={}\n", min_peers));
    s.push_str(&format!("GATE_TIMEOUT={}\n", gate.timeout_seconds));
    s.push_str(&format!("GATE_INTERVAL={}\n", gate.check_interval_seconds));
    s.push_str("GATE_START=$(date +%s)\n");
    s.push_str("echo \"[GATE] Waiting for $GATE_MIN_PEERS peers (timeout ${GATE_TIMEOUT}s)...\"\n\n");

    s.push_str("while true; do\n");
    s.push_str("  REACHABLE=0\n");

    if spec.bootstrap.use_hostnames {
        for i in 0..validators {
            s.push_str(&format!(
                "  if [ \"$POD_INDEX\" != \"{}\" ]; then\n",
                i
            ));
            s.push_str(&format!(
                "    if nc -z -w 2 \"${{DNS_PREFIX}}-{}.${{DNS_SUFFIX}}\" {} 2>/dev/null; then\n",
                i, staking_port
            ));
            s.push_str("      REACHABLE=$((REACHABLE + 1))\n");
            s.push_str("    fi\n");
            s.push_str("  fi\n");
        }
    }

    s.push_str("\n  if [ \"$REACHABLE\" -ge \"$GATE_MIN_PEERS\" ]; then\n");
    s.push_str("    echo \"[GATE] $REACHABLE peers reachable, proceeding with startup\"\n");
    s.push_str("    break\n");
    s.push_str("  fi\n\n");

    s.push_str("  ELAPSED=$(( $(date +%s) - GATE_START ))\n");
    s.push_str("  if [ \"$ELAPSED\" -ge \"$GATE_TIMEOUT\" ]; then\n");
    if gate.on_timeout == "StartAnyway" {
        s.push_str("    echo \"[GATE] WARNING: Timeout after ${ELAPSED}s with only $REACHABLE peers. Proceeding (onTimeout=StartAnyway).\"\n");
        s.push_str("    break\n");
    } else {
        s.push_str("    echo \"[GATE] FATAL: Timeout after ${ELAPSED}s with only $REACHABLE/$GATE_MIN_PEERS peers. Exiting (onTimeout=Fail).\"\n");
        s.push_str("    exit 1\n");
    }
    s.push_str("  fi\n\n");

    s.push_str("  echo \"[GATE] $REACHABLE/$GATE_MIN_PEERS peers reachable (${ELAPSED}/${GATE_TIMEOUT}s), waiting ${GATE_INTERVAL}s...\"\n");
    s.push_str("  sleep \"$GATE_INTERVAL\"\n");
    s.push_str("done\n\n");

    // Optional: wait for at least one peer to be healthy
    if gate.wait_for_healthy_peer {
        s.push_str("# Wait for at least one peer to be healthy\n");
        s.push_str("echo \"[GATE] Waiting for a healthy peer...\"\n");
        s.push_str("HEALTHY_PEER=0\n");
        s.push_str("GATE_START=$(date +%s)\n");
        s.push_str("while [ \"$HEALTHY_PEER\" -eq 0 ]; do\n");
        for i in 0..validators {
            s.push_str(&format!(
                "  if [ \"$POD_INDEX\" != \"{}\" ]; then\n",
                i
            ));
            s.push_str(&format!(
                "    if curl -sf -m 2 http://${{DNS_PREFIX}}-{}.${{DNS_SUFFIX}}:{}/ext/health >/dev/null 2>&1; then\n",
                i, http_port
            ));
            s.push_str(&format!(
                "      echo \"[GATE] Peer {}-{} is healthy\"\n",
                name, i
            ));
            s.push_str("      HEALTHY_PEER=1\n");
            s.push_str("      break\n");
            s.push_str("    fi\n");
            s.push_str("  fi\n");
        }
        s.push_str("  ELAPSED=$(( $(date +%s) - GATE_START ))\n");
        s.push_str("  if [ \"$ELAPSED\" -ge \"$GATE_TIMEOUT\" ]; then\n");
        if gate.on_timeout == "StartAnyway" {
            s.push_str("    echo \"[GATE] WARNING: No healthy peer after ${ELAPSED}s. Proceeding (onTimeout=StartAnyway).\"\n");
            s.push_str("    break\n");
        } else {
            s.push_str("    echo \"[GATE] FATAL: No healthy peer after ${ELAPSED}s. Exiting (onTimeout=Fail).\"\n");
            s.push_str("    exit 1\n");
        }
        s.push_str("  fi\n");
        s.push_str("  sleep \"$GATE_INTERVAL\"\n");
        s.push_str("done\n\n");
    }

    s.push_str("echo \"[GATE] Gate passed, luxd may start.\"\n");
    s
}

// ───────────────────────── StatefulSet ─────────────────────────

/// Create StatefulSet for validator pods
async fn create_statefulset(network: &LuxNetwork, ctx: &Context) -> Result<()> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let statefulsets: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), &namespace);

    let labels = resource_labels(&name);
    let owner_ref = owner_reference(network);

    let resources = build_resource_requirements(&spec.resources);

    // Build volume mounts for main container
    let mut volume_mounts = vec![
        VolumeMount {
            name: "data".to_string(),
            mount_path: "/data".to_string(),
            ..Default::default()
        },
        VolumeMount {
            name: "startup-script".to_string(),
            mount_path: "/scripts".to_string(),
            ..Default::default()
        },
    ];

    // Build volumes
    let startup_cm_name = spec
        .startup_script
        .clone()
        .unwrap_or_else(|| format!("{}-startup", name));

    let mut volumes = vec![
        Volume {
            name: "config".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: Some(format!("{}-config", name)),
                ..Default::default()
            }),
            ..Default::default()
        },
        Volume {
            name: "startup-script".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: Some(startup_cm_name),
                default_mode: Some(0o755),
                ..Default::default()
            }),
            ..Default::default()
        },
    ];

    // Genesis volume
    if spec.genesis.is_some() {
        volume_mounts.push(VolumeMount {
            name: "genesis".to_string(),
            mount_path: "/genesis".to_string(),
            read_only: Some(true),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "genesis".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: Some(format!("{}-config", name)),
                ..Default::default()
            }),
            ..Default::default()
        });
    } else if let Some(genesis_cm) = &spec.genesis_config_map {
        volume_mounts.push(VolumeMount {
            name: "genesis".to_string(),
            mount_path: "/genesis".to_string(),
            read_only: Some(true),
            ..Default::default()
        });
        volumes.push(Volume {
            name: "genesis".to_string(),
            config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                name: Some(genesis_cm.clone()),
                ..Default::default()
            }),
            ..Default::default()
        });
    }

    // Staking keys volume
    if let Some(staking) = &spec.staking {
        volumes.push(Volume {
            name: "staking-keys".to_string(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(staking.secret_name.clone()),
                ..Default::default()
            }),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name: "staking-keys".to_string(),
            mount_path: "/staking-keys".to_string(),
            read_only: Some(true),
            ..Default::default()
        });
    }

    // Container uses startup script
    let container = Container {
        name: "luxd".to_string(),
        image: Some(format!("{}:{}", spec.image.repository, spec.image.tag)),
        image_pull_policy: Some(spec.image.pull_policy.clone()),
        command: Some(vec!["/bin/sh".to_string(), "/scripts/startup.sh".to_string()]),
        ports: Some(vec![
            ContainerPort {
                name: Some("http".to_string()),
                container_port: spec.ports.http,
                ..Default::default()
            },
            ContainerPort {
                name: Some("staking".to_string()),
                container_port: spec.ports.staking,
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
        volume_mounts: Some(volume_mounts),
        resources: Some(resources),
        // startupProbe: TCP check with 5-min budget for slow bootstrap
        startup_probe: Some(Probe {
            tcp_socket: Some(k8s_openapi::api::core::v1::TCPSocketAction {
                port: IntOrString::Int(spec.ports.http),
                ..Default::default()
            }),
            initial_delay_seconds: Some(5),
            period_seconds: Some(10),
            failure_threshold: Some(30), // 30 * 10s = 5 minutes
            ..Default::default()
        }),
        // livenessProbe: HTTP /ext/health (only runs after startupProbe succeeds)
        liveness_probe: Some(Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/ext/health".to_string()),
                port: IntOrString::Int(spec.ports.http),
                ..Default::default()
            }),
            period_seconds: Some(15),
            failure_threshold: Some(3),
            timeout_seconds: Some(5),
            ..Default::default()
        }),
        // readinessProbe: HTTP /ext/health
        readiness_probe: Some(Probe {
            http_get: Some(k8s_openapi::api::core::v1::HTTPGetAction {
                path: Some("/ext/health".to_string()),
                port: IntOrString::Int(spec.ports.http),
                ..Default::default()
            }),
            period_seconds: Some(10),
            failure_threshold: Some(3),
            timeout_seconds: Some(5),
            ..Default::default()
        }),
        ..Default::default()
    };

    // Build init containers
    let mut init_containers = Vec::new();

    // Startup gate initContainer: waits for peers before luxd starts.
    // Runs first, so pod stays in Init until peers are TCP-reachable.
    let gate = &spec.startup_gate;
    if gate.enabled && spec.validators > 1 {
        let gate_script = build_startup_gate_script(network);
        init_containers.push(Container {
            name: "startup-gate".to_string(),
            image: Some(format!("{}:{}", spec.image.repository, spec.image.tag)),
            image_pull_policy: Some(spec.image.pull_policy.clone()),
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            args: Some(vec![gate_script]),
            ..Default::default()
        });
    }

    if let Some(init) = &spec.init {
        let mut init_script = String::from(
            "set -e\nIDX=${HOSTNAME##*-}\necho \"=== Init for ${HOSTNAME} ===\"\n",
        );

        // Optional data clearing for re-genesis
        if init.clear_data {
            init_script.push_str("echo \"=== Clearing data for re-genesis ===\"\n");
            init_script.push_str("rm -rf /data/chainData /data/db /data/genesis.bytes /data/.bootstrap-*-import.done /data/.seeded\n");
            init_script.push_str("echo \"Data cleared\"\n");
        }

        // Seed/snapshot restore (idempotent via marker file)
        let seed = &spec.seed_restore;
        if seed.enabled {
            let marker = &seed.marker_path;
            init_script.push_str("\n# ─── Seed Restore ───\n");
            init_script.push_str(&format!("SEED_MARKER=\"{}\"\n", marker));

            let check_condition = if seed.restore_policy == "Always" {
                "true".to_string()
            } else {
                format!("! -f \"{}\"", marker)
            };

            init_script.push_str(&format!("if [ {} ]; then\n", check_condition));
            init_script.push_str("  echo \"[SEED] Starting seed restore...\"\n");

            match seed.source_type.as_str() {
                "ObjectStore" => {
                    if let Some(url) = &seed.object_store_url {
                        init_script.push_str(&format!(
                            "  echo \"[SEED] Downloading snapshot from {}...\"\n",
                            url
                        ));
                        init_script.push_str(&format!(
                            "  curl -fL --retry 5 --retry-delay 5 -o /tmp/snapshot.tar.zst \"{}\" && \\\n",
                            url
                        ));
                        init_script.push_str(
                            "  echo \"[SEED] Extracting snapshot...\" && \\\n",
                        );
                        // Try zstd first, fall back to gzip
                        init_script.push_str(
                            "  (zstd -d /tmp/snapshot.tar.zst -o /tmp/snapshot.tar 2>/dev/null || cp /tmp/snapshot.tar.zst /tmp/snapshot.tar) && \\\n",
                        );
                        init_script.push_str(
                            "  tar xf /tmp/snapshot.tar -C /data && \\\n",
                        );
                        init_script.push_str(
                            "  rm -f /tmp/snapshot.tar /tmp/snapshot.tar.zst && \\\n",
                        );
                        init_script.push_str(&format!(
                            "  touch \"{}\" && \\\n",
                            marker
                        ));
                        init_script.push_str(
                            "  echo \"[SEED] Restore complete\" || echo \"[SEED] Restore failed\"\n",
                        );
                    }
                }
                "PVCClone" | "VolumeSnapshot" => {
                    // For PVC clone / VolumeSnapshot, the PVC itself is created from the source.
                    // The init container just needs to mark it as seeded.
                    init_script.push_str("  # PVC was created from snapshot/clone by the operator\n");
                    init_script.push_str("  if [ -d \"/data/db\" ] || [ -d \"/data/chainData\" ]; then\n");
                    init_script.push_str("    echo \"[SEED] Data found from PVC clone/snapshot\"\n");
                    init_script.push_str(&format!(
                        "    touch \"{}\"\n",
                        marker
                    ));
                    init_script.push_str("  else\n");
                    init_script.push_str("    echo \"[SEED] WARNING: PVC clone/snapshot has no data\"\n");
                    init_script.push_str("  fi\n");
                }
                _ => {
                    init_script.push_str("  echo \"[SEED] No seed source configured, skipping\"\n");
                }
            }

            init_script.push_str("else\n");
            init_script.push_str(&format!(
                "  echo \"[SEED] Marker {} exists, skipping restore\"\n",
                marker
            ));
            init_script.push_str("fi\n\n");
        }

        // Plugin setup
        if !init.plugins.is_empty() {
            init_script.push_str("echo \"=== Setting up plugins ===\"\n");
            init_script.push_str("mkdir -p /data/plugins\n");
            for plugin in &init.plugins {
                init_script.push_str(&format!(
                    "cp {} /data/plugins/{}\n",
                    plugin.source, plugin.dest
                ));
            }
        } else {
            // Default: copy C-chain and chain EVM plugins
            init_script.push_str("echo \"=== Setting up plugins ===\"\n");
            init_script.push_str("mkdir -p /data/plugins\n");
            init_script.push_str(&format!(
                "cp /luxd/build/plugins/{} /data/plugins/\n",
                C_CHAIN_VM_ID
            ));
            init_script.push_str(&format!(
                "cp /luxd/build/plugins/{} /data/plugins/{}\n",
                C_CHAIN_VM_ID, CHAIN_VM_ID
            ));
        }

        // Staking key setup
        if spec.staking.is_some() {
            init_script.push_str("echo \"=== Setting up staking keys ===\"\n");
            init_script.push_str("mkdir -p /data/staking\n");
            init_script.push_str(
                "cp /staking-keys/staker-${IDX}.crt /data/staking/staker.crt\n",
            );
            init_script.push_str(
                "cp /staking-keys/staker-${IDX}.key /data/staking/staker.key\n",
            );
            init_script
                .push_str("if [ -f \"/staking-keys/signer-${IDX}.key\" ]; then\n");
            init_script.push_str(
                "  cp /staking-keys/signer-${IDX}.key /data/staking/signer.key\n",
            );
            init_script.push_str("fi\n");
            init_script.push_str(&format!(
                "chown -R {}:{} /data/staking\n",
                spec.security.run_as_user, spec.security.run_as_group
            ));
            init_script.push_str("chmod 600 /data/staking/*\n");
        }

        init_script.push_str("echo \"=== Init complete ===\"\n");

        let mut init_volume_mounts = vec![VolumeMount {
            name: "data".to_string(),
            mount_path: "/data".to_string(),
            ..Default::default()
        }];

        if spec.staking.is_some() {
            init_volume_mounts.push(VolumeMount {
                name: "staking-keys".to_string(),
                mount_path: "/staking-keys".to_string(),
                read_only: Some(true),
                ..Default::default()
            });
        }

        init_containers.push(Container {
            name: "init-plugins".to_string(),
            image: Some(init.image.clone()),
            image_pull_policy: Some(init.pull_policy.clone()),
            security_context: Some(k8s_openapi::api::core::v1::SecurityContext {
                run_as_user: Some(0),
                run_as_group: Some(0),
                ..Default::default()
            }),
            command: Some(vec!["/bin/sh".to_string(), "-c".to_string()]),
            args: Some(vec![init_script]),
            volume_mounts: Some(init_volume_mounts),
            ..Default::default()
        });
    }

    // PVC template
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

    // Image pull secrets
    let pull_secrets: Option<Vec<LocalObjectReference>> = if spec.image.pull_secrets.is_empty() {
        None
    } else {
        Some(
            spec.image
                .pull_secrets
                .iter()
                .map(|s| LocalObjectReference {
                    name: Some(s.clone()),
                })
                .collect(),
        )
    };

    let sts = StatefulSet {
        metadata: kube::core::ObjectMeta {
            name: Some(name.clone()),
            namespace: Some(namespace.clone()),
            labels: Some(labels.clone()),
            annotations: Some({
                let mut ann = BTreeMap::new();
                ann.insert(
                    "lux.network/protect-pvc".to_string(),
                    "true".to_string(),
                );
                ann
            }),
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
                    security_context: Some(PodSecurityContext {
                        fs_group: Some(spec.security.fs_group),
                        run_as_user: Some(spec.security.run_as_user),
                        run_as_group: Some(spec.security.run_as_group),
                        ..Default::default()
                    }),
                    init_containers: if init_containers.is_empty() {
                        None
                    } else {
                        Some(init_containers)
                    },
                    containers: vec![container],
                    volumes: Some(volumes),
                    image_pull_secrets: pull_secrets,
                    termination_grace_period_seconds: Some(30),
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![pvc_template]),
            pod_management_policy: Some("Parallel".to_string()),
            update_strategy: Some(k8s_openapi::api::apps::v1::StatefulSetUpdateStrategy {
                type_: Some("OnDelete".to_string()),
                ..Default::default()
            }),
            persistent_volume_claim_retention_policy: Some(
                StatefulSetPersistentVolumeClaimRetentionPolicy {
                    when_deleted: Some("Retain".to_string()),
                    when_scaled: Some("Retain".to_string()),
                },
            ),
            ..Default::default()
        }),
        ..Default::default()
    };

    apply_resource(&statefulsets, &name, &sts).await
}

// ───────────────────────── Progress / Health Checks ─────────────────────────

/// Check creation progress by querying StatefulSet status
async fn check_creation_progress(
    network: &LuxNetwork,
    ctx: &Context,
) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();
    let http_port = spec.ports.http;

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
            bootstrap_endpoints: build_bootstrap_endpoints(&name, &namespace, desired, http_port),
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
    let http_port = spec.ports.http;

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = pod_label_selector(&name, spec.adopt_existing);
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

        match check_node_bootstrapped(&pod_ip, http_port).await {
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
            bootstrap_endpoints: build_bootstrap_endpoints(
                &name,
                &namespace,
                spec.validators,
                http_port,
            ),
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

/// Check node health with enhanced per-node status and degraded conditions
async fn check_health(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    use crate::crd::{DegradedCondition, DegradedReason, NetworkMetrics, NodeStatus};

    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();
    let http_port = spec.ports.http;
    let health_policy = &spec.health_policy;

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = pod_label_selector(&name, spec.adopt_existing);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let mut healthy_count = 0u32;
    let mut chain_statuses = BTreeMap::new();
    let mut node_statuses = BTreeMap::new();
    let mut degraded_reasons: Vec<DegradedCondition> = Vec::new();
    let mut p_heights: Vec<u64> = Vec::new();

    for pod in &pod_list.items {
        let pod_name = pod.metadata.name.clone().unwrap_or_default();
        let pod_ip = pod
            .status
            .as_ref()
            .and_then(|s| s.pod_ip.clone())
            .unwrap_or_default();

        let pod_start_time = pod
            .status
            .as_ref()
            .and_then(|s| s.start_time.as_ref())
            .map(|t| t.0.to_rfc3339());

        if pod_ip.is_empty() {
            node_statuses.insert(
                pod_name.clone(),
                NodeStatus {
                    healthy: false,
                    ..Default::default()
                },
            );
            degraded_reasons.push(DegradedCondition {
                reason: DegradedReason::PodNotReady,
                message: format!("Pod {} has no IP", pod_name),
                affected_nodes: vec![pod_name],
            });
            continue;
        }

        let is_healthy = check_node_health(&pod_ip, http_port)
            .await
            .unwrap_or(false);
        let is_bootstrapped = check_node_bootstrapped(&pod_ip, http_port)
            .await
            .unwrap_or(false);
        let p_height = get_pchain_height(&pod_ip, http_port)
            .await
            .unwrap_or(None);
        let c_height = get_evm_block_height(&pod_ip, http_port, "C")
            .await
            .unwrap_or(None);
        let (node_id, connected, inbound, outbound) =
            get_node_peer_info(&pod_ip, http_port).await;

        // Count tracked chains responding
        let mut chains_responding = 0u32;
        if c_height.is_some() {
            chains_responding += 1;
        }
        for chain_ref in &spec.chains {
            if get_evm_block_height(&pod_ip, http_port, &chain_ref.blockchain_id)
                .await
                .unwrap_or(None)
                .is_some()
            {
                chains_responding += 1;
            }
        }

        if is_healthy {
            healthy_count += 1;
        }

        if let Some(h) = p_height {
            p_heights.push(h);
        }

        let node_status = NodeStatus {
            node_id,
            external_ip: None, // filled from LB services below
            p_chain_height: p_height,
            c_chain_height: c_height,
            chains_count: chains_responding,
            connected_peers: connected,
            inbound_peers: inbound,
            outbound_peers: outbound,
            bootstrapped: is_bootstrapped,
            healthy: is_healthy,
            start_time: pod_start_time.clone(),
        };

        // Check inbound peer policy
        if is_healthy && health_policy.require_inbound_validators && inbound < health_policy.min_inbound {
            // Check grace period
            let in_grace = if let Some(ref start) = pod_start_time {
                if let Ok(start_dt) = chrono::DateTime::parse_from_rfc3339(start) {
                    let elapsed = chrono::Utc::now()
                        .signed_duration_since(start_dt)
                        .num_seconds() as u64;
                    elapsed < health_policy.grace_period_seconds
                } else {
                    false
                }
            } else {
                false
            };

            if !in_grace {
                degraded_reasons.push(DegradedCondition {
                    reason: DegradedReason::InboundPeersTooLow,
                    message: format!(
                        "Pod {} has {} inbound peers (min: {}), grace expired",
                        pod_name, inbound, health_policy.min_inbound
                    ),
                    affected_nodes: vec![pod_name.clone()],
                });
            }
        }

        if !is_healthy {
            degraded_reasons.push(DegradedCondition {
                reason: DegradedReason::NodeUnhealthy,
                message: format!("Pod {} failed health check", pod_name),
                affected_nodes: vec![pod_name.clone()],
            });
        }

        node_statuses.insert(pod_name, node_status);
    }

    // Check height skew
    let (min_h, max_h) = if !p_heights.is_empty() {
        let min = *p_heights.iter().min().unwrap_or(&0);
        let max = *p_heights.iter().max().unwrap_or(&0);
        (min, max)
    } else {
        (0, 0)
    };
    let skew = max_h.saturating_sub(min_h);

    if skew > health_policy.max_height_skew && p_heights.len() > 1 {
        let lagging: Vec<String> = node_statuses
            .iter()
            .filter(|(_, ns)| {
                ns.p_chain_height
                    .map(|h| max_h.saturating_sub(h) > health_policy.max_height_skew)
                    .unwrap_or(false)
            })
            .map(|(name, _)| name.clone())
            .collect();

        degraded_reasons.push(DegradedCondition {
            reason: DegradedReason::HeightSkew,
            message: format!(
                "P-chain height skew: {} (min={}, max={})",
                skew, min_h, max_h
            ),
            affected_nodes: lagging,
        });
    }

    // Build aggregated chain statuses from first healthy node
    let first_healthy_ip = node_statuses
        .values()
        .find(|ns| ns.healthy)
        .and_then(|_| {
            pod_list.items.iter().find_map(|pod| {
                let ip = pod.status.as_ref()?.pod_ip.clone()?;
                if check_node_health_sync(&ip, http_port) {
                    Some(ip)
                } else {
                    None
                }
            })
        });

    // We already have heights from per-node checks, aggregate them
    if !p_heights.is_empty() {
        chain_statuses.insert(
            "P".to_string(),
            ChainStatus {
                alias: Some("P".to_string()),
                healthy: max_h > 0,
                block_height: Some(max_h),
            },
        );
    }

    // C-chain: use max height from any node
    let max_c_height = node_statuses
        .values()
        .filter_map(|ns| ns.c_chain_height)
        .max();
    if let Some(h) = max_c_height {
        chain_statuses.insert(
            "C".to_string(),
            ChainStatus {
                alias: Some("C".to_string()),
                healthy: true,
                block_height: Some(h),
            },
        );
    }

    // Subnet chain statuses (check from first healthy node)
    if let Some(ip) = &first_healthy_ip {
        for chain_ref in &spec.chains {
            if let Ok(Some(height)) =
                get_evm_block_height(ip, http_port, &chain_ref.blockchain_id).await
            {
                chain_statuses.insert(
                    chain_ref.blockchain_id.clone(),
                    ChainStatus {
                        alias: Some(chain_ref.alias.clone()),
                        healthy: true,
                        block_height: Some(height),
                    },
                );
            } else {
                chain_statuses.insert(
                    chain_ref.blockchain_id.clone(),
                    ChainStatus {
                        alias: Some(chain_ref.alias.clone()),
                        healthy: false,
                        block_height: None,
                    },
                );
                degraded_reasons.push(DegradedCondition {
                    reason: DegradedReason::ChainUnhealthy,
                    message: format!("Chain {} ({}) not responding", chain_ref.alias, &chain_ref.blockchain_id[..8.min(chain_ref.blockchain_id.len())]),
                    affected_nodes: vec![],
                });
            }
        }
    }

    // Discover external IPs and merge into node statuses by pod index
    let services: Api<Service> = Api::namespaced(ctx.client.clone(), &namespace);
    let external_ips = discover_external_ips(&services, &name, spec.validators).await;

    // Match external IPs to nodes by index (handles adopt_existing where StatefulSet name != CRD name)
    for (svc_key, ip) in &external_ips {
        // svc_key is "{crd-name}-{i}", extract the index
        if let Some(idx_str) = svc_key.rsplit('-').next() {
            if let Ok(idx) = idx_str.parse::<u32>() {
                // Find the node_status entry whose pod name ends with "-{idx}"
                let matching_pod = node_statuses
                    .keys()
                    .find(|pod_name| {
                        pod_name
                            .rsplit('-')
                            .next()
                            .and_then(|s| s.parse::<u32>().ok())
                            == Some(idx)
                    })
                    .cloned();

                if let Some(pod_name) = matching_pod {
                    if let Some(ns) = node_statuses.get_mut(&pod_name) {
                        ns.external_ip = Some(ip.clone());
                    }
                }
            }
        }
    }

    let total_peers: u32 = node_statuses.values().map(|ns| ns.connected_peers).sum();
    let bootstrapped_chains = chain_statuses.values().filter(|cs| cs.healthy).count() as u32;

    let network_metrics = Some(NetworkMetrics {
        min_p_height: min_h,
        max_p_height: max_h,
        height_skew: skew,
        bootstrapped_chains,
        total_peers,
    });

    debug!(
        "Network {} health: {}/{} validators healthy, P-height skew={}, peers={}",
        name, healthy_count, spec.validators, skew, total_peers
    );

    let threshold = (spec.validators * 2) / 3;
    let phase = if healthy_count >= spec.validators && degraded_reasons.is_empty() {
        "Running".to_string()
    } else if healthy_count >= threshold {
        if !degraded_reasons.is_empty() {
            warn!(
                "Network {} degraded: {} reasons",
                name,
                degraded_reasons.len()
            );
        }
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
        chain_statuses,
        external_ips,
        node_statuses,
        degraded_reasons,
        network_metrics,
        ..Default::default()
    })
}

/// Synchronous health check helper (for use in iterator context)
fn check_node_health_sync(_pod_ip: &str, _http_port: i32) -> bool {
    // This is used only as a filter hint; actual checks are async above
    true
}

/// Attempt recovery by restarting unhealthy pods (NEVER deletes PVCs)
/// Only restarts ONE pod at a time to avoid cascading failures
async fn attempt_recovery(network: &LuxNetwork, ctx: &Context) -> Result<LuxNetworkStatus> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let status = network.status.clone().unwrap_or_default();
    let http_port = spec.ports.http;

    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = pod_label_selector(&name, spec.adopt_existing);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let mut recovered = 0u32;
    let mut healthy = 0u32;
    let max_recoveries = spec.upgrade_strategy.max_unavailable;

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
            check_node_health(&pod_ip, http_port).await.unwrap_or(false)
        };

        if is_healthy {
            healthy += 1;
        } else if recovered < max_recoveries {
            // Check pod age - don't restart pods that just started (< 120s)
            let pod_age = pod
                .status
                .as_ref()
                .and_then(|s| s.start_time.as_ref())
                .map(|t| {
                    chrono::Utc::now()
                        .signed_duration_since(t.0)
                        .num_seconds()
                })
                .unwrap_or(0);

            if pod_age > 120 {
                info!(
                    "Deleting unhealthy pod {} (age {}s) for recovery (PVC preserved)",
                    pod_name, pod_age
                );
                match pods.delete(&pod_name, &DeleteParams::default()).await {
                    Ok(_) => {
                        info!("Deleted pod {} for recovery", pod_name);
                        recovered += 1;
                    }
                    Err(e) => {
                        error!("Failed to delete pod {}: {}", pod_name, e);
                    }
                }
            } else {
                info!(
                    "Pod {} unhealthy but recently started ({}s), skipping recovery",
                    pod_name, pod_age
                );
            }
        }
    }

    info!(
        "Network {} recovery: {} healthy, {} restarted (max {})",
        name, healthy, recovered, max_recoveries
    );

    let phase = if recovered > 0 {
        "Bootstrapping".to_string()
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

/// Enforce scale-down protection: refuse to reduce validators unless explicitly allowed
async fn check_scale_safety(
    network: &LuxNetwork,
    ctx: &Context,
) -> Result<bool> {
    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;

    let statefulsets: Api<StatefulSet> = Api::namespaced(ctx.client.clone(), &namespace);

    let sts = match statefulsets.get(&name).await {
        Ok(sts) => sts,
        Err(_) => return Ok(true), // no STS yet, safe to create
    };

    let current_replicas = sts
        .spec
        .as_ref()
        .and_then(|s| s.replicas)
        .unwrap_or(0) as u32;

    if spec.validators < current_replicas {
        // Scale down requested
        if !spec.allow_validator_removal {
            warn!(
                "Network {} scale-down from {} to {} BLOCKED: allowValidatorRemoval=false",
                name, current_replicas, spec.validators
            );
            return Ok(false);
        }
        warn!(
            "Network {} scale-down from {} to {} ALLOWED (allowValidatorRemoval=true)",
            name, current_replicas, spec.validators
        );
    }

    Ok(true)
}

// ───────────────────────── Node Health Checks ─────────────────────────

/// Check if a node is bootstrapped via health API
async fn check_node_bootstrapped(pod_ip: &str, http_port: i32) -> Result<bool> {
    let url = format!("http://{}:{}/ext/health", pod_ip, http_port);

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

    let result = body.get("result");

    // A node is bootstrapped when:
    // 1. The "bootstrapped" check exists and its message is an empty array []
    //    (empty = no chains are still bootstrapping)
    // 2. OR the overall healthy flag is true
    // We check bootstrapped first because idle private networks can report
    // healthy=false due to "no recent messages" or "no inbound connections"
    // even after all chains are fully bootstrapped.
    let bootstrapped_check = result
        .and_then(|r| r.get("checks"))
        .and_then(|c| c.get("bootstrapped"))
        .and_then(|b| b.get("message"));

    if let Some(msg) = bootstrapped_check {
        if let Some(arr) = msg.as_array() {
            // Empty array means all chains done bootstrapping
            return Ok(arr.is_empty());
        }
    }

    // Fallback: use overall healthy flag
    let healthy = result
        .and_then(|r| r.get("healthy"))
        .and_then(|h| h.as_bool())
        .unwrap_or(false);

    Ok(healthy)
}

/// Check node health via JSONRPC POST.
/// A node is considered healthy if:
/// 1. It responds to health requests (reachable), AND
/// 2. All chains are bootstrapped (empty bootstrapped.message array), AND
/// 3. It has connected peers > 0
/// This avoids marking nodes as unhealthy just because:
/// - The router has "no recent messages" on idle networks
/// - The node has no inbound connections (common in private/K8s networks)
async fn check_node_health(pod_ip: &str, http_port: i32) -> Result<bool> {
    let url = format!("http://{}:{}/ext/health", pod_ip, http_port);

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
        .map_err(|e| OperatorError::Reconcile(format!("Health check failed: {}", e)))?;

    if !resp.status().is_success() {
        return Ok(false);
    }

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("Failed to parse health: {}", e)))?;

    let result = match body.get("result") {
        Some(r) => r,
        None => return Ok(false),
    };

    // Check if all chains are bootstrapped (empty array = all done)
    let bootstrapped = result
        .get("checks")
        .and_then(|c| c.get("bootstrapped"))
        .and_then(|b| b.get("message"))
        .and_then(|m| m.as_array())
        .map(|arr| arr.is_empty())
        .unwrap_or(false);

    // Check peer connectivity
    let connected_peers = result
        .get("checks")
        .and_then(|c| c.get("network"))
        .and_then(|n| n.get("message"))
        .and_then(|m| m.get("connectedPeers"))
        .and_then(|p| p.as_u64())
        .unwrap_or(0);

    // Healthy = bootstrapped + has peers
    Ok(bootstrapped && connected_peers > 0)
}

/// Get P-chain height via platform.getHeight
async fn get_pchain_height(pod_ip: &str, http_port: i32) -> Result<Option<u64>> {
    let url = format!("http://{}:{}/ext/bc/P", pod_ip, http_port);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| OperatorError::Reconcile(format!("HTTP client error: {}", e)))?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "platform.getHeight",
            "params": {}
        }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let height = body
                .get("result")
                .and_then(|r| r.get("height"))
                .and_then(|h| h.as_str())
                .and_then(|s| s.parse::<u64>().ok());
            Ok(height)
        }
        _ => Ok(None),
    }
}

/// Get node ID and peer counts via info.getNodeID and info.peers
async fn get_node_peer_info(
    pod_ip: &str,
    http_port: i32,
) -> (Option<String>, u32, u32, u32) {
    let client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
    {
        Ok(c) => c,
        Err(_) => return (None, 0, 0, 0),
    };

    // Get NodeID
    let node_id = {
        let url = format!("http://{}:{}/ext/info", pod_ip, http_port);
        match client
            .post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "info.getNodeID",
                "params": {}
            }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                body.get("result")
                    .and_then(|r| r.get("nodeID"))
                    .and_then(|n| n.as_str())
                    .map(|s| s.to_string())
            }
            _ => None,
        }
    };

    // Get peer counts
    let (connected, inbound, outbound) = {
        let url = format!("http://{}:{}/ext/info", pod_ip, http_port);
        match client
            .post(&url)
            .json(&serde_json::json!({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "info.peers",
                "params": {}
            }))
            .send()
            .await
        {
            Ok(r) if r.status().is_success() => {
                let body: serde_json::Value = r.json().await.unwrap_or_default();
                let peers = body
                    .get("result")
                    .and_then(|r| r.get("peers"))
                    .and_then(|p| p.as_array());

                match peers {
                    Some(peer_list) => {
                        let total = peer_list.len() as u32;
                        // Count inbound vs outbound based on "type" field
                        let mut ib = 0u32;
                        let mut ob = 0u32;
                        for peer in peer_list {
                            let ptype = peer
                                .get("type")
                                .and_then(|t| t.as_str())
                                .unwrap_or("");
                            match ptype {
                                "inbound" => ib += 1,
                                "outbound" => ob += 1,
                                _ => ob += 1, // default to outbound
                            }
                        }
                        (total, ib, ob)
                    }
                    None => {
                        // Try numPeers field as fallback
                        let n = body
                            .get("result")
                            .and_then(|r| r.get("numPeers"))
                            .and_then(|n| n.as_str())
                            .and_then(|s| s.parse::<u32>().ok())
                            .unwrap_or(0);
                        (n, 0, n)
                    }
                }
            }
            _ => (0, 0, 0),
        }
    };

    (node_id, connected, inbound, outbound)
}

/// Get EVM chain block height via eth_blockNumber
async fn get_evm_block_height(
    pod_ip: &str,
    http_port: i32,
    chain: &str,
) -> Result<Option<u64>> {
    let url = format!("http://{}:{}/ext/bc/{}/rpc", pod_ip, http_port, chain);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| OperatorError::Reconcile(format!("HTTP client error: {}", e)))?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_blockNumber",
            "params": []
        }))
        .send()
        .await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let body: serde_json::Value = r.json().await.unwrap_or_default();
            let hex_str = body
                .get("result")
                .and_then(|r| r.as_str())
                .unwrap_or("0x0");
            let height =
                u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).unwrap_or(0);
            Ok(Some(height))
        }
        _ => Ok(None),
    }
}

// ───────────────────────── Snapshot Management ─────────────────────────

/// Result of a successful snapshot operation
struct SnapshotResult {
    timestamp: String,
    url: String,
    version: Option<u64>,
    count: u32,
}

/// Check if a snapshot is due and manage the snapshot lifecycle.
///
/// Uses a two-phase approach to avoid blocking the reconcile loop:
/// - Phase 1: Trigger admin.snapshot + launch background tar/upload in the pod
/// - Phase 2: Check if the background job completed (marker file)
///
/// Returns Ok(Some(result)) if snapshot completed, Ok(None) if not due or in-progress.
async fn maybe_take_snapshot(
    network: &LuxNetwork,
    ctx: &Context,
    _health_status: &LuxNetworkStatus,
) -> Result<Option<SnapshotResult>> {
    let schedule = &network.spec.snapshot_schedule;
    if !schedule.enabled || schedule.object_store_endpoint.is_empty() {
        return Ok(None);
    }

    let name = network.name_any();
    let namespace = network.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &network.spec;
    let http_port = spec.ports.http;
    let source_idx = schedule.source_node_index;

    // Find the source pod
    let pods: Api<Pod> = Api::namespaced(ctx.client.clone(), &namespace);
    let labels = pod_label_selector(&name, spec.adopt_existing);
    let pod_list = pods
        .list(&ListParams::default().labels(&labels))
        .await
        .map_err(OperatorError::KubeApi)?;

    let source_pod = pod_list
        .items
        .iter()
        .find(|pod| {
            pod.metadata
                .name
                .as_ref()
                .map(|n| n.ends_with(&format!("-{}", source_idx)))
                .unwrap_or(false)
        })
        .ok_or_else(|| {
            OperatorError::Reconcile(format!("Source pod {}-{} not found", name, source_idx))
        })?;

    let pod_ip = source_pod
        .status
        .as_ref()
        .and_then(|s| s.pod_ip.clone())
        .ok_or_else(|| OperatorError::Reconcile("Source pod has no IP".to_string()))?;

    let pod_name = source_pod
        .metadata
        .name
        .clone()
        .unwrap_or_else(|| format!("{}-{}", name, source_idx));

    // Marker files used to track background snapshot progress
    let progress_marker = "/tmp/snapshot-in-progress";
    let done_marker = "/tmp/snapshot-done";

    // Phase 2: Check if a previous background snapshot completed
    let check_result = exec_in_pod(
        &ctx.client,
        &namespace,
        &pod_name,
        &["sh", "-c", &format!(
            "if [ -f {} ]; then cat {}; elif [ -f {} ]; then echo IN_PROGRESS; else echo IDLE; fi",
            done_marker, done_marker, progress_marker
        )],
    )
    .await;

    if let Ok(ref output) = check_result {
        let output = output.trim();
        if output == "IN_PROGRESS" {
            debug!("Network {} snapshot still in progress on {}", name, pod_name);
            return Ok(None);
        }
        if output.starts_with("DONE|") {
            // Background snapshot completed! Parse result and clean up markers.
            let parts: Vec<&str> = output.splitn(4, '|').collect();
            // Format: DONE|<url>|<version>|<timestamp>
            let snap_url = parts.get(1).unwrap_or(&"").to_string();
            let snap_version = parts.get(2).and_then(|v| v.parse::<u64>().ok());
            let snap_time = parts.get(3).unwrap_or(&"").to_string();

            // Clean up markers
            let _ = exec_in_pod(
                &ctx.client,
                &namespace,
                &pod_name,
                &["sh", "-c", &format!("rm -f {} {}", progress_marker, done_marker)],
            )
            .await;

            let status = network.status.clone().unwrap_or_default();
            info!("Network {} snapshot completed: {}", name, snap_url);
            return Ok(Some(SnapshotResult {
                timestamp: if snap_time.is_empty() {
                    chrono::Utc::now().to_rfc3339()
                } else {
                    snap_time
                },
                url: snap_url,
                version: snap_version,
                count: status.snapshot_count + 1,
            }));
        }
        if output.starts_with("DONE") {
            // Old format (DONE:...) from previous operator version — clean up stale marker
            warn!("Network {} found stale DONE marker (old format), cleaning up", name);
            let _ = exec_in_pod(
                &ctx.client,
                &namespace,
                &pod_name,
                &["sh", "-c", &format!("rm -f {} {}", progress_marker, done_marker)],
            )
            .await;
            // Fall through to interval check — will trigger fresh snapshot
        }
        // IDLE — fall through to check if we should start a new snapshot
    }

    // Check if snapshot is due based on last snapshot time
    let status = network.status.clone().unwrap_or_default();
    if let Some(ref last_time) = status.last_snapshot_time {
        if let Ok(last_dt) = chrono::DateTime::parse_from_rfc3339(last_time) {
            let elapsed = chrono::Utc::now()
                .signed_duration_since(last_dt)
                .num_seconds() as u64;
            if elapsed < schedule.interval_seconds {
                return Ok(None);
            }
        }
    }

    // Phase 1: Trigger admin.snapshot and launch background tar+upload
    info!(
        "Network {} taking snapshot from node {} (interval={}s)",
        name, source_idx, schedule.interval_seconds
    );

    // Step 1: Trigger admin.snapshot (fast HTTP call)
    let snapshot_version = trigger_admin_snapshot(&pod_ip, http_port).await?;
    info!(
        "Network {} admin.snapshot returned version {} on {}",
        name, snapshot_version, pod_name
    );

    // Step 2: Build the background script that does the heavy lifting
    let bucket = &schedule.bucket;
    let prefix = if schedule.prefix.is_empty() {
        name.clone()
    } else {
        schedule.prefix.trim_end_matches('/').to_string()
    };
    let archive_name = format!("{}-node{}-full.tar.gz", prefix, source_idx);
    let archive_path = format!("/tmp/{}", archive_name);
    let object_key = format!("{}/{}", prefix, archive_name);
    let endpoint = &schedule.object_store_endpoint;
    let access_key = schedule.access_key.as_deref().unwrap_or("hanzo");
    let secret_key_ref = schedule.secret_key_ref.as_deref().unwrap_or("hanzo-minio-secret");
    let snapshot_url = format!("{}/{}/{}", endpoint, bucket, object_key);
    let now_rfc3339 = chrono::Utc::now().to_rfc3339();

    // Build RLP export commands if configured
    let mut rlp_cmds = String::new();
    if schedule.include_rlp_exports {
        // C-chain RLP export
        rlp_cmds.push_str(&format!(
            concat!(
                "curl -sf -X POST -H 'Content-Type: application/json' ",
                "-d '{{\"jsonrpc\":\"2.0\",\"method\":\"admin_exportChain\",\"params\":[\"/tmp/cchain.rlp\"],\"id\":1}}' ",
                "http://127.0.0.1:{}/ext/bc/C/rpc >/dev/null 2>&1 || true; ",
            ),
            http_port,
        ));
    }

    // The background script: tar + upload + cleanup + write done marker
    // Includes PID lock guard to prevent concurrent jobs
    let bg_script = format!(
        concat!(
            "if [ -f {progress} ]; then ",
            "  OLD_PID=$(cat {progress}); ",
            "  if kill -0 $OLD_PID 2>/dev/null; then exit 0; fi; ",
            "fi; ",
            "echo $$ > {progress}; ",
            "{rlp_cmds}",
            "tar czf {archive} -C /data --exclude='*.log' --exclude='LOCK' db chainData genesis.bytes 2>/dev/null; ",
            "MC=/tmp/mc; ",
            "if [ ! -f $MC ]; then ",
            "  curl -sfL https://dl.min.io/client/mc/release/linux-amd64/mc -o $MC 2>/dev/null && chmod +x $MC; ",
            "fi; ",
            "RESULT=FAIL; ",
            "if [ -f $MC ]; then ",
            "  $MC alias set snap {endpoint} {access_key} {secret_key} --api s3v4 2>/dev/null; ",
            "  if $MC cp {archive} snap/{bucket}/{key} 2>/dev/null; then RESULT=OK; fi; ",
            "fi; ",
            "rm -f {archive} /tmp/*.rlp {progress}; ",
            "if [ \"$RESULT\" = \"OK\" ]; then ",
            "  echo 'DONE|{url}|{version}|{time}' > {done}; ",
            "else ",
            "  echo 'DONE|UPLOAD_FAILED|0|{time}' > {done}; ",
            "fi",
        ),
        progress = progress_marker,
        rlp_cmds = rlp_cmds,
        archive = archive_path,
        endpoint = endpoint,
        access_key = access_key,
        secret_key = secret_key_ref,
        bucket = bucket,
        key = object_key,
        url = snapshot_url,
        version = snapshot_version,
        time = now_rfc3339,
        done = done_marker,
    );

    // Launch as background process via nohup — exec returns immediately
    let launch_cmd = format!("nohup sh -c '{}' >/tmp/snapshot.log 2>&1 &", bg_script.replace('\'', "'\\''"));
    let launch_result = exec_in_pod(
        &ctx.client,
        &namespace,
        &pod_name,
        &["sh", "-c", &launch_cmd],
    )
    .await;

    match launch_result {
        Ok(_) => {
            info!("Network {} snapshot background job launched on {}", name, pod_name);
        }
        Err(ref e) => {
            warn!("Network {} failed to launch snapshot job: {}", name, e);
        }
    }

    // Return None — snapshot is in progress, will be picked up on next reconcile
    Ok(None)
}

/// Trigger admin.snapshot on a node, returns the snapshot version number
async fn trigger_admin_snapshot(pod_ip: &str, http_port: i32) -> Result<u64> {
    let url = format!("http://{}:{}/ext/admin", pod_ip, http_port);

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(60))
        .build()
        .map_err(|e| OperatorError::Reconcile(format!("HTTP client error: {}", e)))?;

    let resp = client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "admin.snapshot",
            "params": {
                "path": "/data/snapshots/operator",
                "since": 0
            }
        }))
        .send()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("admin.snapshot failed: {}", e)))?;

    let body: serde_json::Value = resp
        .json()
        .await
        .map_err(|e| OperatorError::Reconcile(format!("admin.snapshot parse error: {}", e)))?;

    let version = body
        .get("result")
        .and_then(|r| r.get("version"))
        .and_then(|v| v.as_u64())
        .unwrap_or(0);

    Ok(version)
}

/// Execute a command inside a pod and return stdout.
/// Uses kube-rs exec API (requires `ws` feature on `kube` crate).
async fn exec_in_pod(
    client: &Client,
    namespace: &str,
    pod_name: &str,
    command: &[&str],
) -> Result<String> {
    let pods: Api<Pod> = Api::namespaced(client.clone(), namespace);
    let cmd: Vec<String> = command.iter().map(|s| s.to_string()).collect();

    let mut attached = pods
        .exec(
            pod_name,
            cmd,
            &kube::api::AttachParams::default()
                .stdout(true)
                .stderr(true),
        )
        .await
        .map_err(|e| OperatorError::Reconcile(format!("exec failed on {}: {}", pod_name, e)))?;

    // Collect stdout before joining (join consumes the process)
    let stdout = {
        let mut buf = Vec::new();
        if let Some(mut reader) = attached.stdout() {
            use tokio::io::AsyncReadExt;
            let _ = tokio::time::timeout(
                Duration::from_secs(300),
                reader.read_to_end(&mut buf),
            )
            .await;
        }
        buf
    };

    // Wait for process to complete
    let _ = attached.join().await;

    let output = String::from_utf8_lossy(&stdout).to_string();
    Ok(output)
}

// ───────────────────────── Helpers ─────────────────────────

/// Build pod label selector string
fn pod_label_selector(name: &str, adopt_existing: bool) -> String {
    if adopt_existing {
        "app=luxd".to_string()
    } else {
        format!("app.kubernetes.io/instance={}", name)
    }
}

/// Build list of bootstrap endpoints
fn build_bootstrap_endpoints(
    name: &str,
    namespace: &str,
    count: u32,
    http_port: i32,
) -> Vec<String> {
    (0..count)
        .map(|i| {
            format!(
                "http://{}-{}.{}-headless.{}.svc:{}",
                name, i, name, namespace, http_port
            )
        })
        .collect()
}

/// Build resource labels for a network
fn resource_labels(name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "luxd".to_string());
    labels.insert(
        "app.kubernetes.io/instance".to_string(),
        name.to_string(),
    );
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
        requests.insert("cpu".to_string(), Quantity("100m".to_string()));
    }

    if let Some(mem) = &spec.memory_request {
        requests.insert("memory".to_string(), Quantity(mem.clone()));
    } else {
        requests.insert("memory".to_string(), Quantity("256Mi".to_string()));
    }

    if let Some(cpu) = &spec.cpu_limit {
        limits.insert("cpu".to_string(), Quantity(cpu.clone()));
    } else {
        limits.insert("cpu".to_string(), Quantity("1".to_string()));
    }

    if let Some(mem) = &spec.memory_limit {
        limits.insert("memory".to_string(), Quantity(mem.clone()));
    } else {
        limits.insert("memory".to_string(), Quantity("1Gi".to_string()));
    }

    ResourceRequirements {
        requests: Some(requests),
        limits: Some(limits),
        ..Default::default()
    }
}

/// Apply a Kubernetes resource (create or update via server-side apply)
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

/// Error policy for the network controller
fn network_error_policy(
    network: Arc<LuxNetwork>,
    error: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(
        "Error reconciling network {}: {:?}",
        network.name_any(),
        error
    );
    Action::requeue(Duration::from_secs(30))
}

// ═══════════════════════════════════════════════════════════════════════════
// LuxIndexer Reconciler
// ═══════════════════════════════════════════════════════════════════════════

async fn reconcile_indexer(indexer: Arc<LuxIndexer>, ctx: Arc<Context>) -> Result<Action> {
    let name = indexer.name_any();
    let namespace = indexer.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &indexer.spec;

    info!("Reconciling LuxIndexer {}/{}", namespace, name);

    let indexers_api: Api<LuxIndexer> = Api::namespaced(ctx.client.clone(), &namespace);
    let current_status = indexer.status.clone().unwrap_or_default();
    let phase = current_status.phase.as_str();

    let new_status = match phase {
        "" | "Pending" => {
            info!("Indexer {}: Creating resources", name);
            create_indexer_resources(&ctx.client, &namespace, &name, spec, &indexer).await?;
            LuxIndexerStatus {
                phase: "Syncing".to_string(),
                database_ready: spec.database.managed,
                ..current_status
            }
        }
        "Creating" | "Syncing" | "Ready" => {
            // Always re-apply resources so spec changes (blockchainId, image, etc.) propagate
            create_indexer_resources(&ctx.client, &namespace, &name, spec, &indexer).await?;

            // Check if Deployment is ready
            let deploy_api: Api<Deployment> =
                Api::namespaced(ctx.client.clone(), &namespace);
            let new_phase = match deploy_api.get(&format!("{}-indexer", name)).await {
                Ok(deploy) => {
                    let ready = deploy
                        .status
                        .as_ref()
                        .and_then(|s| s.ready_replicas)
                        .unwrap_or(0);
                    if ready > 0 { "Ready" } else { "Syncing" }
                }
                Err(_) => "Creating",
            };
            LuxIndexerStatus {
                phase: new_phase.to_string(),
                api_endpoint: Some(format!(
                    "http://{}-indexer.{}.svc:{}",
                    name, namespace, spec.port
                )),
                database_ready: true,
                ..current_status
            }
        }
        "Error" => {
            warn!("Indexer {} in Error state, retrying", name);
            create_indexer_resources(&ctx.client, &namespace, &name, spec, &indexer).await?;
            LuxIndexerStatus {
                phase: "Syncing".to_string(),
                ..current_status
            }
        }
        _ => current_status,
    };

    // Update status
    let patch = serde_json::json!({ "status": new_status });
    indexers_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(OperatorError::KubeApi)?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Create all K8s resources for an indexer
async fn create_indexer_resources(
    client: &Client,
    namespace: &str,
    name: &str,
    spec: &crate::crd::LuxIndexerSpec,
    indexer: &LuxIndexer,
) -> Result<()> {
    let labels = indexer_labels(name, &spec.chain_alias);
    let owner_ref = indexer_owner_reference(indexer);

    // Look up parent LuxNetwork's HTTP port (default 9650)
    let network_port = {
        let networks_api: Api<LuxNetwork> = Api::namespaced(client.clone(), namespace);
        match networks_api.get(&spec.network_ref).await {
            Ok(net) => net.spec.ports.http,
            Err(e) => {
                warn!(
                    "Could not look up LuxNetwork {}/{}: {}, using default port 9650",
                    namespace, spec.network_ref, e
                );
                9650
            }
        }
    };

    // Resolve RPC endpoint
    let chain_path = spec.blockchain_id.as_deref().unwrap_or("C");
    let rpc_endpoint = spec.rpc_endpoint.clone().unwrap_or_else(|| {
        format!(
            "http://{}-0.{}-headless.{}.svc:{}/ext/bc/{}/rpc",
            spec.network_ref, spec.network_ref, namespace, network_port, chain_path
        )
    });

    let ws_endpoint = spec.ws_endpoint.clone().unwrap_or_else(|| {
        format!(
            "ws://{}-0.{}-headless.{}.svc:{}/ext/bc/{}/ws",
            spec.network_ref, spec.network_ref, namespace, network_port, chain_path
        )
    });

    // Database URL
    let db_name = spec
        .database
        .name
        .clone()
        .unwrap_or_else(|| format!("indexer_{}", spec.chain_alias.replace('-', "_")));

    let db_url = if spec.database.managed {
        // Create managed PostgreSQL StatefulSet
        create_indexer_postgres(client, namespace, name, spec, &labels, &owner_ref).await?;
        format!(
            "postgres://indexer:indexer@{}-pg.{}.svc:5432/{}?sslmode=disable",
            name, namespace, db_name
        )
    } else {
        spec.database
            .url
            .clone()
            .unwrap_or_else(|| "postgres://localhost:5432/indexer".to_string())
    };

    // Indexer Deployment
    let deploy_name = format!("{}-indexer", name);
    let image = format!("{}:{}", spec.image.repository, spec.image.tag);

    let mut env_vars = vec![
        EnvVar {
            name: "DATABASE_URL".to_string(),
            value: Some(db_url),
            ..Default::default()
        },
        EnvVar {
            name: "RPC_ENDPOINT".to_string(),
            value: Some(rpc_endpoint),
            ..Default::default()
        },
        EnvVar {
            name: "WS_ENDPOINT".to_string(),
            value: Some(ws_endpoint),
            ..Default::default()
        },
        EnvVar {
            name: "CHAIN_ID".to_string(),
            value: Some(spec.chain_id.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "CHAIN_ALIAS".to_string(),
            value: Some(spec.chain_alias.clone()),
            ..Default::default()
        },
        EnvVar {
            name: "HTTP_PORT".to_string(),
            value: Some(spec.port.to_string()),
            ..Default::default()
        },
        EnvVar {
            name: "POLL_INTERVAL".to_string(),
            value: Some(spec.poll_interval.to_string()),
            ..Default::default()
        },
    ];

    if spec.trace_enabled {
        env_vars.push(EnvVar {
            name: "TRACE_ENABLED".to_string(),
            value: Some("true".to_string()),
            ..Default::default()
        });
    }
    if spec.defi_indexing {
        env_vars.push(EnvVar {
            name: "DEFI_INDEXING".to_string(),
            value: Some("true".to_string()),
            ..Default::default()
        });
    }
    if spec.nft_indexing {
        env_vars.push(EnvVar {
            name: "NFT_INDEXING".to_string(),
            value: Some("true".to_string()),
            ..Default::default()
        });
    }

    let deployment = Deployment {
        metadata: kube::core::ObjectMeta {
            name: Some(deploy_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(kube::core::ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "indexer".to_string(),
                        image: Some(image),
                        image_pull_policy: Some(spec.image.pull_policy.clone()),
                        args: Some({
                            // Map chain alias to indexer chain type
                            // All EVM chains (C-chain + subnets) use "cchain"
                            let chain_type = match spec.chain_alias.to_lowercase().as_str() {
                                "p" | "pchain" => "pchain",
                                "x" | "xchain" => "xchain",
                                _ => "cchain", // C-chain and all EVM subnet chains
                            };
                            vec![
                                "-chain".to_string(),
                                chain_type.to_string(),
                            ]
                        }),
                        ports: Some(vec![ContainerPort {
                            container_port: spec.port,
                            name: Some("http".to_string()),
                            ..Default::default()
                        }]),
                        env: Some(env_vars),
                        resources: Some(build_resource_requirements(&spec.resources)),
                        liveness_probe: Some(Probe {
                            http_get: Some(
                                k8s_openapi::api::core::v1::HTTPGetAction {
                                    path: Some("/health".to_string()),
                                    port: IntOrString::Int(spec.port),
                                    ..Default::default()
                                },
                            ),
                            initial_delay_seconds: Some(30),
                            period_seconds: Some(30),
                            ..Default::default()
                        }),
                        readiness_probe: Some(Probe {
                            http_get: Some(
                                k8s_openapi::api::core::v1::HTTPGetAction {
                                    path: Some("/health".to_string()),
                                    port: IntOrString::Int(spec.port),
                                    ..Default::default()
                                },
                            ),
                            initial_delay_seconds: Some(10),
                            period_seconds: Some(10),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    image_pull_secrets: Some(vec![LocalObjectReference {
                        name: Some("registry-hanzo".to_string()),
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    apply_resource(&deploy_api, &deploy_name, &deployment).await?;

    // Service for indexer API
    let svc_name = format!("{}-indexer", name);
    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(svc_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: spec.port,
                target_port: Some(IntOrString::Int(spec.port)),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    apply_resource(&svc_api, &svc_name, &svc).await?;

    info!("Created indexer resources for {}/{}", namespace, name);
    Ok(())
}

/// Create managed PostgreSQL StatefulSet for an indexer
async fn create_indexer_postgres(
    client: &Client,
    namespace: &str,
    name: &str,
    spec: &crate::crd::LuxIndexerSpec,
    parent_labels: &BTreeMap<String, String>,
    owner_ref: &OwnerReference,
) -> Result<()> {
    let pg_name = format!("{}-pg", name);
    let mut pg_labels = parent_labels.clone();
    pg_labels.insert("component".to_string(), "postgresql".to_string());

    let db_name = spec
        .database
        .name
        .clone()
        .unwrap_or_else(|| format!("indexer_{}", spec.chain_alias.replace('-', "_")));

    let pg_sts = StatefulSet {
        metadata: kube::core::ObjectMeta {
            name: Some(pg_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(pg_labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(StatefulSetSpec {
            replicas: Some(1),
            service_name: pg_name.clone(),
            selector: LabelSelector {
                match_labels: Some(pg_labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(kube::core::ObjectMeta {
                    labels: Some(pg_labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "postgres".to_string(),
                        image: Some(spec.database.image.clone()),
                        ports: Some(vec![ContainerPort {
                            container_port: 5432,
                            name: Some("pg".to_string()),
                            ..Default::default()
                        }]),
                        env: Some(vec![
                            EnvVar {
                                name: "POSTGRES_DB".to_string(),
                                value: Some(db_name),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "POSTGRES_USER".to_string(),
                                value: Some("indexer".to_string()),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "POSTGRES_PASSWORD".to_string(),
                                value: Some("indexer".to_string()),
                                ..Default::default()
                            },
                            EnvVar {
                                name: "PGDATA".to_string(),
                                value: Some("/var/lib/postgresql/data/pgdata".to_string()),
                                ..Default::default()
                            },
                        ]),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "pg-data".to_string(),
                            mount_path: "/var/lib/postgresql/data".to_string(),
                            ..Default::default()
                        }]),
                        readiness_probe: Some(Probe {
                            exec: Some(k8s_openapi::api::core::v1::ExecAction {
                                command: Some(vec![
                                    "pg_isready".to_string(),
                                    "-U".to_string(),
                                    "indexer".to_string(),
                                ]),
                            }),
                            initial_delay_seconds: Some(5),
                            period_seconds: Some(10),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            volume_claim_templates: Some(vec![PersistentVolumeClaim {
                metadata: kube::core::ObjectMeta {
                    name: Some("pg-data".to_string()),
                    ..Default::default()
                },
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec!["ReadWriteOnce".to_string()]),
                    resources: Some(ResourceRequirements {
                        requests: Some({
                            let mut m = BTreeMap::new();
                            m.insert(
                                "storage".to_string(),
                                Quantity(spec.database.storage_size.clone()),
                            );
                            m
                        }),
                        ..Default::default()
                    }),
                    storage_class_name: spec.database.storage_class.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            }]),
            persistent_volume_claim_retention_policy: Some(
                StatefulSetPersistentVolumeClaimRetentionPolicy {
                    when_deleted: Some("Retain".to_string()),
                    when_scaled: Some("Retain".to_string()),
                },
            ),
            ..Default::default()
        }),
        ..Default::default()
    };

    let sts_api: Api<StatefulSet> = Api::namespaced(client.clone(), namespace);
    apply_resource(&sts_api, &pg_name, &pg_sts).await?;

    // Headless service for PostgreSQL
    let pg_svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(pg_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(pg_labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            selector: Some(pg_labels),
            ports: Some(vec![ServicePort {
                name: Some("pg".to_string()),
                port: 5432,
                target_port: Some(IntOrString::Int(5432)),
                ..Default::default()
            }]),
            cluster_ip: Some("None".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    apply_resource(&svc_api, &pg_name, &pg_svc).await?;

    info!("Created PostgreSQL for indexer {}/{}", namespace, name);
    Ok(())
}

fn indexer_labels(name: &str, chain_alias: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "lux-indexer".to_string());
    labels.insert("app.kubernetes.io/instance".to_string(), name.to_string());
    labels.insert("app.kubernetes.io/component".to_string(), "indexer".to_string());
    labels.insert("lux.network/chain".to_string(), chain_alias.to_string());
    labels.insert("app.kubernetes.io/managed-by".to_string(), "lux-operator".to_string());
    labels
}

fn indexer_owner_reference(indexer: &LuxIndexer) -> OwnerReference {
    OwnerReference {
        api_version: LuxIndexer::api_version(&()).to_string(),
        kind: LuxIndexer::kind(&()).to_string(),
        name: indexer.name_any(),
        uid: indexer.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

fn indexer_error_policy(
    indexer: Arc<LuxIndexer>,
    error: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(
        "Error reconciling indexer {}: {:?}",
        indexer.name_any(),
        error
    );
    Action::requeue(Duration::from_secs(30))
}

// ═══════════════════════════════════════════════════════════════════════════
// LuxExplorer Reconciler
// ═══════════════════════════════════════════════════════════════════════════

async fn reconcile_explorer(explorer: Arc<LuxExplorer>, ctx: Arc<Context>) -> Result<Action> {
    let name = explorer.name_any();
    let namespace = explorer.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &explorer.spec;

    info!("Reconciling LuxExplorer {}/{}", namespace, name);

    let explorers_api: Api<LuxExplorer> = Api::namespaced(ctx.client.clone(), &namespace);
    let current_status = explorer.status.clone().unwrap_or_default();
    let phase = current_status.phase.as_str();

    let new_status = match phase {
        "" | "Pending" => {
            info!("Explorer {}: Creating resources", name);
            create_explorer_resources(&ctx.client, &namespace, &name, spec, &explorer).await?;
            LuxExplorerStatus {
                phase: "Creating".to_string(),
                ..current_status
            }
        }
        "Creating" | "Ready" => {
            let deploy_api: Api<Deployment> =
                Api::namespaced(ctx.client.clone(), &namespace);
            match deploy_api.get(&format!("{}-explorer", name)).await {
                Ok(deploy) => {
                    let ready = deploy
                        .status
                        .as_ref()
                        .and_then(|s| s.ready_replicas)
                        .unwrap_or(0);
                    let url = spec
                        .ingress
                        .as_ref()
                        .map(|i| format!("https://{}", i.host));
                    LuxExplorerStatus {
                        phase: if ready > 0 { "Ready" } else { "Creating" }.to_string(),
                        url,
                        ready_replicas: ready,
                        ..current_status
                    }
                }
                Err(_) => {
                    create_explorer_resources(&ctx.client, &namespace, &name, spec, &explorer)
                        .await?;
                    LuxExplorerStatus {
                        phase: "Creating".to_string(),
                        ..current_status
                    }
                }
            }
        }
        "Error" => {
            warn!("Explorer {} in Error state, retrying", name);
            create_explorer_resources(&ctx.client, &namespace, &name, spec, &explorer).await?;
            LuxExplorerStatus {
                phase: "Creating".to_string(),
                ..current_status
            }
        }
        _ => current_status,
    };

    let patch = serde_json::json!({ "status": new_status });
    explorers_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(OperatorError::KubeApi)?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Create explorer Deployment, Service, and optional Ingress
async fn create_explorer_resources(
    client: &Client,
    namespace: &str,
    name: &str,
    spec: &crate::crd::LuxExplorerSpec,
    explorer: &LuxExplorer,
) -> Result<()> {
    let labels = explorer_labels(name);
    let owner_ref = explorer_owner_reference(explorer);
    let deploy_name = format!("{}-explorer", name);
    let image = format!("{}:{}", spec.image.repository, spec.image.tag);

    // Find default indexer ref (first with default=true, or first overall)
    let default_ref = spec
        .indexer_refs
        .iter()
        .find(|r| r.default)
        .or_else(|| spec.indexer_refs.first());

    // Look up default indexer's chain ID from LuxIndexer CR
    let chain_id: i64 = if let Some(ref_) = default_ref {
        let indexers: Api<crate::crd::LuxIndexer> = Api::namespaced(client.clone(), namespace);
        if let Ok(indexer) = indexers.get(&ref_.indexer_name).await {
            indexer.spec.chain_id as i64
        } else {
            1 // fallback
        }
    } else {
        1
    };

    // Determine hosts
    let app_host = spec
        .ingress
        .as_ref()
        .map(|i| i.host.clone())
        .unwrap_or_else(|| format!("{}-explorer.{}.svc", name, namespace));
    let api_host = if let Some(ref_) = default_ref {
        format!("{}-indexer.{}.svc:4000", ref_.indexer_name, namespace)
    } else {
        format!("indexer-c-indexer.{}.svc:4000", namespace)
    };
    let network_name = spec
        .branding
        .as_ref()
        .map(|b| b.network_name.clone())
        .unwrap_or_else(|| "Lux Network".to_string());

    // Build indexer backend env vars (connect to indexer APIs)
    let mut env_vars: Vec<EnvVar> = spec
        .indexer_refs
        .iter()
        .enumerate()
        .flat_map(|(i, chain_ref)| {
            vec![
                EnvVar {
                    name: format!("CHAIN_{}_NAME", i),
                    value: Some(chain_ref.display_name.clone()),
                    ..Default::default()
                },
                EnvVar {
                    name: format!("CHAIN_{}_INDEXER", i),
                    value: Some(format!(
                        "http://{}-indexer.{}.svc:4000",
                        chain_ref.indexer_name, namespace
                    )),
                    ..Default::default()
                },
            ]
        })
        .collect();

    env_vars.push(EnvVar {
        name: "CHAIN_COUNT".to_string(),
        value: Some(spec.indexer_refs.len().to_string()),
        ..Default::default()
    });

    // Required Blockscout frontend env vars
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_APP_HOST".to_string(),
        value: Some(app_host.clone()),
        ..Default::default()
    });
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_NETWORK_NAME".to_string(),
        value: Some(network_name.clone()),
        ..Default::default()
    });
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_NETWORK_ID".to_string(),
        value: Some(chain_id.to_string()),
        ..Default::default()
    });
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_API_HOST".to_string(),
        value: Some(format!("http://{}", api_host)),
        ..Default::default()
    });
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_APP_PROTOCOL".to_string(),
        value: Some("https".to_string()),
        ..Default::default()
    });
    env_vars.push(EnvVar {
        name: "NEXT_PUBLIC_API_PROTOCOL".to_string(),
        value: Some("http".to_string()),
        ..Default::default()
    });

    if let Some(branding) = &spec.branding {
        env_vars.push(EnvVar {
            name: "NETWORK_NAME".to_string(),
            value: Some(branding.network_name.clone()),
            ..Default::default()
        });
        if let Some(logo) = &branding.logo_url {
            env_vars.push(EnvVar {
                name: "LOGO_URL".to_string(),
                value: Some(logo.clone()),
                ..Default::default()
            });
        }
    }

    let deployment = Deployment {
        metadata: kube::core::ObjectMeta {
            name: Some(deploy_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(kube::core::ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "explorer".to_string(),
                        image: Some(image),
                        image_pull_policy: Some(spec.image.pull_policy.clone()),
                        ports: Some(vec![ContainerPort {
                            container_port: spec.port,
                            name: Some("http".to_string()),
                            ..Default::default()
                        }]),
                        env: Some(env_vars),
                        resources: Some(build_resource_requirements(&spec.resources)),
                        liveness_probe: Some(Probe {
                            http_get: Some(
                                k8s_openapi::api::core::v1::HTTPGetAction {
                                    path: Some("/".to_string()),
                                    port: IntOrString::Int(spec.port),
                                    ..Default::default()
                                },
                            ),
                            initial_delay_seconds: Some(15),
                            period_seconds: Some(30),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    image_pull_secrets: Some(vec![LocalObjectReference {
                        name: Some("registry-hanzo".to_string()),
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    apply_resource(&deploy_api, &deploy_name, &deployment).await?;

    // ClusterIP Service
    let svc_name = format!("{}-explorer", name);
    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(svc_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            selector: Some(labels.clone()),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: spec.port,
                target_port: Some(IntOrString::Int(spec.port)),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    apply_resource(&svc_api, &svc_name, &svc).await?;

    // Ingress (optional)
    if let Some(ingress_spec) = &spec.ingress {
        let ingress_name = format!("{}-explorer", name);
        let mut annotations = ingress_spec.annotations.clone();
        annotations.insert(
            "kubernetes.io/ingress.class".to_string(),
            ingress_spec.ingress_class.clone(),
        );

        let ingress = Ingress {
            metadata: kube::core::ObjectMeta {
                name: Some(ingress_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                annotations: Some(annotations),
                owner_references: Some(vec![owner_ref]),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                tls: ingress_spec.tls_secret.as_ref().map(|secret| {
                    vec![IngressTLS {
                        hosts: Some(vec![ingress_spec.host.clone()]),
                        secret_name: Some(secret.clone()),
                    }]
                }),
                rules: Some(vec![IngressRule {
                    host: Some(ingress_spec.host.clone()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(
                                    k8s_openapi::api::networking::v1::IngressServiceBackend {
                                        name: svc_name,
                                        port: Some(ServiceBackendPort {
                                            number: Some(spec.port),
                                            ..Default::default()
                                        }),
                                    },
                                ),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
        apply_resource(&ingress_api, &ingress_name, &ingress).await?;
    }

    info!("Created explorer resources for {}/{}", namespace, name);
    Ok(())
}

fn explorer_labels(name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "lux-explorer".to_string());
    labels.insert("app.kubernetes.io/instance".to_string(), name.to_string());
    labels.insert("app.kubernetes.io/component".to_string(), "explorer".to_string());
    labels.insert("app.kubernetes.io/managed-by".to_string(), "lux-operator".to_string());
    labels
}

fn explorer_owner_reference(explorer: &LuxExplorer) -> OwnerReference {
    OwnerReference {
        api_version: LuxExplorer::api_version(&()).to_string(),
        kind: LuxExplorer::kind(&()).to_string(),
        name: explorer.name_any(),
        uid: explorer.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

fn explorer_error_policy(
    explorer: Arc<LuxExplorer>,
    error: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(
        "Error reconciling explorer {}: {:?}",
        explorer.name_any(),
        error
    );
    Action::requeue(Duration::from_secs(30))
}

// ═══════════════════════════════════════════════════════════════════════════
// LuxGateway Reconciler
// ═══════════════════════════════════════════════════════════════════════════

async fn reconcile_gateway(gateway: Arc<LuxGateway>, ctx: Arc<Context>) -> Result<Action> {
    let name = gateway.name_any();
    let namespace = gateway.namespace().unwrap_or_else(|| "default".to_string());
    let spec = &gateway.spec;

    info!("Reconciling LuxGateway {}/{}", namespace, name);

    let gateways_api: Api<LuxGateway> = Api::namespaced(ctx.client.clone(), &namespace);
    let current_status = gateway.status.clone().unwrap_or_default();
    let phase = current_status.phase.as_str();

    // Look up the referenced LuxNetwork to get HTTP port
    let networks_api: Api<LuxNetwork> = Api::namespaced(ctx.client.clone(), &namespace);
    let http_port = match networks_api.get(&spec.network_ref).await {
        Ok(network) => network.spec.ports.http,
        Err(_) => {
            warn!("Gateway {}: LuxNetwork {} not found, using default port 9650", name, spec.network_ref);
            9650
        }
    };

    // Discover subnet blockchain IDs from P-chain (best-effort)
    let subnet_chains = discover_subnet_chains(&namespace, &spec.network_ref, http_port).await;
    if !subnet_chains.is_empty() {
        info!("Gateway {}: discovered {} subnet chains from P-chain", name, subnet_chains.len());
    }

    let new_status = match phase {
        "" | "Pending" => {
            info!("Gateway {}: Creating resources", name);
            create_gateway_resources(&ctx.client, &namespace, &name, spec, &gateway, http_port, &subnet_chains).await?;
            LuxGatewayStatus {
                phase: "Creating".to_string(),
                ..current_status
            }
        }
        "Creating" | "Ready" => {
            // Always re-create resources to pick up subnet chain changes
            create_gateway_resources(&ctx.client, &namespace, &name, spec, &gateway, http_port, &subnet_chains).await?;

            let deploy_api: Api<Deployment> =
                Api::namespaced(ctx.client.clone(), &namespace);
            match deploy_api.get(&format!("{}-gateway", name)).await {
                Ok(deploy) => {
                    let ready = deploy
                        .status
                        .as_ref()
                        .and_then(|s| s.ready_replicas)
                        .unwrap_or(0);

                    // Count routes: 6 base (C rpc, C ws, X, P, info, health) + 2 per subnet (rpc + ws)
                    let auto_count: u32 = if spec.auto_routes {
                        6 + (subnet_chains.len() as u32 * 2)
                    } else {
                        0
                    };
                    let custom_count = spec.custom_routes.len() as u32;
                    let indexer_count = spec.indexer_refs.len() as u32;

                    // Build chain_routes status map
                    let mut chain_routes = BTreeMap::new();
                    chain_routes.insert("C-chain".to_string(), "/ext/bc/C/rpc".to_string());
                    for (chain_name, blockchain_id) in &subnet_chains {
                        chain_routes.insert(
                            chain_name.clone(),
                            format!("/ext/bc/{}/rpc", blockchain_id),
                        );
                    }

                    LuxGatewayStatus {
                        phase: if ready > 0 { "Ready" } else { "Creating" }.to_string(),
                        route_count: auto_count + custom_count + indexer_count,
                        ready_replicas: ready,
                        external_endpoint: Some(format!("https://{}", spec.host)),
                        chain_routes,
                        ..current_status
                    }
                }
                Err(_) => {
                    LuxGatewayStatus {
                        phase: "Creating".to_string(),
                        ..current_status
                    }
                }
            }
        }
        "Error" => {
            warn!("Gateway {} in Error state, retrying", name);
            create_gateway_resources(&ctx.client, &namespace, &name, spec, &gateway, http_port, &subnet_chains).await?;
            LuxGatewayStatus {
                phase: "Creating".to_string(),
                ..current_status
            }
        }
        _ => current_status,
    };

    let patch = serde_json::json!({ "status": new_status });
    gateways_api
        .patch_status(&name, &PatchParams::default(), &Patch::Merge(&patch))
        .await
        .map_err(OperatorError::KubeApi)?;

    Ok(Action::requeue(Duration::from_secs(60)))
}

/// Discover subnet blockchain IDs from P-chain RPC (best-effort, returns empty on failure)
async fn discover_subnet_chains(
    namespace: &str,
    network_ref: &str,
    http_port: i32,
) -> Vec<(String, String)> {
    let url = format!(
        "http://{}-headless.{}.svc:{}/ext/bc/P",
        network_ref, namespace, http_port
    );

    let http_client = match reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
    {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let resp = match http_client
        .post(&url)
        .json(&serde_json::json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "platform.getBlockchains",
            "params": {}
        }))
        .send()
        .await
    {
        Ok(r) => r,
        Err(e) => {
            warn!("Failed to query P-chain for blockchains: {}", e);
            return Vec::new();
        }
    };

    let body: serde_json::Value = match resp.json().await {
        Ok(b) => b,
        Err(_) => return Vec::new(),
    };

    let primary_subnet = "11111111111111111111111111111111LpoYY";
    let mut chains = Vec::new();

    if let Some(blockchains) = body["result"]["blockchains"].as_array() {
        for chain in blockchains {
            // Lux P-chain uses "netID" (not "subnetID") for the subnet identifier
            let net_id = chain["netID"].as_str().unwrap_or("");
            let chain_name = chain["name"].as_str().unwrap_or("");

            // Skip primary network chains (P, X, C are on the primary subnet)
            if net_id == primary_subnet {
                continue;
            }

            if let Some(id) = chain["id"].as_str() {
                let name = if chain_name.is_empty() { "unknown" } else { chain_name };
                chains.push((name.to_string(), id.to_string()));
            }
        }
    }

    chains
}

/// Create gateway ConfigMap (KrakenD config), Deployment, Service, and Ingress
async fn create_gateway_resources(
    client: &Client,
    namespace: &str,
    name: &str,
    spec: &crate::crd::LuxGatewaySpec,
    gateway: &LuxGateway,
    http_port: i32,
    subnet_chains: &[(String, String)],
) -> Result<()> {
    let labels = gateway_labels(name);
    let owner_ref = gateway_owner_reference(gateway);

    // Build KrakenD configuration JSON
    let krakend_config = build_krakend_config(namespace, spec, http_port, subnet_chains);

    // ConfigMap with KrakenD config
    let cm_name = format!("{}-gateway-config", name);
    let mut cm_data = BTreeMap::new();
    cm_data.insert("krakend.json".to_string(), krakend_config);

    let config_map = ConfigMap {
        metadata: kube::core::ObjectMeta {
            name: Some(cm_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        data: Some(cm_data),
        ..Default::default()
    };

    let cm_api: Api<ConfigMap> = Api::namespaced(client.clone(), namespace);
    apply_resource(&cm_api, &cm_name, &config_map).await?;

    // Gateway Deployment
    let deploy_name = format!("{}-gateway", name);
    let image = format!("{}:{}", spec.image.repository, spec.image.tag);

    let deployment = Deployment {
        metadata: kube::core::ObjectMeta {
            name: Some(deploy_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(kube::core::ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    containers: vec![Container {
                        name: "krakend".to_string(),
                        image: Some(image),
                        image_pull_policy: Some(spec.image.pull_policy.clone()),
                        ports: Some(vec![ContainerPort {
                            container_port: spec.port,
                            name: Some("http".to_string()),
                            ..Default::default()
                        }]),
                        command: Some(vec!["/usr/bin/krakend".to_string()]),
                        args: Some(vec![
                            "run".to_string(),
                            "-c".to_string(),
                            "/etc/krakend/krakend.json".to_string(),
                        ]),
                        volume_mounts: Some(vec![VolumeMount {
                            name: "config".to_string(),
                            mount_path: "/etc/krakend".to_string(),
                            read_only: Some(true),
                            ..Default::default()
                        }]),
                        resources: Some(build_resource_requirements(&spec.resources)),
                        liveness_probe: Some(Probe {
                            http_get: Some(
                                k8s_openapi::api::core::v1::HTTPGetAction {
                                    path: Some("/__health".to_string()),
                                    port: IntOrString::Int(spec.port),
                                    ..Default::default()
                                },
                            ),
                            initial_delay_seconds: Some(10),
                            period_seconds: Some(15),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: "config".to_string(),
                        config_map: Some(k8s_openapi::api::core::v1::ConfigMapVolumeSource {
                            name: Some(cm_name),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    let deploy_api: Api<Deployment> = Api::namespaced(client.clone(), namespace);
    apply_resource(&deploy_api, &deploy_name, &deployment).await?;

    // LoadBalancer Service
    let svc_name = format!("{}-gateway", name);
    let svc = Service {
        metadata: kube::core::ObjectMeta {
            name: Some(svc_name.clone()),
            namespace: Some(namespace.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_ref.clone()]),
            ..Default::default()
        },
        spec: Some(K8sServiceSpec {
            selector: Some(labels.clone()),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: 80,
                target_port: Some(IntOrString::Int(spec.port)),
                ..Default::default()
            }]),
            type_: Some("LoadBalancer".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    let svc_api: Api<Service> = Api::namespaced(client.clone(), namespace);
    apply_resource(&svc_api, &svc_name, &svc).await?;

    // Ingress (if TLS configured)
    if let Some(tls) = &spec.tls {
        let ingress_name = format!("{}-gateway", name);
        let mut annotations = BTreeMap::new();
        annotations.insert(
            "kubernetes.io/ingress.class".to_string(),
            "nginx".to_string(),
        );
        if tls.cert_manager {
            if let Some(issuer) = &tls.issuer {
                annotations.insert(
                    "cert-manager.io/cluster-issuer".to_string(),
                    issuer.clone(),
                );
            }
        }

        let ingress = Ingress {
            metadata: kube::core::ObjectMeta {
                name: Some(ingress_name.clone()),
                namespace: Some(namespace.to_string()),
                labels: Some(labels),
                annotations: Some(annotations),
                owner_references: Some(vec![owner_ref]),
                ..Default::default()
            },
            spec: Some(IngressSpec {
                tls: Some(vec![IngressTLS {
                    hosts: Some(vec![spec.host.clone()]),
                    secret_name: Some(tls.secret_name.clone()),
                }]),
                rules: Some(vec![IngressRule {
                    host: Some(spec.host.clone()),
                    http: Some(HTTPIngressRuleValue {
                        paths: vec![HTTPIngressPath {
                            path: Some("/".to_string()),
                            path_type: "Prefix".to_string(),
                            backend: IngressBackend {
                                service: Some(
                                    k8s_openapi::api::networking::v1::IngressServiceBackend {
                                        name: svc_name,
                                        port: Some(ServiceBackendPort {
                                            number: Some(80),
                                            ..Default::default()
                                        }),
                                    },
                                ),
                                ..Default::default()
                            },
                        }],
                    }),
                }]),
                ..Default::default()
            }),
            ..Default::default()
        };

        let ingress_api: Api<Ingress> = Api::namespaced(client.clone(), namespace);
        apply_resource(&ingress_api, &ingress_name, &ingress).await?;
    }

    info!("Created gateway resources for {}/{}", namespace, name);
    Ok(())
}

/// Build KrakenD JSON configuration from gateway spec
fn build_krakend_config(
    namespace: &str,
    spec: &crate::crd::LuxGatewaySpec,
    http_port: i32,
    subnet_chains: &[(String, String)],
) -> String {
    let mut endpoints = Vec::new();

    // Auto-routes for blockchain RPCs
    if spec.auto_routes {
        let rpc_backend = format!(
            "http://{}-headless.{}.svc:{}",
            spec.network_ref, namespace, http_port
        );

        let max_rate = spec.rate_limit.as_ref().map(|r| r.requests_per_second).unwrap_or(100);
        let burst = spec.rate_limit.as_ref().map(|r| r.burst).unwrap_or(200);

        // C-chain RPC (rate-limited)
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/bc/C/rpc",
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/bc/C/rpc",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }],
            "extra_config": {
                "qos/ratelimit/router": {
                    "max_rate": max_rate,
                    "capacity": burst
                }
            }
        }));

        // C-chain WebSocket
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/bc/C/ws",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/bc/C/ws",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }]
        }));

        // X-chain
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/bc/X",
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/bc/X",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }]
        }));

        // P-chain
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/bc/P",
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/bc/P",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }]
        }));

        // Info API
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/info",
            "method": "POST",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/info",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }]
        }));

        // Health
        endpoints.push(serde_json::json!({
            "endpoint": "/ext/health",
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": "/ext/health",
                "host": [&rpc_backend],
                "encoding": "no-op"
            }]
        }));

        // Subnet chain routes (auto-discovered from P-chain)
        for (chain_name, blockchain_id) in subnet_chains {
            // RPC endpoint
            endpoints.push(serde_json::json!({
                "endpoint": format!("/ext/bc/{}/rpc", blockchain_id),
                "method": "POST",
                "output_encoding": "no-op",
                "backend": [{
                    "url_pattern": format!("/ext/bc/{}/rpc", blockchain_id),
                    "host": [&rpc_backend],
                    "encoding": "no-op"
                }],
                "extra_config": {
                    "qos/ratelimit/router": {
                        "max_rate": max_rate,
                        "capacity": burst
                    }
                }
            }));

            // WebSocket endpoint
            endpoints.push(serde_json::json!({
                "endpoint": format!("/ext/bc/{}/ws", blockchain_id),
                "output_encoding": "no-op",
                "backend": [{
                    "url_pattern": format!("/ext/bc/{}/ws", blockchain_id),
                    "host": [&rpc_backend],
                    "encoding": "no-op"
                }]
            }));

            info!("  Added routes for subnet chain '{}': /ext/bc/{}/rpc", chain_name, blockchain_id);
        }

        // Indexer API routes
        for indexer_ref in &spec.indexer_refs {
            let indexer_backend = format!(
                "http://{}-indexer.{}.svc:4000",
                indexer_ref, namespace
            );
            endpoints.push(serde_json::json!({
                "endpoint": format!("/api/indexer/{}", indexer_ref),
                "output_encoding": "no-op",
                "backend": [{
                    "url_pattern": "/",
                    "host": [&indexer_backend],
                    "encoding": "no-op"
                }]
            }));
        }
    }

    // Custom routes
    for route in &spec.custom_routes {
        endpoints.push(serde_json::json!({
            "endpoint": route.path,
            "method": route.methods.first().unwrap_or(&"GET".to_string()),
            "output_encoding": "no-op",
            "backend": [{
                "url_pattern": route.path,
                "host": [&route.backend],
                "encoding": "no-op",
                "timeout": format!("{}s", route.timeout)
            }]
        }));
    }

    let config = serde_json::json!({
        "$schema": "https://www.krakend.io/schema/v2.7/krakend.json",
        "version": 3,
        "name": format!("Lux Gateway - {}", spec.host),
        "port": spec.port,
        "timeout": "30s",
        "cache_ttl": "0s",
        "extra_config": {
            "security/cors": {
                "allow_origins": spec.cors.allowed_origins,
                "allow_methods": spec.cors.allowed_methods,
                "allow_headers": spec.cors.allowed_headers,
                "expose_headers": ["Content-Length"],
                "max_age": "12h"
            }
        },
        "endpoints": endpoints
    });

    serde_json::to_string_pretty(&config).unwrap_or_default()
}

fn gateway_labels(name: &str) -> BTreeMap<String, String> {
    let mut labels = BTreeMap::new();
    labels.insert("app.kubernetes.io/name".to_string(), "lux-gateway".to_string());
    labels.insert("app.kubernetes.io/instance".to_string(), name.to_string());
    labels.insert("app.kubernetes.io/component".to_string(), "gateway".to_string());
    labels.insert("app.kubernetes.io/managed-by".to_string(), "lux-operator".to_string());
    labels
}

fn gateway_owner_reference(gateway: &LuxGateway) -> OwnerReference {
    OwnerReference {
        api_version: LuxGateway::api_version(&()).to_string(),
        kind: LuxGateway::kind(&()).to_string(),
        name: gateway.name_any(),
        uid: gateway.metadata.uid.clone().unwrap_or_default(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

fn gateway_error_policy(
    gateway: Arc<LuxGateway>,
    error: &OperatorError,
    _ctx: Arc<Context>,
) -> Action {
    error!(
        "Error reconciling gateway {}: {:?}",
        gateway.name_any(),
        error
    );
    Action::requeue(Duration::from_secs(30))
}
