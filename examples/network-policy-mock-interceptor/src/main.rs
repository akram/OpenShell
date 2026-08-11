// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use openshell_core::proto::gateway_interceptor::v1::{
    gateway_interceptor_server::{GatewayInterceptor, GatewayInterceptorServer},
    interceptor_evaluation::Phase, DescribeRequest, GatewayInterceptorPhase,
    InterceptorBinding, InterceptorEvaluation, InterceptorManifest, InterceptorResult,
    InterceptorSelector, JsonPatch, ProviderProfileSnapshot,
    ProviderProfileSnapshotRequest,
};
use prost_types::{Struct, Value as ProtoValue, value::Kind};
use serde_json::{Value, json};
use tonic::transport::Server;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

#[derive(Parser)]
struct Args {
    #[arg(long, default_value = "127.0.0.1:18082")]
    listen: SocketAddr,

    #[arg(long, default_value = "policy.yaml")]
    policy: PathBuf,
}

struct NetworkPolicyMockInterceptor {
    org_network_policy: Value,
    allowed_hosts: Vec<String>,
}

impl NetworkPolicyMockInterceptor {
    fn new(policy_path: &std::path::Path) -> anyhow::Result<Self> {
        let content = std::fs::read_to_string(policy_path)?;
        let policy: Value = serde_yml::from_str(&content)?;

        let allowed_hosts: Vec<String> = policy
            .get("network_policies")
            .and_then(|np| np.as_object())
            .map(|policies| {
                policies
                    .values()
                    .filter_map(|p| p.get("endpoints"))
                    .filter_map(|e| e.as_array())
                    .flat_map(|endpoints| {
                        endpoints
                            .iter()
                            .filter_map(|ep| ep.get("host"))
                            .filter_map(|h| h.as_str())
                            .map(String::from)
                    })
                    .collect()
            })
            .unwrap_or_default();

        info!(
            hosts = ?allowed_hosts,
            "loaded org network policy with {} allowed hosts",
            allowed_hosts.len()
        );

        Ok(Self {
            org_network_policy: policy,
            allowed_hosts,
        })
    }

    fn manifest(&self) -> InterceptorManifest {
        InterceptorManifest {
            name: "network-policy-mock".to_string(),
            failure_policy: "fail_open".to_string(),
            provider_profiles: false,
            bindings: vec![
                binding(
                    "inject-network-policy",
                    "CreateSandbox",
                    &[
                        GatewayInterceptorPhase::ModifyOperation,
                        GatewayInterceptorPhase::PostCommit,
                    ],
                ),
                binding(
                    "validate-network-policy",
                    "UpdateConfig",
                    &[
                        GatewayInterceptorPhase::Validate,
                        GatewayInterceptorPhase::PostCommit,
                    ],
                ),
                binding(
                    "audit-policy-analysis",
                    "SubmitPolicyAnalysis",
                    &[GatewayInterceptorPhase::Validate],
                ),
            ],
        }
    }

    fn evaluate_inner(
        &self,
        evaluation: &InterceptorEvaluation,
    ) -> Result<InterceptorResult, Status> {
        let phase = evaluation
            .phase
            .as_ref()
            .ok_or_else(|| Status::invalid_argument("missing phase"))?;

        match (evaluation.method.as_str(), phase) {
            ("CreateSandbox", Phase::ModifyOperation(modify)) => {
                let operation = modify
                    .proposed_operation
                    .as_ref()
                    .map(struct_to_json)
                    .unwrap_or_default();
                self.patch_network_policy(&operation)
            }
            ("CreateSandbox", Phase::PostCommit(post)) => {
                let response = post
                    .committed_response
                    .as_ref()
                    .map(struct_to_json)
                    .unwrap_or_default();
                let name = response
                    .get("name")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                let sandbox_id = response
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                info!(
                    sandbox = name,
                    sandbox_id,
                    allowed_endpoints = self.allowed_hosts.len(),
                    "sandbox created with org network policy"
                );
                let mut annotations = HashMap::new();
                annotations.insert(
                    "network_policy_action".to_string(),
                    format!("injected org network policy into sandbox '{name}'"),
                );
                annotations.insert("sandbox_id".to_string(), sandbox_id.to_string());
                annotations.insert(
                    "allowed_endpoint_count".to_string(),
                    self.allowed_hosts.len().to_string(),
                );
                annotations.insert(
                    "allowed_hosts".to_string(),
                    self.allowed_hosts.join(", "),
                );
                Ok(InterceptorResult {
                    allowed: true,
                    reason: String::new(),
                    status_code: String::new(),
                    patches: Vec::new(),
                    log_annotations: annotations,
                })
            }
            ("UpdateConfig", Phase::Validate(validate)) => {
                let operation = validate
                    .proposed_operation
                    .as_ref()
                    .map(struct_to_json)
                    .unwrap_or_default();
                self.validate_network_policy_update(&operation, &evaluation.principal)
            }
            ("UpdateConfig", Phase::PostCommit(_)) => {
                info!("policy update committed");
                Ok(allow())
            }
            ("SubmitPolicyAnalysis", Phase::Validate(validate)) => {
                let operation = validate
                    .proposed_operation
                    .as_ref()
                    .map(struct_to_json)
                    .unwrap_or_default();
                let sandbox_id = operation
                    .get("sandboxId")
                    .and_then(|v| v.as_str())
                    .unwrap_or("unknown");
                info!(sandbox_id, "policy analysis submitted — allowing for audit");
                Ok(allow_with_log(
                    "network_policy_action",
                    &format!("policy analysis submitted for sandbox '{sandbox_id}'"),
                ))
            }
            _ => Ok(allow()),
        }
    }

    fn patch_network_policy(
        &self,
        operation: &Value,
    ) -> Result<InterceptorResult, Status> {
        let sandbox_name = operation
            .get("name")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");

        info!(
            sandbox = sandbox_name,
            hosts = ?self.allowed_hosts,
            "injecting org network policy into CreateSandbox"
        );

        let network_policies_json = self
            .org_network_policy
            .get("network_policies")
            .cloned()
            .unwrap_or(json!({}));

        let mut patches = Vec::new();

        let has_spec = operation.get("spec").is_some_and(Value::is_object);
        let has_policy = has_spec
            && operation
                .get("spec")
                .and_then(|v| v.get("policy"))
                .is_some_and(Value::is_object);

        if has_policy {
            patches.push(JsonPatch {
                op: "add".to_string(),
                path: "/spec/policy/networkPolicies".to_string(),
                value: Some(json_to_proto_value(&network_policies_json)),
                from: String::new(),
            });
        } else if has_spec {
            patches.push(JsonPatch {
                op: "add".to_string(),
                path: "/spec/policy".to_string(),
                value: Some(json_to_proto_value(&json!({
                    "networkPolicies": network_policies_json
                }))),
                from: String::new(),
            });
        } else {
            patches.push(JsonPatch {
                op: "add".to_string(),
                path: "/spec".to_string(),
                value: Some(json_to_proto_value(&json!({
                    "policy": {
                        "networkPolicies": network_policies_json
                    }
                }))),
                from: String::new(),
            });
        }

        let mut annotations = HashMap::new();
        annotations.insert(
            "network_policy_action".to_string(),
            format!(
                "injected org network policy: allowed hosts = {:?}",
                self.allowed_hosts
            ),
        );
        annotations.insert(
            "correlation_id".to_string(),
            format!("network-policy:create-sandbox:{sandbox_name}"),
        );

        Ok(InterceptorResult {
            allowed: true,
            reason: String::new(),
            status_code: String::new(),
            patches,
            log_annotations: annotations,
        })
    }

    fn validate_network_policy_update(
        &self,
        operation: &Value,
        principal: &HashMap<String, String>,
    ) -> Result<InterceptorResult, Status> {
        let user = principal.get("subject").map(|s| s.as_str()).unwrap_or("unknown");

        info!(
            user,
            operation_keys = ?operation.as_object().map(|m| m.keys().collect::<Vec<_>>()),
            "validating network policy update"
        );

        let merge_ops = operation.get("mergeOperations");
        let policy = operation.get("policy");
        let spec = operation.get("spec");

        // Direct policy field (full policy set)
        if let Some(policy_val) = policy {
            if let Some(network_policies) = policy_val.get("networkPolicies") {
                return self.check_endpoints_allowed(network_policies, user);
            }
        }

        // spec.policy.networkPolicies (some UpdateConfig variants)
        if let Some(spec_val) = spec {
            if let Some(network_policies) = spec_val
                .get("policy")
                .and_then(|p| p.get("networkPolicies"))
            {
                return self.check_endpoints_allowed(network_policies, user);
            }
        }

        // mergeOperations — log structure and search recursively
        if let Some(merge_val) = merge_ops {
            info!(
                user,
                merge_structure = %merge_val,
                "inspecting mergeOperations"
            );
            if let Some(arr) = merge_val.as_array() {
                for (i, op) in arr.iter().enumerate() {
                    info!(
                        user,
                        merge_op_index = i,
                        merge_op_keys = ?op.as_object().map(|m| m.keys().collect::<Vec<_>>()),
                        "inspecting merge operation"
                    );
                    // Try op.policy.networkPolicies
                    if let Some(network_policies) = op
                        .get("policy")
                        .and_then(|p| p.get("networkPolicies"))
                    {
                        return self.check_endpoints_allowed(network_policies, user);
                    }
                    // Try op.networkPolicies directly
                    if let Some(network_policies) = op.get("networkPolicies") {
                        return self.check_endpoints_allowed(network_policies, user);
                    }
                    // addRule.rule.endpoints — used by `policy update --add-endpoint`
                    if let Some(rule) = op
                        .get("addRule")
                        .and_then(|ar| ar.get("rule"))
                    {
                        if let Some(endpoints) = rule.get("endpoints").and_then(|e| e.as_array()) {
                            for endpoint in endpoints {
                                if let Some(host) = endpoint.get("host").and_then(|h| h.as_str()) {
                                    if !self.allowed_hosts.iter().any(|h| h == host) {
                                        warn!(
                                            user,
                                            unauthorized_host = host,
                                            "DENIED: merge operation adds unauthorized endpoint"
                                        );
                                        let reason = format!(
                                            "host '{host}' is not in the organisation's \
                                             allowed endpoint list: {:?}",
                                            self.allowed_hosts
                                        );
                                        let mut annotations = HashMap::new();
                                        annotations.insert("network_policy_action".to_string(), "DENIED".to_string());
                                        annotations.insert("denied_host".to_string(), host.to_string());
                                        annotations.insert("denied_user".to_string(), user.to_string());
                                        return Ok(InterceptorResult {
                                            allowed: false,
                                            reason,
                                            status_code: "PERMISSION_DENIED".to_string(),
                                            patches: Vec::new(),
                                            log_annotations: annotations,
                                        });
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Check all nested fields for networkPolicies as a catch-all
        if let Some(obj) = operation.as_object() {
            for (key, val) in obj {
                if let Some(network_policies) = val.get("networkPolicies") {
                    info!(user, parent_key = key.as_str(), "found networkPolicies in nested field");
                    return self.check_endpoints_allowed(network_policies, user);
                }
            }
        }

        info!(user, "policy update with no network policy changes — allowing");
        Ok(allow())
    }

    fn check_endpoints_allowed(
        &self,
        network_policies: &Value,
        user: &str,
    ) -> Result<InterceptorResult, Status> {
        if let Some(policies) = network_policies.as_object() {
            for (name, policy) in policies {
                if let Some(endpoints) = policy.get("endpoints").and_then(|e| e.as_array()) {
                    for endpoint in endpoints {
                        if let Some(host) = endpoint.get("host").and_then(|h| h.as_str()) {
                            if !self.allowed_hosts.iter().any(|h| h == host) {
                                warn!(
                                    user,
                                    policy_name = name.as_str(),
                                    unauthorized_host = host,
                                    "DENIED: user attempted to add unauthorized endpoint"
                                );
                                let reason = format!(
                                    "host '{host}' in policy '{name}' is not in the \
                                     organisation's allowed endpoint list: {:?}",
                                    self.allowed_hosts
                                );
                                let mut annotations = HashMap::new();
                                annotations.insert(
                                    "network_policy_action".to_string(),
                                    "DENIED".to_string(),
                                );
                                annotations.insert(
                                    "denied_host".to_string(),
                                    host.to_string(),
                                );
                                annotations.insert(
                                    "denied_policy".to_string(),
                                    name.clone(),
                                );
                                annotations.insert(
                                    "denied_user".to_string(),
                                    user.to_string(),
                                );
                                return Ok(InterceptorResult {
                                    allowed: false,
                                    reason,
                                    status_code: "PERMISSION_DENIED".to_string(),
                                    patches: Vec::new(),
                                    log_annotations: annotations,
                                });
                            }
                        }
                    }
                }
            }
        }

        info!(user, "network policy update validated — all endpoints allowed");
        Ok(allow_with_log(
            "network_policy_action",
            &format!("network policy update validated for user '{user}'"),
        ))
    }
}

#[tonic::async_trait]
impl GatewayInterceptor for NetworkPolicyMockInterceptor {
    async fn describe(
        &self,
        _request: Request<DescribeRequest>,
    ) -> Result<Response<InterceptorManifest>, Status> {
        Ok(Response::new(self.manifest()))
    }

    async fn evaluate(
        &self,
        request: Request<InterceptorEvaluation>,
    ) -> Result<Response<InterceptorResult>, Status> {
        let result = self.evaluate_inner(request.get_ref())?;
        Ok(Response::new(result))
    }

    async fn snapshot_provider_profiles(
        &self,
        _request: Request<ProviderProfileSnapshotRequest>,
    ) -> Result<Response<ProviderProfileSnapshot>, Status> {
        Ok(Response::new(ProviderProfileSnapshot {
            revision: String::new(),
            profiles: Vec::new(),
        }))
    }
}

fn binding(id: &str, method: &str, phases: &[GatewayInterceptorPhase]) -> InterceptorBinding {
    InterceptorBinding {
        id: id.to_string(),
        selector: Some(InterceptorSelector {
            rpc: format!("openshell.v1.OpenShell/{method}"),
            service: String::new(),
            method: String::new(),
        }),
        phases: phases.iter().map(|p| *p as i32).collect(),
        failure_policy: String::new(),
    }
}

fn allow() -> InterceptorResult {
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn allow_with_log(key: &str, value: &str) -> InterceptorResult {
    let mut annotations = HashMap::new();
    annotations.insert(key.to_string(), value.to_string());
    InterceptorResult {
        allowed: true,
        reason: String::new(),
        status_code: String::new(),
        patches: Vec::new(),
        log_annotations: annotations,
    }
}

fn deny(reason: &str) -> InterceptorResult {
    InterceptorResult {
        allowed: false,
        reason: reason.to_string(),
        status_code: "PERMISSION_DENIED".to_string(),
        patches: Vec::new(),
        log_annotations: HashMap::new(),
    }
}

fn struct_to_json(s: &Struct) -> Value {
    let mut map = serde_json::Map::new();
    for (key, value) in &s.fields {
        map.insert(key.clone(), proto_value_to_json(value));
    }
    Value::Object(map)
}

fn proto_value_to_json(v: &ProtoValue) -> Value {
    match &v.kind {
        Some(Kind::NullValue(_)) => Value::Null,
        Some(Kind::NumberValue(n)) => {
            if let Some(i) = serde_json::Number::from_f64(*n) {
                Value::Number(i)
            } else {
                Value::Null
            }
        }
        Some(Kind::StringValue(s)) => Value::String(s.clone()),
        Some(Kind::BoolValue(b)) => Value::Bool(*b),
        Some(Kind::StructValue(s)) => struct_to_json(s),
        Some(Kind::ListValue(list)) => {
            Value::Array(list.values.iter().map(proto_value_to_json).collect())
        }
        None => Value::Null,
    }
}

fn json_to_proto_value(v: &Value) -> ProtoValue {
    match v {
        Value::Null => ProtoValue {
            kind: Some(Kind::NullValue(0)),
        },
        Value::Bool(b) => ProtoValue {
            kind: Some(Kind::BoolValue(*b)),
        },
        Value::Number(n) => ProtoValue {
            kind: Some(Kind::NumberValue(n.as_f64().unwrap_or(0.0))),
        },
        Value::String(s) => ProtoValue {
            kind: Some(Kind::StringValue(s.clone())),
        },
        Value::Array(arr) => ProtoValue {
            kind: Some(Kind::ListValue(prost_types::ListValue {
                values: arr.iter().map(json_to_proto_value).collect(),
            })),
        },
        Value::Object(map) => {
            let fields = map
                .iter()
                .map(|(k, v)| (k.clone(), json_to_proto_value(v)))
                .collect();
            ProtoValue {
                kind: Some(Kind::StructValue(Struct { fields })),
            }
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let args = Args::parse();

    let policy_path = if args.policy.is_absolute() {
        args.policy.clone()
    } else {
        std::env::current_dir()?.join(&args.policy)
    };

    let service = NetworkPolicyMockInterceptor::new(&policy_path)?;

    info!(listen = %args.listen, "starting network policy mock interceptor");

    Server::builder()
        .add_service(GatewayInterceptorServer::new(service))
        .serve(args.listen)
        .await?;

    Ok(())
}
