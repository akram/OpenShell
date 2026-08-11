# Network Policy Mock Interceptor

A simplified gateway interceptor that demonstrates organisation-level network
policy governance. It injects a mandated network policy into every sandbox and
rejects policy updates that add endpoints outside the organisation's allow list.

## What It Does

| Operation | Phase | Action |
|---|---|---|
| `CreateSandbox` | `modify_operation` | Patches the sandbox spec to include the org network policy |
| `CreateSandbox` | `post_commit` | Logs the sandbox name and confirms the policy was injected |
| `UpdateConfig` | `validate` | Rejects updates that add hosts not in the allow list |
| `UpdateConfig` | `post_commit` | Logs the policy update |
| `SubmitPolicyAnalysis` | `validate` | Allows but logs the analysis for audit |

## Organisation Policy

The interceptor loads `policy.yaml` at startup. The `network_policies` section
defines which endpoints sandboxes are allowed to reach:

```yaml
network_policies:
  company_api:
    endpoints:
      - host: api.company.com
        port: 443
      - host: auth.company.com
        port: 443
```

Any `UpdateConfig` that attempts to add an endpoint not in this list is denied
with `PERMISSION_DENIED`.

## Run

```shell
cargo run -- --listen 127.0.0.1:18082 --policy policy.yaml
```

## Configure the Gateway

Register the interceptor in the gateway config TOML:

```toml
[[openshell.gateway.interceptors]]
name = "network-policy-mock"
grpc_endpoint = "http://127.0.0.1:18082"
binding_policy = "allowlist"

[[openshell.gateway.interceptors.bindings]]
id = "inject-network-policy"
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
id = "validate-network-policy"
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
id = "audit-policy-analysis"
rpc = "openshell.v1.OpenShell/SubmitPolicyAnalysis"
phases = ["validate"]
```

## Demo Scenario

1. Start the interceptor and gateway
2. Create a sandbox — the org network policy is automatically injected
3. From inside the sandbox, `curl api.company.com` works (allowed by policy)
4. Try `openshell policy update` to add `malicious.com` — the interceptor rejects it
5. Check the gateway logs for audit annotations from the interceptor
