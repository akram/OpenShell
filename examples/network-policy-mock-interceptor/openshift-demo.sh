#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Live demo of the network policy mock interceptor on OpenShift.
#
# Prerequisites:
#   - oc logged in to an OpenShift cluster
#   - OpenShell gateway deployed in the 'openshell' namespace
#   - openshell CLI in PATH (built from the same branch as the gateway)
#   - Interceptor image built and available in openshell-images namespace
#
# The script:
#   1. Deploys the interceptor pod
#   2. Configures the gateway to use it
#   3. Creates a sandbox (policy injected)
#   4. Shows the effective network policy
#   5. Attempts an unauthorized policy update (DENIED)
#   6. Shows the audit trail
#   7. Cleans up

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NAMESPACE="${NAMESPACE:-openshell}"
IMAGES_NS="${IMAGES_NS:-openshell-images}"
REGISTRY="${REGISTRY:-image-registry.openshift-image-registry.svc:5000}"
SANDBOX_NAME="${SANDBOX_NAME:-policy-demo}"
GATEWAY_NAME="${GATEWAY_NAME:-rosa}"
PORT_FORWARD_PORT="${PORT_FORWARD_PORT:-8097}"

# mTLS certs are copied from the gateway's client-tls secret in Step 3.
# No --gateway-insecure needed when CLI and gateway share the same CA.

PF_PID=""

cleanup() {
    if [[ -n "$PF_PID" ]]; then
        kill "$PF_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

run() {
    printf "\n\033[1;32m$\033[0m %s\n" "$*"
    "$@"
}

title() {
    printf "\n\033[1;35m━━━ %s ━━━\033[0m\n\n" "$1"
}

wait_for_pod() {
    local label="$1"
    local ns="$2"
    printf "Waiting for pod %s..." "$label"
    for _ in $(seq 1 60); do
        if oc get pods -n "$ns" -l "$label" -o jsonpath='{.items[0].status.phase}' 2>/dev/null | grep -q Running; then
            printf " ready\n"
            return 0
        fi
        sleep 2
        printf "."
    done
    printf " timeout\n"
    return 1
}

OS=(openshell --gateway "$GATEWAY_NAME")

# ── Step 1: Deploy interceptor ────────────────────────────────────────

title "Step 1: Deploy the Network Policy Mock Interceptor"

printf "Deploying interceptor pod in namespace '%s'...\n" "$NAMESPACE"

oc apply -f - <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: network-policy-interceptor
  namespace: $NAMESPACE
spec:
  replicas: 1
  selector:
    matchLabels:
      app: network-policy-interceptor
  template:
    metadata:
      labels:
        app: network-policy-interceptor
    spec:
      containers:
        - name: interceptor
          image: ${REGISTRY}/${IMAGES_NS}/interceptor:latest
          ports:
            - containerPort: 18082
---
apiVersion: v1
kind: Service
metadata:
  name: network-policy-interceptor
  namespace: $NAMESPACE
spec:
  selector:
    app: network-policy-interceptor
  ports:
    - port: 18082
      targetPort: 18082
EOF

wait_for_pod "app=network-policy-interceptor" "$NAMESPACE"

run oc logs deployment/network-policy-interceptor -n "$NAMESPACE" --tail=3

# ── Step 2: Configure gateway ─────────────────────────────────────────

title "Step 2: Configure Gateway with Interceptor"

printf "Adding interceptor config to gateway TOML...\n"

INTERCEPTOR_CONFIG='
[[openshell.gateway.interceptors]]
name = "network-policy-mock"
grpc_endpoint = "http://network-policy-interceptor.'"$NAMESPACE"'.svc.cluster.local:18082"
order = 10
failure_policy = "fail_open"
binding_policy = "allowlist"
timeout = "2s"
max_response_bytes = 1048576
max_patches = 32

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/CreateSandbox"
phases = ["modify_operation", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/UpdateConfig"
phases = ["validate", "post_commit"]

[[openshell.gateway.interceptors.bindings]]
rpc = "openshell.v1.OpenShell/SubmitPolicyAnalysis"
phases = ["validate"]
'

oc get configmap openshell-config -n "$NAMESPACE" -o json | python3 -c "
import json, sys
cm = json.load(sys.stdin)
toml = cm['data']['gateway.toml']
if 'interceptors' not in toml:
    idx = toml.find('[openshell.drivers')
    if idx > 0:
        toml = toml[:idx] + '''$INTERCEPTOR_CONFIG''' + toml[idx:]
    else:
        toml += '''$INTERCEPTOR_CONFIG'''
    cm['data']['gateway.toml'] = toml
json.dump(cm, sys.stdout)
" | oc replace -f -

run oc rollout restart statefulset openshell -n "$NAMESPACE"
printf "Waiting for gateway to be ready..."
oc -n "$NAMESPACE" rollout status statefulset/openshell --timeout=120s 2>/dev/null
sleep 5

oc logs openshell-0 -n "$NAMESPACE" | grep "interceptors initialized" && \
    printf "\033[1;32m✓ Gateway connected to interceptor\033[0m\n" || \
    printf "\033[1;31m✗ Interceptor not initialized — check logs\033[0m\n"

# ── Step 3: Setup CLI ─────────────────────────────────────────────────

title "Step 3: Connect CLI"

# Fetch mTLS certs AFTER gateway restart (certs may have been regenerated)
openshell gateway remove "$GATEWAY_NAME" 2>/dev/null || true
mkdir -p ~/.config/openshell/gateways/${GATEWAY_NAME}/mtls
oc -n "$NAMESPACE" get secret openshell-client-tls -o jsonpath='{.data.ca\.crt}' | base64 -d > ~/.config/openshell/gateways/${GATEWAY_NAME}/mtls/ca.crt
oc -n "$NAMESPACE" get secret openshell-client-tls -o jsonpath='{.data.tls\.crt}' | base64 -d > ~/.config/openshell/gateways/${GATEWAY_NAME}/mtls/tls.crt
oc -n "$NAMESPACE" get secret openshell-client-tls -o jsonpath='{.data.tls\.key}' | base64 -d > ~/.config/openshell/gateways/${GATEWAY_NAME}/mtls/tls.key

# Start port-forward AFTER certs are fetched
pkill -f "port-forward.*${PORT_FORWARD_PORT}" 2>/dev/null || true
oc -n "$NAMESPACE" port-forward svc/openshell "${PORT_FORWARD_PORT}:8080" > /tmp/pf-demo.log 2>&1 &
PF_PID=$!
sleep 3

openshell gateway add "https://127.0.0.1:${PORT_FORWARD_PORT}" --local --name "$GATEWAY_NAME"

run "${OS[@]}" status

# ── Step 4: Create sandbox ────────────────────────────────────────────

title "Step 4: Create Sandbox (org policy will be injected by interceptor)"

"${OS[@]}" sandbox delete "$SANDBOX_NAME" 2>/dev/null || true

run "${OS[@]}" sandbox create --name "$SANDBOX_NAME" --keep --no-tty -- echo "sandbox ready"

# ── Step 5: Show effective policy ─────────────────────────────────────

title "Step 5: Effective Network Policy on the Sandbox"

printf "\033[1;33mThe interceptor injected the org network policy.\033[0m\n"
printf "Checking the effective policy on the sandbox:\n\n"

"${OS[@]}" policy get "$SANDBOX_NAME" --full 2>&1 || true

# ── Step 6: Attempt unauthorized policy change ────────────────────────

title "Step 6: Attempt Unauthorized Policy Change (should be DENIED)"

printf "Trying to add 'malicious.com:443' to the sandbox network policy...\n\n"

if "${OS[@]}" policy update "$SANDBOX_NAME" --add-endpoint "malicious.com:443:full:rest:enforce" 2>&1; then
    printf "\n\033[1;31mUNEXPECTED: policy update was allowed\033[0m\n"
else
    printf "\n\033[1;32m✓ Policy update correctly DENIED by interceptor\033[0m\n"
fi

# ── Step 7: Audit trail ──────────────────────────────────────────────

title "Step 7: Audit Trail"

printf "\033[1;33mGateway interceptor evaluations:\033[0m\n\n"
oc logs openshell-0 -n "$NAMESPACE" --since=300s 2>&1 | grep "interceptor evaluated" | \
    sed 's/.*interceptor=/  interceptor=/' | \
    sed 's/\x1b\[[0-9;]*m//g' | \
    tail -10

printf "\n\033[1;33mInterceptor pod logs:\033[0m\n\n"
oc logs deployment/network-policy-interceptor -n "$NAMESPACE" --since=300s 2>&1 | \
    grep -iE "injecting|created|DENIED|validated|committed|allowing" | \
    sed 's/\x1b\[[0-9;]*m//g'

# ── Step 8: Show sandbox pod ──────────────────────────────────────────

title "Step 8: Sandbox Pod"

oc get pods -n "$NAMESPACE" | grep -E "NAME|$SANDBOX_NAME|interceptor"

# ── Done ──────────────────────────────────────────────────────────────

title "Demo Complete"

cat <<EOF
What happened:
  1. The interceptor injected the org network policy into sandbox '$SANDBOX_NAME'
  2. The sandbox can only reach api.company.com and auth.company.com
  3. An attempt to add malicious.com was DENIED by the interceptor
  4. The gateway logged audit annotations with correlation IDs

Cleanup:
  ${OS[*]} sandbox delete $SANDBOX_NAME
  oc delete deployment network-policy-interceptor -n $NAMESPACE
  oc delete svc network-policy-interceptor -n $NAMESPACE
EOF
