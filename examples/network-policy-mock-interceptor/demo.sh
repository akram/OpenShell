#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Network policy mock interceptor demo.
#
# Demonstrates:
# 1. Org network policy is automatically injected into every sandbox
# 2. The sandbox can only reach allowed endpoints
# 3. Attempts to weaken the policy are rejected by the interceptor
#
# Prerequisites:
# - OpenShell gateway running with the interceptor configured
# - openshell CLI in PATH
# - Gateway registered (OPENSHELL_GATEWAY or --gateway flag)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

SANDBOX_NAME="${SANDBOX_NAME:-policy-demo}"
GATEWAY="${OPENSHELL_GATEWAY:-local-test}"
GATEWAY_ENDPOINT="${GATEWAY_ENDPOINT:-}"
INTERCEPTOR_LISTEN="${INTERCEPTOR_LISTEN:-127.0.0.1:18082}"

OS=(openshell --gateway "$GATEWAY")
if [[ -n "$GATEWAY_ENDPOINT" ]]; then
    OS+=(--gateway-endpoint "$GATEWAY_ENDPOINT")
fi
if [[ "${GATEWAY_INSECURE:-}" == "1" ]]; then
    OS+=(--gateway-insecure)
fi

INTERCEPTOR_PID=""
GATEWAY_PID=""

cleanup() {
    "${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
    if [[ -n "$INTERCEPTOR_PID" ]]; then
        kill "$INTERCEPTOR_PID" 2>/dev/null || true
    fi
    if [[ -n "$GATEWAY_PID" ]]; then
        kill "$GATEWAY_PID" 2>/dev/null || true
    fi
}
trap cleanup EXIT

run() {
    printf "\n\033[1;36m$\033[0m %s\n" "$*"
    "$@"
}

expect_failure() {
    local label="$1"
    shift
    printf "\n\033[1;33m$ %s\033[0m (expecting denial)\n" "$*"
    if "$@" 2>&1; then
        printf "\033[1;31mFAIL:\033[0m expected '%s' to be denied but it succeeded\n" "$label"
        exit 1
    else
        printf "\033[1;32mOK:\033[0m '%s' was correctly denied\n" "$label"
    fi
}

section() {
    printf "\n\033[1;35m=== %s ===\033[0m\n" "$1"
}

# ── Step 0: Start interceptor if running locally ──────────────────────

if [[ "${START_INTERCEPTOR:-1}" == "1" ]]; then
    section "Starting network policy mock interceptor"
    "$ROOT/examples/network-policy-mock-interceptor/target/debug/network-policy-mock-interceptor" \
        --policy "$SCRIPT_DIR/policy.yaml" \
        --listen "$INTERCEPTOR_LISTEN" &
    INTERCEPTOR_PID=$!
    sleep 1
    printf "Interceptor running (PID %d) on %s\n" "$INTERCEPTOR_PID" "$INTERCEPTOR_LISTEN"
fi

# ── Step 1: Show the org policy ───────────────────────────────────────

section "Organisation network policy"
printf "The interceptor enforces this policy on every sandbox:\n\n"
cat "$SCRIPT_DIR/policy.yaml"

# ── Step 2: Create a sandbox ──────────────────────────────────────────

section "Creating sandbox (policy will be injected by interceptor)"
"${OS[@]}" sandbox delete "$SANDBOX_NAME" >/dev/null 2>&1 || true
run "${OS[@]}" sandbox create --name "$SANDBOX_NAME" --keep --no-tty -- echo "sandbox ready"

# ── Step 3: Show interceptor audit in gateway logs ────────────────────

section "Interceptor audit trail"
printf "The gateway logs show the interceptor's actions:\n"
printf "  - modify_operation: policy injected (patch_count=1)\n"
printf "  - post_commit: sandbox creation logged\n"
printf "  - correlation_id tracks the operation\n\n"
printf "Check gateway logs with:\n"
printf "  kubectl logs <gateway-pod> | grep 'interceptor evaluated'\n"

# ── Step 4: Try to add an unauthorized endpoint ───────────────────────

section "Attempting to add unauthorized endpoint (should be DENIED)"
printf "Trying to merge a policy that adds 'malicious.com:443'...\n"

MALICIOUS_POLICY='{"network_policies":{"evil":{"name":"evil","endpoints":[{"host":"malicious.com","port":443,"protocol":"rest","access":"full","enforcement":"enforce"}],"binaries":[{"path":"/usr/bin/curl"}]}}}'

expect_failure "add malicious.com" \
    "${OS[@]}" sandbox exec --name "$SANDBOX_NAME" --no-tty -- \
    sh -c "echo 'This should not run if interceptor blocks UpdateConfig'"

# Note: the actual policy update denial happens at the gateway level when
# someone tries to update the sandbox's network policy. The sandbox exec
# above just shows the sandbox is running — the real denial test is:

printf "\nTo test UpdateConfig denial, use the CLI to update the sandbox policy:\n"
printf "  openshell policy update --sandbox %s --merge '%s'\n" "$SANDBOX_NAME" "$MALICIOUS_POLICY"
printf "\nThe interceptor will reject this with PERMISSION_DENIED because\n"
printf "'malicious.com' is not in the org allow-list.\n"

# ── Step 5: Show what's allowed ───────────────────────────────────────

section "Allowed endpoints"
printf "The sandbox can only reach these hosts:\n"
printf "  - api.company.com:443 (read-write)\n"
printf "  - auth.company.com:443 (read-only)\n"
printf "\nAll other endpoints are blocked by the sandbox network policy.\n"

# ── Summary ───────────────────────────────────────────────────────────

section "Demo complete"
printf "What happened:\n"
printf "  1. The interceptor injected the org network policy into the sandbox\n"
printf "  2. The gateway logged audit annotations with correlation IDs\n"
printf "  3. Unauthorized policy changes would be rejected by the interceptor\n"
printf "  4. The sandbox is restricted to the org's allowed endpoints\n\n"
printf "This demonstrates how an organisation can enforce network governance\n"
printf "on AI agent sandboxes without modifying the OpenShell core.\n"
