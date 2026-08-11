# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Network Policy Mock Interceptor — Makefile
#
# Targets:
#   make build            Build the interceptor binary
#   make demo-local       Run the full demo locally (gateway + interceptor + test)
#   make demo-openshift   Run the demo on OpenShift
#   make demo-simulate    Run the self-contained simulation demo
#   make record           Record the simulation demo as mp4 (requires asciinema + agg + ffmpeg)
#   make clean            Stop all processes and remove artifacts

ROOT           := $(shell cd ../.. && pwd)
SCRIPT_DIR     := $(shell pwd)
INTERCEPTOR    := $(SCRIPT_DIR)/target/debug/network-policy-mock-interceptor
GATEWAY        := $(ROOT)/target/debug/openshell-gateway
CLI            := $(ROOT)/target/release/openshell
POLICY         := $(SCRIPT_DIR)/policy.yaml

GATEWAY_PORT   ?= 8098
INTERCEPTOR_PORT ?= 18082
GATEWAY_NAME   ?= local-test
SANDBOX_NAME   ?= policy-demo

TEST_DIR       := $(shell mktemp -d)
JWT_DIR        := $(TEST_DIR)/jwt

.PHONY: build demo-local demo-openshift demo-simulate record clean help

help: ## Show this help
	@grep -E '^[a-zA-Z_-]+:.*##' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*##"}; {printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

build: ## Build the interceptor binary
	cargo build --manifest-path $(SCRIPT_DIR)/Cargo.toml

build-gateway: ## Build the gateway with bundled Z3
	cd $(ROOT) && cargo build -p openshell-server --bin openshell-gateway --features bundled-z3

build-cli: ## Build the CLI with bundled Z3
	cd $(ROOT) && cargo build --release -p openshell-cli --features bundled-z3

demo-local: build ## Run the full demo locally (builds + starts gateway + interceptor + test)
	@echo ""
	@echo "\033[1;35m━━━ Network Policy Mock Interceptor — Local Demo ━━━\033[0m"
	@echo ""
	@# Generate JWT keys
	@mkdir -p $(JWT_DIR)
	@openssl genpkey -algorithm ed25519 -outform PEM -out $(JWT_DIR)/signing.pem 2>/dev/null
	@openssl pkey -in $(JWT_DIR)/signing.pem -pubout -out $(JWT_DIR)/public.pem 2>/dev/null
	@echo "test-kid-001" > $(JWT_DIR)/kid
	@# Write gateway config
	@printf '[openshell]\nversion = 1\n\n[openshell.gateway]\n\n[openshell.gateway.auth]\nallow_unauthenticated_users = true\n\n[openshell.gateway.gateway_jwt]\nsigning_key_path = "$(JWT_DIR)/signing.pem"\npublic_key_path = "$(JWT_DIR)/public.pem"\nkid_path = "$(JWT_DIR)/kid"\ngateway_id = "interceptor-test"\nttl_secs = 0\n\n[[openshell.gateway.interceptors]]\nname = "network-policy-mock"\ngrpc_endpoint = "http://127.0.0.1:$(INTERCEPTOR_PORT)"\norder = 10\nfailure_policy = "fail_open"\nbinding_policy = "allowlist"\ntimeout = "2s"\nmax_response_bytes = 1048576\nmax_patches = 32\n\n[[openshell.gateway.interceptors.bindings]]\nrpc = "openshell.v1.OpenShell/CreateSandbox"\nphases = ["modify_operation", "post_commit"]\n\n[[openshell.gateway.interceptors.bindings]]\nrpc = "openshell.v1.OpenShell/UpdateConfig"\nphases = ["validate", "post_commit"]\n\n[[openshell.gateway.interceptors.bindings]]\nrpc = "openshell.v1.OpenShell/SubmitPolicyAnalysis"\nphases = ["validate"]\n' > $(TEST_DIR)/gateway.toml
	@# Start interceptor
	@echo "\033[1;33mStarting interceptor...\033[0m"
	@$(INTERCEPTOR) --policy $(POLICY) --listen 127.0.0.1:$(INTERCEPTOR_PORT) > $(TEST_DIR)/interceptor.log 2>&1 & echo $$! > $(TEST_DIR)/interceptor.pid
	@sleep 1
	@# Start gateway
	@echo "\033[1;33mStarting gateway...\033[0m"
	@$(GATEWAY) --config $(TEST_DIR)/gateway.toml --bind-address 127.0.0.1 --port $(GATEWAY_PORT) --disable-tls --db-url "sqlite:$(TEST_DIR)/openshell.db" > $(TEST_DIR)/gateway.log 2>&1 & echo $$! > $(TEST_DIR)/gateway.pid
	@sleep 5
	@# Register gateway
	@$(CLI) gateway remove $(GATEWAY_NAME) 2>/dev/null || true
	@$(CLI) gateway add http://127.0.0.1:$(GATEWAY_PORT) --local --name $(GATEWAY_NAME) 2>/dev/null
	@echo ""
	@echo "\033[1;35m━━━ Step 1: Org Network Policy ━━━\033[0m"
	@cat $(POLICY)
	@echo ""
	@echo "\033[1;35m━━━ Step 2: Create Sandbox (policy injected) ━━━\033[0m"
	@$(CLI) --gateway $(GATEWAY_NAME) sandbox delete $(SANDBOX_NAME) 2>/dev/null || true
	@$(CLI) --gateway $(GATEWAY_NAME) sandbox create --name $(SANDBOX_NAME) --no-tty -- echo "sandbox ready"
	@echo ""
	@echo "\033[1;35m━━━ Step 3: Attempt Unauthorized Endpoint ━━━\033[0m"
	@$(CLI) --gateway $(GATEWAY_NAME) policy update $(SANDBOX_NAME) --add-endpoint "malicious.com:443:full:rest:enforce" 2>&1 || true
	@echo ""
	@echo "\033[1;35m━━━ Step 4: Audit Trail ━━━\033[0m"
	@echo "\033[1;33mGateway:\033[0m"
	@grep "interceptor evaluated" $(TEST_DIR)/gateway.log | sed 's/.*interceptor=/  interceptor=/' | tail -5
	@echo ""
	@echo "\033[1;33mInterceptor:\033[0m"
	@grep -E "injecting|DENIED|validated|committed" $(TEST_DIR)/interceptor.log | tail -5
	@echo ""
	@echo "\033[1;32m━━━ Demo Complete ━━━\033[0m"
	@echo ""
	@echo "Cleanup: make clean TEST_DIR=$(TEST_DIR)"

demo-openshift: ## Run the demo on OpenShift (requires oc login)
	bash $(SCRIPT_DIR)/openshift-demo.sh

demo-simulate: ## Run the self-contained simulation demo (no infra needed)
	bash $(SCRIPT_DIR)/simulation-demo.sh

record: ## Record the simulation demo as mp4
	@echo "Recording simulation demo..."
	@asciinema rec --command="bash $(SCRIPT_DIR)/simulation-demo.sh" /tmp/interceptor-demo.cast --overwrite
	@echo "Converting to gif..."
	@agg /tmp/interceptor-demo.cast /tmp/interceptor-demo.gif
	@echo "Converting to mp4..."
	@ffmpeg -y -i /tmp/interceptor-demo.gif -movflags faststart -pix_fmt yuv420p -vf "scale=trunc(iw/2)*2:trunc(ih/2)*2" $(SCRIPT_DIR)/demo.mp4
	@echo "Done: $(SCRIPT_DIR)/demo.mp4"

clean: ## Stop local interceptor + gateway processes
	@echo "Cleaning up local processes..."
	-@pkill -f "network-policy-mock-interceptor" 2>/dev/null || true
	-@pkill -f "openshell-gateway.*interceptor-test" 2>/dev/null || true
	-@pkill -f "port-forward.*$(INTERCEPTOR_PORT)" 2>/dev/null || true
	@echo "Done"

clean-openshift: ## Remove interceptor and sandbox from OpenShift
	@echo "Cleaning up OpenShift resources..."
	-@oc delete deployment network-policy-interceptor -n openshell 2>/dev/null || true
	-@oc delete svc network-policy-interceptor -n openshell 2>/dev/null || true
	-@openshell --gateway $(GATEWAY_NAME) sandbox delete $(SANDBOX_NAME) 2>/dev/null || true
	@echo "Done"

clean-all: clean clean-openshift ## Clean both local and OpenShift
