// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Startup selection of the gateway's sandbox identity provider.
//!
//! The provider broker depends only on
//! [`SandboxIdentityProvider`]; this module chooses the SPIRE adapter when
//! `[openshell.gateway.spiffe_delegation]` is configured.
use std::sync::Arc;

use openshell_core::config::{Config, SpiffeDelegationConfig};
use openshell_core::token_grant_failure::TokenGrantFailure;
use openshell_spiffe::SandboxIdentityProvider;

/// Check the delegation settings `config` enables without building them.
///
/// # Errors
///
/// Rejects delegation without gateway session JWTs and a positive session
/// TTL, and settings [`SpiffeDelegationConfig::validate`] rejects.
pub fn validate_config(config: &Config) -> Result<(), String> {
    enabled(config).map(drop)
}

/// The sandbox identity provider `config` enables, if any.
///
/// When `[openshell.gateway.spiffe_delegation]` is set, uses the SPIRE admin
/// socket for per-sandbox delegated SVIDs. Otherwise, falls back to the
/// workload API if a SPIFFE socket is available (e.g. via CSI on OpenShift),
/// using the gateway's own SVID for all exchanges.
///
/// # Errors
///
/// Rejects what [`validate_config`] rejects.
pub fn sandbox_identity_provider(
    config: &Config,
) -> Result<Option<Arc<dyn SandboxIdentityProvider<Error = TokenGrantFailure>>>, String> {
    if let Some(delegation) = enabled(config)? {
        let provider = openshell_spire::SpireDelegatedIdentity::new(delegation)?;
        tracing::info!("sandbox identity provider: SPIRE delegation (admin socket)");
        return Ok(Some(Arc::new(provider)));
    }
    if let Some(socket_path) = workload_api_socket_path() {
        let gateway_spiffe_id = gateway_spiffe_id_from_env()
            .ok_or("OPENSHELL_GATEWAY_SPIFFE_ID required for workload API identity fallback")?;
        tracing::info!(%socket_path, %gateway_spiffe_id,
            "sandbox identity provider: workload API (gateway-as-broker)");
        let provider = crate::workload_api_identity::WorkloadApiIdentity::new(
            socket_path,
            gateway_spiffe_id,
        );
        return Ok(Some(Arc::new(provider)));
    }
    Ok(None)
}

fn workload_api_socket_path() -> Option<String> {
    std::env::var("OPENSHELL_GATEWAY_SPIFFE_WORKLOAD_API_SOCKET")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

fn gateway_spiffe_id_from_env() -> Option<String> {
    std::env::var("OPENSHELL_GATEWAY_SPIFFE_ID")
        .ok()
        .filter(|v| !v.trim().is_empty())
}

/// Validated delegation settings, when delegation is enabled.
fn enabled(config: &Config) -> Result<Option<&SpiffeDelegationConfig>, String> {
    let Some(delegation) = &config.spiffe_delegation else {
        return Ok(None);
    };
    let jwt = config
        .gateway_jwt
        .as_ref()
        .ok_or("spiffe_delegation requires gateway session JWTs")?;
    delegation.validate(&jwt.gateway_id)?;
    if jwt.ttl_secs.is_none() {
        return Err("spiffe_delegation requires a positive gateway_jwt.ttl_secs".into());
    }
    Ok(Some(delegation))
}
