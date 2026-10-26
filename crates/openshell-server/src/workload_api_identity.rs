// SPDX-FileCopyrightText: Copyright (c) 2026 Red Hat, Inc.
// SPDX-License-Identifier: Apache-2.0

//! Workload API-based sandbox identity provider for OpenShift deployments.
//!
//! When SPIRE delegation is not available (no admin socket, e.g. on OpenShift
//! where hostPath is restricted by SCCs), the gateway can still act as a token
//! exchange broker by presenting its own JWT-SVID from the workload API.
//!
//! The gateway authenticates as itself for all sandbox exchanges. Keycloak
//! authorizes the gateway via FGAP policies. The sandbox identity is carried
//! through the subject_token chain, not through per-sandbox SVIDs.

use base64::Engine as _;
use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
};
use openshell_spiffe::{SandboxIdentityProvider, SandboxJwtSvid};

/// Uses the SPIFFE Workload API (CSI-mounted socket) to return the gateway's
/// own JWT-SVID for any sandbox. Both exchange stages use the gateway identity.
#[derive(Debug)]
pub struct WorkloadApiIdentity {
    socket_path: String,
    gateway_spiffe_id: String,
}

impl WorkloadApiIdentity {
    pub fn new(socket_path: String, gateway_spiffe_id: String) -> Self {
        Self {
            socket_path,
            gateway_spiffe_id,
        }
    }
}

#[async_trait::async_trait]
impl SandboxIdentityProvider for WorkloadApiIdentity {
    type Error = TokenGrantFailure;

    async fn fetch_jwt_svid(
        &self,
        _gateway_id: &str,
        _sandbox_id: &str,
        audience: &str,
    ) -> Result<SandboxJwtSvid, TokenGrantFailure> {
        let endpoint = openshell_spiffe::workload_api_endpoint(
            std::path::Path::new(&self.socket_path),
        );
        let client = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            spiffe::WorkloadApiClient::connect_to(&endpoint)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| timeout())?
        .map_err(|_| unavailable())?;

        let token = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            client
                .fetch_jwt_token([audience], None)
                .await
                .map_err(|_| unavailable())
        })
        .await
        .map_err(|_| timeout())?
        .map_err(|_| unavailable())?;

        let exp = extract_exp(&token).unwrap_or(0);

        Ok(SandboxJwtSvid {
            spiffe_id: self.gateway_spiffe_id.clone(),
            token,
            expires_at: exp,
        })
    }
}

fn extract_exp(token: &str) -> Option<i64> {
    let payload = token.split('.').nth(1)?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload)
        .ok()?;
    let claims: serde_json::Value = serde_json::from_slice(&decoded).ok()?;
    claims["exp"].as_i64()
}

fn unavailable() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Unavailable,
        TokenGrantStage::WorkloadIdentity,
    )
}

fn timeout() -> TokenGrantFailure {
    TokenGrantFailure::new(
        TokenGrantFailureKind::Timeout,
        TokenGrantStage::WorkloadIdentity,
    )
}
