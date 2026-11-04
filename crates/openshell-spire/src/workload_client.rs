// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Client for the SPIFFE Workload API (standard, non-delegated).
//!
//! Connects to the Workload API socket exposed by the SPIRE agent (via CSI
//! driver or sidecar emptyDir) and fetches JWT-SVIDs for the calling workload.

use std::path::Path;

use openshell_core::token_grant_failure::{
    TokenGrantFailure, TokenGrantFailureKind, TokenGrantStage,
    WORKLOAD_IDENTITY_CALL_TIMEOUT as AGENT_CALL_TIMEOUT,
};

use crate::{configuration_failure, identity_rejected, workload_wire};

fn agent_failure(kind: TokenGrantFailureKind) -> TokenGrantFailure {
    TokenGrantFailure::new(kind, TokenGrantStage::WorkloadIdentity)
}

fn status_failure(status: &tonic::Status) -> TokenGrantFailure {
    agent_failure(match status.code() {
        tonic::Code::PermissionDenied | tonic::Code::Unauthenticated => {
            TokenGrantFailureKind::WorkloadIdentityRejected
        }
        tonic::Code::DeadlineExceeded => TokenGrantFailureKind::Timeout,
        tonic::Code::Unavailable => TokenGrantFailureKind::Unavailable,
        tonic::Code::InvalidArgument | tonic::Code::Unimplemented => {
            TokenGrantFailureKind::Configuration
        }
        _ => TokenGrantFailureKind::Unclassified,
    })
}

pub struct WorkloadApiClient {
    grpc: tonic::client::Grpc<tonic::transport::Channel>,
}

impl WorkloadApiClient {
    pub async fn connect(socket: &Path) -> Result<Self, TokenGrantFailure> {
        if !socket.is_absolute() {
            return Err(configuration_failure());
        }
        let endpoint =
            spiffe::transport::endpoint::Endpoint::parse(&format!("unix:{}", socket.display()))
                .map_err(|_| configuration_failure())?;
        let channel = tokio::time::timeout(
            AGENT_CALL_TIMEOUT,
            spiffe::transport::connector::connect(&endpoint),
        )
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
        .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))?;
        Ok(Self {
            grpc: tonic::client::Grpc::new(channel),
        })
    }

    /// Fetch a JWT-SVID for the given audience and optional SPIFFE ID.
    ///
    /// When `spiffe_id` is non-empty, the agent returns a SVID for that
    /// specific identity (the calling workload must have a matching
    /// registration entry). When empty, the agent returns the workload's
    /// default SVID.
    pub async fn fetch_jwt_svid(
        &mut self,
        request: workload_wire::JwtSvidRequest,
    ) -> Result<workload_wire::JwtSvidResponse, TokenGrantFailure> {
        tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
            self.ready().await?;
            self.grpc
                .unary(
                    tonic::Request::new(request),
                    http::uri::PathAndQuery::from_static(workload_wire::FETCH_JWT_SVID),
                    tonic_prost::ProstCodec::default(),
                )
                .await
                .map(tonic::Response::into_inner)
                .map_err(|status| status_failure(&status))
        })
        .await
        .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))?
    }

    /// The agent's current JWT bundle for `trust_domain`.
    pub async fn jwt_bundles(
        &mut self,
        trust_domain: &spiffe::TrustDomain,
    ) -> Result<spiffe::JwtBundleSet, TokenGrantFailure> {
        let response: workload_wire::JwtBundlesResponse =
            tokio::time::timeout(AGENT_CALL_TIMEOUT, async {
                self.ready().await?;
                let mut stream = self
                    .grpc
                    .server_streaming(
                        tonic::Request::new(workload_wire::JwtBundlesRequest {}),
                        http::uri::PathAndQuery::from_static(workload_wire::FETCH_JWT_BUNDLES),
                        tonic_prost::ProstCodec::default(),
                    )
                    .await
                    .map_err(|status| status_failure(&status))?
                    .into_inner();
                stream
                    .message()
                    .await
                    .map_err(|status| status_failure(&status))?
                    .ok_or_else(|| agent_failure(TokenGrantFailureKind::Unavailable))
            })
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Timeout))??;
        let jwks = response
            .bundles
            .get(&trust_domain.id_string())
            .ok_or_else(identity_rejected)?;
        let bundle = spiffe::JwtBundle::from_jwt_authorities(trust_domain.clone(), jwks)
            .map_err(|_| identity_rejected())?;
        let mut bundles = spiffe::JwtBundleSet::new();
        bundles.add_bundle(bundle);
        Ok(bundles)
    }

    async fn ready(&mut self) -> Result<(), TokenGrantFailure> {
        self.grpc
            .ready()
            .await
            .map_err(|_| agent_failure(TokenGrantFailureKind::Unavailable))
    }
}
