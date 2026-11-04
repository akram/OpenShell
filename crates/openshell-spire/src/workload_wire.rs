// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Wire messages of the SPIFFE Workload API.
//!
//! Transcribed from `proto/spiffe/workload/workloadapi.proto` of
//! <https://github.com/spiffe/spiffe/blob/main/standards/SPIFFE_Workload_API.md>.
//! Only the messages for `FetchJWTSVID` and `FetchJWTBundles` are reproduced;
//! field numbers and types are unchanged.

use std::collections::HashMap;

pub const FETCH_JWT_SVID: &str = "/SpiffeWorkloadAPI/FetchJWTSVID";
pub const FETCH_JWT_BUNDLES: &str = "/SpiffeWorkloadAPI/FetchJWTBundles";

/// `JWTSVIDRequest`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtSvidRequest {
    #[prost(string, repeated, tag = "1")]
    pub audience: Vec<String>,
    #[prost(string, tag = "2")]
    pub spiffe_id: String,
}

/// `JWTSVID` (Workload API variant)
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtSvid {
    #[prost(string, tag = "1")]
    pub spiffe_id: String,
    #[prost(string, tag = "2")]
    pub svid: String,
}

/// `JWTSVIDResponse`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtSvidResponse {
    #[prost(message, repeated, tag = "1")]
    pub svids: Vec<JwtSvid>,
}

/// `JWTBundlesRequest`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtBundlesRequest {}

/// `JWTBundlesResponse`
#[derive(Clone, PartialEq, Eq, prost::Message)]
pub struct JwtBundlesResponse {
    #[prost(map = "string, bytes", tag = "1")]
    pub bundles: HashMap<String, Vec<u8>>,
}
