// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

/// Select the crypto backend before any TLS/JWT/credential code can run.
/// `default_context()` otherwise lazily falls back to AWS-LC on first use
/// whenever the `aws-lc` feature is compiled in, even if `openssl` is also
/// available; without this call a crypto-openssl build silently stays on
/// AWS-LC instead of using the backend it was built to select.
#[cfg(feature = "crypto-openssl")]
fn install_crypto_backend() -> miette::Result<()> {
    openshell_crypto::install_default_context(openshell_crypto::CryptoContext::new(Box::new(
        openshell_crypto::OpenSsl,
    )))
    .map_err(|err| miette::miette!("failed to install the OpenSSL crypto backend: {err}"))
}

#[cfg(not(feature = "crypto-openssl"))]
fn install_crypto_backend() -> miette::Result<()> {
    Ok(())
}

#[tokio::main]
async fn main() -> miette::Result<()> {
    install_crypto_backend()?;
    // Same reasoning as `install_crypto_backend`, for jsonwebtoken's own
    // process-wide `CryptoProvider`: without this, it lazily falls back to
    // whichever backend jsonwebtoken's own Cargo features select on first
    // use. Dependencies such as spiffe call `jsonwebtoken::decode` directly
    // and may run before this binary's own JWT code would otherwise trigger
    // that lazy install.
    openshell_crypto::install_jwt_provider();
    openshell_server::cli::run_cli_with_compute_drivers(
        openshell_gateway::install_default_compute_drivers(),
    )
    .await
}
