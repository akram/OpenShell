# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  stdenv,
  openssl_3_5,
}:

# Same pattern as z3.nix/aws-lc.nix: rebuild nixpkgs' OpenSSL against the
# toolchain's own stdenv (the glibc-2.28 one for x86_64-gnu/aarch64-gnu)
# instead of nixpkgs' native/default stdenv. Linking the gateway against the
# native build's OpenSSL mixes glibc ABIs: that OpenSSL expects symbols
# (e.g. __isoc23_strtol, only present from glibc 2.38) that the project's
# glibc-2.28 sysroot does not provide.
(openssl_3_5.override { inherit stdenv; }).overrideAttrs (old: {
  # This is a link-time dependency for the gateway build, not a package
  # we ship/validate standalone; skip OpenSSL's own (lengthy, FIPS
  # self-test-inclusive) test suite, same as z3.nix's doCheck = false.
  doCheck = false;
  doInstallCheck = false;
})
