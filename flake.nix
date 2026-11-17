# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

{
  description = "OpenShell development environment";

  nixConfig = {
    extra-substituters = [ "https://openshell.cachix.org" ];
    extra-trusted-public-keys = [
      "openshell.cachix.org-1:OAr5MunsfH5PZvUsfD08OtGx5RtcwdNZGJdU5FqLm5w="
    ];
  };

  inputs = {
    flake-utils.url = "github:numtide/flake-utils";
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    # Keep the QEMU and OVMF runtime used by Apple Silicon test guests on a
    # known-good release. Development shells and cross toolchains use nixpkgs.
    nixpkgs-test-guest.url = "github:NixOS/nixpkgs/0954f7ee2f6bb3dc7d4e3d0d8bcb8fd4bde4cfc5";
    rust-overlay = {
      url = "github:oxalica/rust-overlay";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    treefmt-nix = {
      url = "github:numtide/treefmt-nix";
      inputs.nixpkgs.follows = "nixpkgs";
    };

  };

  outputs =
    {
      flake-utils,
      nixpkgs,
      nixpkgs-test-guest,
      treefmt-nix,
      rust-overlay,
      ...
    }:
    flake-utils.lib.eachSystem [ "x86_64-linux" "aarch64-linux" "aarch64-darwin" ] (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
          overlays = [ (import rust-overlay) ];
        };
        testGuestPkgs = import nixpkgs-test-guest { inherit system; };
        tmachineRuntimePkgs = if pkgs.stdenv.hostPlatform.isDarwin then testGuestPkgs else pkgs;
        commonDevShellPackages = with pkgs; [
          actionlint
          cargo-auditable
          cargo-deny
          cargo-nextest
          # Assemble Debian artifacts on macOS and Linux.
          dpkg
          # Build and inspect ext4 images in VM driver tests.
          e2fsprogs
          git
          # Required to find packages.
          pkg-config
          # Coverage.
          lcov
          # mise dependencies
          mise
          cmakeMinimal
          zlib
          openssl_3_5
          xz
          gh
          kubernetes-helm
          syft
          trivy
          uv
          yq-go
          zizmor
          zstd
          buf
        ];
        commonDevShell = {
          packages = [ rustToolchain ] ++ commonDevShellPackages;
          env = pkgs.lib.foldl' (env: toolchain: env // toolchain.env) { } (builtins.attrValues toolchains);
        };
        treefmtEval = treefmt-nix.lib.evalModule pkgs {
          projectRootFile = "flake.nix";
          programs.nixfmt.enable = true;
        };
        rustToolchain =
          ((pkgs.rust-bin.fromRustupToolchainFile ./rust-toolchain.toml).override {
            targets = map (toolchain: toolchain.target) (builtins.attrValues toolchains);
          }).overrideAttrs
            {
              propagatedBuildInputs = [ ];
              depsHostHostPropagated = [ ];
              depsTargetTargetPropagated = [ ];
            };
        buildInputs = { pkgs, stdenv }: [
          (pkgs.callPackage ./nix/pkgs/z3.nix { inherit stdenv; })
          (pkgs.callPackage ./nix/pkgs/aws-lc.nix { inherit stdenv; })
        ];
        # Same cross sysroots, minus aws-lc.nix. The release toolchains above
        # bake an unprefixed AWS-LC libcrypto/libssl shim straight into each
        # target's --sysroot (via aws-lc.nix), so it sits on the linker's
        # default search path for every build regardless of Cargo feature
        # selection. That's fine for the default crypto-aws-lc build, but it
        # silently satisfies most of the real `openssl` crate's link
        # requirements with AWS-LC's compat shim instead, which exposes
        # several OpenSSL-3-only symbols (the ASN1_ITEM accessors among them)
        # with an incompatible type (STT_OBJECT vs. OpenSSL 3.x's STT_FUNC),
        # so the linker errors on duplicate, type-mismatched definitions once
        # the real OpenSSL 3.5 is also linked in. These openssl toolchains
        # keep z3 (the gateway binary needs it regardless of crypto backend)
        # but drop aws-lc.nix, so the devShells.crypto shell below links
        # cleanly against only the OpenSSL it's pointed at.
        opensslBuildInputs = { pkgs, stdenv }: [
          (pkgs.callPackage ./nix/pkgs/z3.nix { inherit stdenv; })
          (pkgs.callPackage ./nix/pkgs/openssl.nix { inherit stdenv; })
        ];
        inherit (import ./nix/toolchain) mkToolchain;
        toolchains = {
          x86_64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.gnu64;
            inherit buildInputs;
          };
          x86_64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.musl64;
            inherit buildInputs;
          };
          aarch64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform;
            inherit buildInputs;
          };
          aarch64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            inherit buildInputs;
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          aarch64-darwin = mkToolchain {
            inherit pkgs buildInputs;
          };
        };
        opensslToolchains = {
          x86_64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.gnu64;
            buildInputs = opensslBuildInputs;
          };
          x86_64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.musl64;
            buildInputs = opensslBuildInputs;
          };
          aarch64-gnu = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform;
            buildInputs = opensslBuildInputs;
          };
          aarch64-musl = mkToolchain {
            pkgs = pkgs.pkgsCross.aarch64-multiplatform-musl;
            buildInputs = opensslBuildInputs;
          };
        }
        // pkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isDarwin {
          aarch64-darwin = mkToolchain {
            inherit pkgs;
            buildInputs = opensslBuildInputs;
          };
        };
        # opensslBuildInputs' second entry (see above): the OpenSSL built
        # against the x86_64-gnu toolchain's own glibc-2.28 stdenv, for
        # devShells.crypto to point OPENSSL_LIB_DIR/OPENSSL_INCLUDE_DIR at,
        # instead of nixpkgs' native-stdenv pkgs.openssl_3_5.
        opensslCrossPackage = builtins.elemAt opensslToolchains.x86_64-gnu.buildInputs 1;
        vmRuntime = pkgs.callPackage ./nix/pkgs/vm-runtime.nix { };
        testGuest = import ./nix/test-guest {
          inherit pkgs;
          qemuPkgs = testGuestPkgs;
          firmwarePkgs = testGuestPkgs;
        };
        testMachines = import ./tests/tmachine/config.nix {
          inherit pkgs toolchains rustToolchain;
          qemuPkgs = tmachineRuntimePkgs;
          firmwarePkgs = tmachineRuntimePkgs;
        };
        artifacts = pkgs.callPackage ./tests/tmachine/artifacts.nix { inherit rustToolchain toolchains; };
        checkProtobufCompatibility = pkgs.writeShellApplication {
          name = "check-protobuf-compatibility";
          runtimeInputs = [
            pkgs.buf
            pkgs.git
          ];
          text = ''
            exec ${pkgs.python3}/bin/python3 ${./tasks/scripts}/check_proto_compatibility.py "$@"
          '';
        };
      in
      {
        apps = {
          check-protobuf-compatibility = {
            type = "app";
            program = "${checkProtobufCompatibility}/bin/check-protobuf-compatibility";
          };
          build-artifacts = {
            type = "app";
            program = "${artifacts.all}/bin/build-artifacts";
          };
          build-artifacts-binaries = {
            type = "app";
            program = "${artifacts.binaries}/bin/build-artifacts-binaries";
          };
          build-artifacts-vm-driver = {
            type = "app";
            program = "${artifacts.vmDriver}/bin/build-artifacts-vm-driver";
          };
          build-artifacts-deb = {
            type = "app";
            program = "${artifacts.deb}/bin/build-artifacts-deb";
          };
          build-artifacts-rpm = {
            type = "app";
            program = "${artifacts.rpm}/bin/build-artifacts-rpm";
          };
          build-artifacts-test-archives = {
            type = "app";
            program = "${artifacts.testArchives}/bin/build-artifacts-test-archives";
          };
          build-artifacts-test-images = {
            type = "app";
            program = "${artifacts.testImages}/bin/build-artifacts-test-images";
          };
          generate-podman-e2e-ci-tests = {
            type = "app";
            program = "${artifacts.podmanE2eCiTests}/bin/generate-podman-e2e-ci-tests";
          };
          build-artifacts-helm = {
            type = "app";
            program = "${artifacts.helm}/bin/build-artifacts-helm";
          };
          build-artifacts-images = {
            type = "app";
            program = "${artifacts.images}/bin/build-artifacts-images";
          };
          test-guest = testGuest.app;
          test-guest-cache = testGuest.cacheApp;
        };

        packages = {
          # Expose app derivations so CI can prepare them before executing once.
          check-protobuf-compatibility = checkProtobufCompatibility;
          build-artifacts-test-archives = artifacts.testArchives;
          build-artifacts-test-images = artifacts.testImages;
          build-artifacts-helm = artifacts.helm;
          vm-runtime = vmRuntime;
          tmachine = testMachines.package;
          tmachine-config = testMachines.config;
          tmachine-unwrapped = testMachines.unwrapped;
          openshell-test-runner = testMachines.testRunner;
        };

        devShells = {
          default = pkgs.mkShellNoCC commonDevShell;

          # Crypto backend tests need an OpenSSL built against the same
          # glibc-2.28 stdenv as the rest of the gateway binary (see
          # nix/pkgs/openssl.nix), not nixpkgs' native-stdenv pkgs.openssl_3_5:
          # the native build expects glibc symbols (e.g. __isoc23_strtol,
          # glibc >= 2.38) the project's glibc-2.28 sysroot doesn't provide.
          # CC/LINKER/AS/AR come from opensslToolchains.x86_64-gnu only: this
          # shell exists for the gateway's x86_64-unknown-linux-gnu build
          # (see Dockerfile.gateway.multistage), so unlike commonDevShell's
          # env (which folds over every `toolchains` entry so any of its
          # target triples can be cross-built from one shell) this must not
          # fold over all of `opensslToolchains` too: that would force
          # realizing every other target's toolchain as well, including a
          # from-scratch aarch64-gnu cross-GCC with no binary cache hit (this
          # combination of glibc-2.28 + openssl.nix has never been built
          # before), just to enter a shell that only ever targets x86_64-gnu.
          # This target's cross sysroot never bakes in aws-lc.nix's
          # unprefixed libcrypto/libssl shim (see opensslBuildInputs above),
          # so linking the real OpenSSL below can't collide with it.
          crypto = pkgs.mkShell (
            commonDevShell
            // {
              buildInputs = [ opensslCrossPackage ];
              env = opensslToolchains.x86_64-gnu.env // {
                OPENSSL_LIB_DIR = "${pkgs.lib.getLib opensslCrossPackage}/lib";
                OPENSSL_INCLUDE_DIR = "${pkgs.lib.getDev opensslCrossPackage}/include";
                OPENSSL_NO_VENDOR = "1";
                OPENSSL_STATIC = "0";
                AWS_LC_SYS_USE_SYSTEM = "0";
              };
            }
          );

          testing = pkgs.mkShellNoCC (
            commonDevShell
            // {
              packages = commonDevShell.packages ++ [
                pkgs.ansible
                pkgs.skopeo
                pkgs.sshpass
                testMachines.package
              ];

              shellHook = ''
                export ANSIBLE_CONFIG="$(git rev-parse --show-toplevel)/tests/tmachine/ansible/ansible.cfg"
              '';
            }
          );
        };

        formatter = treefmtEval.config.build.wrapper;
      }
    );
}
