{
  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    crane = {
      url = "github:ipetkov/crane";
    };
  };

  outputs = {
    self,
    nixpkgs,
    fenix,
    crane,
    ...
  }: let
    systems = ["x86_64-linux" "aarch64-linux" "x86_64-darwin" "aarch64-darwin"];
    forAllSystems = f:
      nixpkgs.lib.genAttrs systems (system:
        f {
          pkgs = nixpkgs.legacyPackages.${system};
          fenixPkgs = fenix.packages.${system};
          craneLib =
            (crane.mkLib nixpkgs.legacyPackages.${system}).overrideToolchain
            fenix.packages.${system}.stable.toolchain;
        });

    perSystem = forAllSystems ({
      pkgs,
      fenixPkgs,
      craneLib,
    }: let
      src = craneLib.cleanCargoSource ./.;
      onnxruntime-bin = pkgs.callPackage ./nix/onnxruntime.nix {};
      commonArgs = {
        inherit src;
        pname = "parry-guard";
        strictDeps = true;
        nativeCheckInputs = [pkgs.git];
        nativeBuildInputs = pkgs.lib.optionals pkgs.stdenv.isLinux [
          pkgs.pkg-config
          pkgs.openssl
        ];
        buildInputs =
          pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.openssl
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.libiconv
            pkgs.apple-sdk_15
          ];
      };
      meta = {
        description = "Prompt injection scanner for Claude Code";
        license = pkgs.lib.licenses.mit;
        mainProgram = "parry-guard";
      };
      onnxSupported = builtins.elem pkgs.stdenv.hostPlatform.system [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];

      # Candle
      candleArgs =
        commonArgs
        // {
          cargoExtraArgs = "--no-default-features --features candle";
        };
      candleArtifacts = craneLib.buildDepsOnly candleArgs;
      candlePkg = craneLib.buildPackage (candleArgs
        // {
          cargoArtifacts = candleArtifacts;
          inherit meta;
        });

      # ONNX
      onnxArgs =
        commonArgs
        // {
          cargoExtraArgs = "--no-default-features --features onnx";
          ORT_DYLIB_PATH = "${onnxruntime-bin}/lib/libonnxruntime${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}";
        };
      onnxArtifacts = craneLib.buildDepsOnly onnxArgs;
      onnxPkg = let
        unwrapped = craneLib.buildPackage (onnxArgs
          // {
            cargoArtifacts = onnxArtifacts;
            inherit meta;
          });
      in
        pkgs.symlinkJoin {
          name = "parry-onnx";
          paths = [unwrapped];
          nativeBuildInputs = [pkgs.makeWrapper];
          postBuild = ''
            wrapProgram $out/bin/parry-guard \
              --set ORT_DYLIB_PATH "${onnxruntime-bin}/lib/libonnxruntime${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}"
          '';
          inherit meta;
        };

      toolchain = fenixPkgs.stable.withComponents [
        "cargo"
        "clippy"
        "rustc"
        "rustfmt"
        "rust-src"
        "rust-analyzer"
      ];

      maturinVendorDir = craneLib.vendorCargoDeps {inherit src;};
    in {
      packages =
        {candle = candlePkg;}
        // pkgs.lib.optionalAttrs onnxSupported {
          default = onnxPkg;
          onnx = onnxPkg;
          onnxruntime = onnxruntime-bin;
        };

      checks =
        {
          fmt = craneLib.cargoFmt {inherit src;};

          candle-clippy = craneLib.cargoClippy (candleArgs
            // {
              cargoArtifacts = candleArtifacts;
              cargoClippyExtraArgs = "--workspace -- -D warnings";
            });

          candle-nextest = craneLib.cargoNextest (candleArgs
            // {
              cargoArtifacts = candleArtifacts;
            });

          taplo =
            pkgs.runCommand "taplo-check" {
              nativeBuildInputs = [pkgs.taplo];
            } ''
              cd ${self}
              taplo check
              touch $out
            '';

          typos =
            pkgs.runCommand "typos-check" {
              nativeBuildInputs = [pkgs.typos];
            } ''
              cd ${self}
              typos
              touch $out
            '';

          nix-fmt =
            pkgs.runCommand "nix-fmt-check" {
              nativeBuildInputs = [pkgs.alejandra];
            } ''
              alejandra --check ${self}/flake.nix ${self}/nix/
              touch $out
            '';

          maturin-build = pkgs.stdenv.mkDerivation {
            name = "maturin-build-check";
            src = self;
            nativeBuildInputs =
              [
                toolchain
                pkgs.maturin
                pkgs.python3
              ]
              ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
                pkgs.pkg-config
                pkgs.openssl
              ];
            buildInputs =
              pkgs.lib.optionals pkgs.stdenv.isLinux [pkgs.openssl]
              ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
                pkgs.libiconv
                pkgs.apple-sdk_15
              ];
            buildPhase = let
              vendorConfig = pkgs.writeText "maturin-vendor-config" ''
                [source.crates-io]
                replace-with = "vendored-sources"
                [source.vendored-sources]
                directory = "${maturinVendorDir}"
              '';
            in ''
              mkdir -p .cargo
              cat ${vendorConfig} >> .cargo/config.toml
              maturin build --release --out dist
            '';
            installPhase = "touch $out";
            HOME = "/build";
          };
        }
        // pkgs.lib.optionalAttrs onnxSupported {
          onnx-clippy = craneLib.cargoClippy (onnxArgs
            // {
              cargoArtifacts = onnxArtifacts;
              cargoClippyExtraArgs = "--workspace -- -D warnings";
            });

          onnx-nextest = craneLib.cargoNextest (onnxArgs
            // {
              cargoArtifacts = onnxArtifacts;
            });
        };

      devShells.default = pkgs.mkShell {
        packages =
          [
            toolchain
            pkgs.just
            pkgs.taplo
            pkgs.typos
            pkgs.actionlint
            pkgs.cargo-nextest
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isLinux [
            pkgs.pkg-config
            pkgs.openssl
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.apple-sdk_15
          ];

        env =
          {
            RUST_BACKTRACE = "1";
            RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
          }
          // pkgs.lib.optionalAttrs onnxSupported {
            ORT_DYLIB_PATH = onnxArgs.ORT_DYLIB_PATH;
          };
      };
    });
  in {
    formatter = nixpkgs.lib.genAttrs systems (system: nixpkgs.legacyPackages.${system}.alejandra);

    overlays.default = final: _prev: let
      sys = final.stdenv.hostPlatform.system;
    in {
      parry =
        self.packages.${
          sys
        }.${
          if builtins.hasAttr "default" self.packages.${sys}
          then "default"
          else "candle"
        };
    };

    homeManagerModules.default = import ./nix/hm-module.nix;

    packages = nixpkgs.lib.mapAttrs (_: s: s.packages) perSystem;
    checks = nixpkgs.lib.mapAttrs (_: s: s.checks) perSystem;
    devShells = nixpkgs.lib.mapAttrs (_: s: s.devShells) perSystem;
  };
}
