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

    packages = forAllSystems ({
      pkgs,
      craneLib,
      ...
    }: let
      src = craneLib.cleanCargoSource ./.;
      onnxruntime-bin = pkgs.callPackage ./nix/onnxruntime.nix {};
      commonArgs = {
        inherit src;
        pname = "parry";
        strictDeps = true;
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
        mainProgram = "parry";
      };
      onnxSupported = builtins.elem pkgs.stdenv.hostPlatform.system [
        "x86_64-linux"
        "aarch64-linux"
        "aarch64-darwin"
      ];
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
            wrapProgram $out/bin/parry \
              --set ORT_DYLIB_PATH "${onnxruntime-bin}/lib/libonnxruntime${pkgs.stdenv.hostPlatform.extensions.sharedLibrary}"
          '';
          inherit meta;
        };
    in
      {
        candle = candlePkg;
      }
      // pkgs.lib.optionalAttrs onnxSupported {
        default = onnxPkg;
        onnx = onnxPkg;
      });

    devShells = forAllSystems ({
      pkgs,
      fenixPkgs,
      ...
    }: let
      toolchain = fenixPkgs.stable.withComponents [
        "cargo"
        "clippy"
        "rustc"
        "rustfmt"
        "rust-src"
        "rust-analyzer"
      ];
    in {
      default = pkgs.mkShell {
        packages =
          [
            toolchain
            pkgs.just
            pkgs.taplo
            pkgs.typos
            pkgs.actionlint
            pkgs.cargo-nextest
          ]
          ++ pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.apple-sdk_15
          ];

        env = {
          RUST_BACKTRACE = "1";
          RUST_SRC_PATH = "${toolchain}/lib/rustlib/src/rust/library";
        };
      };
    });
  };
}
