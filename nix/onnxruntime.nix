# Pre-built ONNX Runtime 1.24.2 for use with the `ort` crate (v2.0.0-rc.11).
# nixpkgs ships 1.23.x which is ABI-incompatible with ort 2.x.
{
  lib,
  stdenv,
  fetchurl,
  autoPatchelfHook,
}: let
  version = "1.24.2";

  platform =
    {
      x86_64-linux = {
        name = "linux-x64";
        hash = "1ri5mpz7i8idqx575ggg0lh0x1ckcsa1fiv82wp68qsnp9s58wj3";
      };
      aarch64-linux = {
        name = "linux-aarch64";
        hash = "0ph8l3n7rb0as6z0shi65l6w7a0p9yi4pvbq3scad8k5k78v65b7";
      };
      aarch64-darwin = {
        name = "osx-arm64";
        hash = "1pmbb3wfrm61l1yqaw0jm1b826s6lz845vj7bcj8b8lf7r8gmx0a";
      };
    }
    .${
      stdenv.hostPlatform.system
    }
      or (throw "onnxruntime-bin: unsupported system ${stdenv.hostPlatform.system}");
in
  stdenv.mkDerivation {
    pname = "onnxruntime-bin";
    inherit version;

    src = fetchurl {
      url = "https://github.com/microsoft/onnxruntime/releases/download/v${version}/onnxruntime-${platform.name}-${version}.tgz";
      hash = "sha256:${platform.hash}";
    };

    sourceRoot = "onnxruntime-${platform.name}-${version}";

    nativeBuildInputs = lib.optionals stdenv.hostPlatform.isLinux [autoPatchelfHook];
    buildInputs = lib.optionals stdenv.hostPlatform.isLinux [stdenv.cc.cc.lib];

    installPhase = ''
      runHook preInstall
      mkdir -p $out/lib $out/include
      cp -r lib/*.${
        if stdenv.hostPlatform.isDarwin
        then "dylib*"
        else "so*"
      } $out/lib/
      cp -r include/* $out/include/
      runHook postInstall
    '';

    meta = {
      description = "ONNX Runtime ${version} pre-built binaries";
      homepage = "https://github.com/microsoft/onnxruntime";
      license = lib.licenses.mit;
      platforms = ["x86_64-linux" "aarch64-linux" "aarch64-darwin"];
    };
  }
