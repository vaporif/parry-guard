{
  config,
  lib,
  pkgs,
  ...
}: let
  inherit (lib) mkEnableOption mkOption mkIf types;
  cfg = config.programs.parry;

  patternEntryType = types.submodule {
    options = {
      pattern = mkOption {
        type = types.str;
        description = "The pattern string to match.";
      };
      kind = mkOption {
        type = types.enum ["path_segment" "suffix" "substring"];
        default = "path_segment";
        description = "How the pattern is matched against paths.";
      };
    };
  };

  patternsType = types.submodule {
    options = {
      sensitive_paths = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf patternEntryType;
              default = [];
              description = "Sensitive path patterns to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in sensitive path patterns to remove.";
            };
          };
        };
        default = {};
      };
      exfil_domains = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Exfiltration domains to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in exfiltration domains to remove.";
            };
          };
        };
        default = {};
      };
      secrets = mkOption {
        type = types.submodule {
          options = {
            add = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Secret regex patterns to add.";
            };
            remove = mkOption {
              type = types.listOf types.str;
              default = [];
              description = "Built-in secret patterns to remove.";
            };
          };
        };
        default = {};
      };
    };
  };

  modelEntryToml = m:
    {inherit (m) repo;}
    // lib.optionalAttrs (m.threshold != null) {inherit (m) threshold;};

  modelsToml = pkgs.writers.writeTOML "models.toml" {
    models = map modelEntryToml cfg.models;
  };

  patternsToml = pkgs.writers.writeTOML "patterns.toml" {
    sensitive_paths = {
      add = map (e: {inherit (e) pattern kind;}) cfg.patterns.sensitive_paths.add;
      remove = cfg.patterns.sensitive_paths.remove;
    };
    exfil_domains = {
      add = cfg.patterns.exfil_domains.add;
      remove = cfg.patterns.exfil_domains.remove;
    };
    secrets = {
      add = cfg.patterns.secrets.add;
      remove = cfg.patterns.secrets.remove;
    };
  };

  envVars =
    lib.optional (cfg.threshold != null) ''--set PARRY_THRESHOLD "${toString cfg.threshold}"''
    ++ lib.optional (cfg.logLevel != null) ''--set PARRY_LOG "${cfg.logLevel}"''
    ++ lib.optional (cfg.hfTokenFile != null) ''--set HF_TOKEN_PATH "${cfg.hfTokenFile}"''
    ++ lib.optional (cfg.idleTimeout != null) ''--set PARRY_IDLE_TIMEOUT "${toString cfg.idleTimeout}"''
    ++ lib.optional (cfg.ignorePaths != []) ''--set PARRY_IGNORE_PATHS "${lib.concatStringsSep "," cfg.ignorePaths}"''
    ++ lib.optional (cfg.models != []) ''--set PARRY_SCAN_MODE "custom"''
    ++ lib.optional (cfg.scanMode != null && cfg.models == []) ''--set PARRY_SCAN_MODE "${cfg.scanMode}"''
    ++ lib.optional (cfg.logFile != null) ''--set PARRY_LOG_FILE "${cfg.logFile}"'';

  wrappedParry =
    if envVars != []
    then
      pkgs.symlinkJoin {
        name = "parry-wrapped";
        paths = [cfg.package];
        nativeBuildInputs = [pkgs.makeWrapper];
        postBuild = ''
          wrapProgram $out/bin/parry ${lib.concatStringsSep " " envVars}
        '';
      }
    else cfg.package;
in {
  options.programs.parry = {
    enable = mkEnableOption "parry prompt injection scanner";

    package = mkOption {
      type = types.package;
      description = "The parry package to use.";
    };

    threshold = mkOption {
      type = types.nullOr types.float;
      default = null;
      description = "ML detection threshold (0.0–1.0). Null uses the default (0.7).";
    };

    logLevel = mkOption {
      type = types.nullOr (types.enum ["trace" "debug" "info" "warn" "error"]);
      default = null;
      description = "Log level filter for tracing output.";
    };

    hfTokenFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Path to a file containing the HuggingFace token.";
    };

    idleTimeout = mkOption {
      type = types.nullOr types.int;
      default = null;
      description = "Daemon idle timeout in seconds. Null uses the default (1800).";
    };

    ignorePaths = mkOption {
      type = types.listOf types.str;
      default = [];
      description = "Project paths to skip scanning entirely (prefix match).";
    };

    scanMode = mkOption {
      type = types.nullOr (types.enum ["fast" "full" "custom"]);
      default = null;
      description = "ML scan mode. fast = DeBERTa only, full = DeBERTa + Llama ensemble, custom = user models.toml.";
    };

    models = mkOption {
      type = types.listOf (types.submodule {
        options = {
          repo = mkOption {
            type = types.str;
            description = "HuggingFace repo ID.";
          };
          threshold = mkOption {
            type = types.nullOr types.float;
            default = null;
            description = "Per-model threshold. Null falls back to global threshold.";
          };
        };
      });
      default = [];
      description = "Custom model list. When non-empty, generates ~/.config/parry/models.toml and sets scanMode to custom.";
    };

    logFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Override log file path. Null uses the default (~/.parry/parry.log).";
    };

    patterns = mkOption {
      type = types.nullOr patternsType;
      default = null;
      description = "Custom patterns config. When set, generates ~/.config/parry/patterns.toml.";
    };
  };

  config = mkIf cfg.enable {
    assertions =
      map (m: {
        assertion = builtins.match ".+/.+" m.repo != null;
        message = "parry: model repo '${m.repo}' must be in 'owner/name' format (e.g. 'ProtectAI/deberta-v3-small-prompt-injection-v2')";
      })
      cfg.models
      ++ [
        {
          assertion = cfg.scanMode != "custom" || cfg.models != [];
          message = "parry: scanMode 'custom' requires at least one entry in 'models'";
        }
        {
          assertion = cfg.models == [] || cfg.scanMode == null || cfg.scanMode == "custom";
          message = "parry: 'models' is set but scanMode is '${toString cfg.scanMode}' (models are only used in 'custom' mode)";
        }
      ];

    home.packages = [wrappedParry];

    home.activation.parryRestart = lib.hm.dag.entryAfter ["writeBoundary"] ''
      ${
        if pkgs.stdenv.isDarwin
        then "/usr/bin/pkill"
        else "${pkgs.procps}/bin/pkill"
      } -x parry 2>/dev/null || true
      rm -f "$HOME/.parry/parry.sock" "$HOME/.parry/daemon.pid" 2>/dev/null || true
    '';

    xdg.configFile."parry/models.toml" = mkIf (cfg.models != []) {
      source = modelsToml;
    };

    xdg.configFile."parry/patterns.toml" = mkIf (cfg.patterns != null) {
      source = patternsToml;
    };
  };
}
