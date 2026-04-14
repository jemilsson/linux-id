flake:
{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.linux-id;

  instanceModule = lib.types.submodule (
    { config, name, ... }:
    {
      options = {
        enable = lib.mkEnableOption "this linux-id instance";

        name = lib.mkOption {
          type = lib.types.str;
          default = name;
          description = "UHID device name. Must be unique across instances.";
        };

        mode = lib.mkOption {
          type = lib.types.enum [
            "user"
            "system"
          ];
          default = "user";
          description = ''
            Service scope. "user" installs a systemd user service (requires
            an active session or linger). "system" installs a system service
            suitable for headless/agent use.
          '';
        };

        user = lib.mkOption {
          type = lib.types.str;
          default = "";
          description = ''
            User account to run the system service as.
            Required when mode = "system", ignored for mode = "user".
          '';
        };

        auth = lib.mkOption {
          type = lib.types.enum [
            "pinentry"
            "fprintd"
          ];
          default = "pinentry";
          description = ''
            User verification method. "pinentry" confirms presence with a
            click dialog (UP only). "fprintd" verifies identity via
            fingerprint (UP+UV).
          '';
        };

        backend = lib.mkOption {
          type = lib.types.enum [
            "tpm"
            "memory"
          ];
          default = "tpm";
          description = "Key storage backend.";
        };

        device = lib.mkOption {
          type = lib.types.str;
          default = "/dev/tpmrm0";
          description = "TPM device path.";
        };

        autoApproveAll = lib.mkOption {
          type = lib.types.bool;
          default = false;
          description = ''
            Globally disable all user verification prompts.
            Useful for headless/agent environments.
          '';
        };

        sites = lib.mkOption {
          type = lib.types.attrsOf (
            lib.types.submodule {
              options = {
                autoApprove = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Skip verification for this relying party.";
                };
                backupEligible = lib.mkOption {
                  type = lib.types.bool;
                  default = false;
                  description = "Set the Backup Eligible flag for this relying party.";
                };
              };
            }
          );
          default = { };
          description = "Per-site configuration keyed by relying party ID.";
        };

        extraPaths = lib.mkOption {
          type = lib.types.listOf lib.types.package;
          default = [ ];
          description = "Extra packages to add to the service PATH (e.g. pinentry-qt).";
        };

        package = lib.mkOption {
          type = lib.types.package;
          default = flake.packages.${pkgs.system}.default;
          description = "The linux-id package to use.";
        };
      };
    }
  );

  enabledInstances = lib.filterAttrs (_: inst: inst.enable) cfg.instances;

  userInstances = lib.filterAttrs (_: inst: inst.mode == "user") enabledInstances;
  systemInstances = lib.filterAttrs (_: inst: inst.mode == "system") enabledInstances;

  mkConfigFile = inst:
    pkgs.writeText "linux-id-config-${inst.name}.json" (
      builtins.toJSON {
        auto_approve_all = inst.autoApproveAll;
        sites = lib.mapAttrs (_: site: {
          auto_approve = site.autoApprove;
          backup_eligible = site.backupEligible;
        }) inst.sites;
      }
    );

  mkExecStart = inst: lib.concatStringsSep " " (
    [
      "${inst.package}/bin/linux-id"
      "--name ${lib.escapeShellArg inst.name}"
      "--backend ${inst.backend}"
      "--device ${inst.device}"
      "--config ${mkConfigFile inst}"
    ]
    ++ lib.optional (inst.auth == "fprintd") "--auth fprintd"
  );

in
{
  options.services.linux-id = {
    instances = lib.mkOption {
      type = lib.types.attrsOf instanceModule;
      default = { };
      description = ''
        Named linux-id instances. Each instance creates an independent
        virtual FIDO2 authenticator backed by the TPM.
      '';
      example = lib.literalExpression ''
        {
          personal = {
            enable = true;
            mode = "user";
            auth = "fprintd";
            extraPaths = [ pkgs.pinentry-qt ];
          };
          agent = {
            enable = true;
            mode = "system";
            user = "openclaw";
            name = "linux-id-agent";
            autoApproveAll = true;
          };
        }
      '';
    };

    udev.enable = lib.mkOption {
      type = lib.types.bool;
      default = enabledInstances != { };
      defaultText = lib.literalExpression "any instance enabled";
      description = "Install udev rules for uhid and tpmrm0 access.";
    };
  };

  config = lib.mkIf (enabledInstances != { }) {
    assertions =
      lib.mapAttrsToList (name: inst: {
        assertion = inst.mode == "user" || inst.user != "";
        message = "services.linux-id.instances.${name}: mode = \"system\" requires 'user' to be set.";
      }) enabledInstances;

    # Udev rules: grant access to uhid and tpmrm0.
    # uaccess covers seat-attached sessions; GROUP+MODE covers system services.
    services.udev.extraRules = lib.mkIf cfg.udev.enable ''
      KERNEL=="uhid",      SUBSYSTEM=="misc",   TAG+="uaccess", GROUP="tss", MODE="0660"
      KERNEL=="hidraw[0-9]*", SUBSYSTEM=="hidraw", KERNELS=="0003:15D9:0A37.*", TAG+="uaccess", GROUP="tss", MODE="0660"
      KERNEL=="tpmrm0",    SUBSYSTEM=="tpmrm",  TAG+="uaccess"
    '';

    # User services.
    systemd.user.services = lib.mapAttrs' (
      name: inst:
      lib.nameValuePair "linux-id-${name}" {
        description = "linux-id TPM FIDO2/U2F device (${name})";
        wantedBy = [ "default.target" ];
        path = inst.extraPaths;
        serviceConfig = {
          ExecStart = mkExecStart inst;
          Restart = "on-failure";
          RestartSec = 5;
        };
      }
    ) userInstances;

    # System services.
    systemd.services = lib.mapAttrs' (
      name: inst:
      lib.nameValuePair "linux-id-${name}" {
        description = "linux-id TPM FIDO2/U2F device (${name})";
        wantedBy = [ "multi-user.target" ];
        after = [ "modprobe@uhid.service" ];
        wants = [ "modprobe@uhid.service" ];
        serviceConfig = {
          Type = "simple";
          User = inst.user;
          ExecStart = mkExecStart inst;
          Restart = "on-failure";
          RestartSec = 5;
          RuntimeDirectory = "linux-id-${name}";

          # Hardening.
          NoNewPrivileges = true;
          ProtectSystem = "strict";
          ProtectHome = true;
          PrivateTmp = true;
          PrivateNetwork = true;
          ProtectHostname = true;
          ProtectClock = true;
          ProtectKernelTunables = true;
          ProtectKernelModules = true;
          ProtectKernelLogs = true;
          ProtectControlGroups = true;
          RestrictAddressFamilies = [ "AF_UNIX" ];
          RestrictNamespaces = true;
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          DeviceAllow = [
            "/dev/tpmrm0"
            "/dev/uhid"
          ];
        };
      }
    ) systemInstances;
  };
}
