{ config, lib, pkgs, ... }:

let
  cfg = config.services.facelock;
  settingsFormat = pkgs.formats.toml { };
  configFile = settingsFormat.generate "config.toml" cfg.config;
  facelockPackage = cfg.package;
in
{
  options.services.facelock = {
    enable = lib.mkEnableOption "Facelock face authentication";

    package = lib.mkOption {
      type = lib.types.package;
      default = pkgs.callPackage ./default.nix { };
      defaultText = lib.literalExpression "pkgs.callPackage ./default.nix { }";
      description = "The Facelock package to use.";
    };

    config = lib.mkOption {
      type = settingsFormat.type;
      default = { };
      description = ''
        Configuration for Facelock. These options map directly to
        /etc/facelock/config.toml keys. See the default config for
        available options.
      '';
      example = lib.literalExpression ''
        {
          device.path = "/dev/video2";
          recognition.threshold = 0.80;
          recognition.timeout_secs = 5;
          daemon.mode = "daemon";
          security.require_ir = true;
        }
      '';
    };
  };

  config = lib.mkIf cfg.enable {
    # Install the package
    environment.systemPackages = [ facelockPackage ];

    # Polkit authority, for the facelock-polkit-agent binary the package ships
    security.polkit.enable = true;

    # facelock's compiled-in catalog root is /usr/share/locale, which does not
    # exist on NixOS, so point it at the package's own tree.
    #
    # Read this as partial coverage, not a working translation story. It is a
    # session variable, so sudo's env_reset strips it, and nearly every verb
    # needs root: in practice only unprivileged commands see it. The PAM module
    # has no equivalent override at all, so its catalog stays English here.
    # Inert while po/ holds only templates. A real NixOS translation needs the
    # catalog root resolved at build time rather than through the environment.
    environment.sessionVariables.FACELOCK_LOCALEDIR = "${facelockPackage}/share/locale";

    # PAM module
    security.pam.services = {
      sudo.rules.auth.facelock = {
        order = 100;
        control = "sufficient";
        modulePath = "${facelockPackage}/lib/security/pam_facelock.so";
      };
    };

    # Configuration file
    environment.etc."facelock/config.toml".source = configFile;

    # D-Bus policy and activation service. On NixOS both live in the read-only
    # store under /etc/dbus-1, so they cannot be written through
    # environment.etc. services.dbus.packages links the package's
    # share/dbus-1/{system.d,system-services} trees into place. The activation
    # file's Exec= path is rewritten to the store binary in default.nix.
    services.dbus.packages = [ facelockPackage ];

    # systemd units
    systemd.services.facelock-daemon = {
      description = "Facelock Face Authentication Daemon";
      after = [ "local-fs.target" ];
      wantedBy = [ "multi-user.target" ];
      # Kept in parity with systemd/facelock-daemon.service. Any change to the
      # hardening there must be mirrored here.
      serviceConfig = {
        Type = "dbus";
        BusName = "org.facelock.Daemon";
        ExecStart = "${facelockPackage}/bin/facelock daemon";
        StandardOutput = "journal";
        StandardError = "journal";
        Restart = "on-failure";
        RestartSec = 3;
        LimitNOFILE = 1024;
        UMask = "0027";

        # Phase 1: Filesystem isolation. ProtectHome is deliberately not used
        # (it hides /run/user/, breaking desktop notifications); InaccessiblePaths
        # protects /home and /root instead.
        ProtectSystem = "strict";
        InaccessiblePaths = [ "/home" "/root" ];
        ReadWritePaths = [ "/var/lib/facelock" "/var/log/facelock" ];
        PrivateTmp = true;
        NoNewPrivileges = true;

        # Phase 2: Kernel hardening.
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectControlGroups = true;
        RestrictNamespaces = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;

        # Phase 3: Capabilities, seccomp, and network lockdown. CAP_SETUID and
        # CAP_SETGID are empirically required (runuser for notifications);
        # CAP_CHOWN is startup-only (state-layout and enrollment-marker chowns).
        CapabilityBoundingSet = "CAP_SETUID CAP_SETGID CAP_CHOWN";
        AmbientCapabilities = "CAP_SETUID CAP_SETGID";
        RestrictAddressFamilies = "AF_UNIX AF_NETLINK";
        IPAddressDeny = "any";
        SystemCallFilter = "@system-service";
        SystemCallErrorNumber = "EPERM";
        SystemCallArchitectures = "native";

        # Hide other processes' /proc entries and non-PID /proc contents.
        ProtectProc = "invisible";
        ProcSubset = "pid";
        ProtectHostname = true;
      };
    };

    # tmpfiles rules
    # Must match dist/facelock.tmpfiles.
    systemd.tmpfiles.rules = [
      # Nothing is group-owned any more (ADR 010).
      "d /run/facelock 0755 root root -"
      # 0711 root:root = traversable by everyone, listable by root only
      # (ADR 010). Parent must come before its children.
      "d /var/lib/facelock 0711 root root -"
      # Public, SHA256-verified downloads.
      "d /var/lib/facelock/models 0755 root root -"
      # Markers only: a user can open its own 0600 marker by name but cannot
      # enumerate who else is enrolled.
      "d /var/lib/facelock/enrolled 0711 root root -"
      # PAM rollback state contains complete service files: root-only.
      "d /var/lib/facelock/pam-backups 0700 root root -"
      # Encrypted biometric templates: root-only. `z` never creates.
      "z /var/lib/facelock/facelock.db 0600 root root -"
      "z /var/lib/facelock/facelock.db-wal 0600 root root -"
      "z /var/lib/facelock/facelock.db-shm 0600 root root -"
      # Per-user auth history and raw face snapshots: root-only.
      "d /var/log/facelock 0700 root root -"
      "d /var/log/facelock/snapshots 0700 root root -"
      "z /var/log/facelock/audit.jsonl 0600 root root -"
    ];
  };
}
