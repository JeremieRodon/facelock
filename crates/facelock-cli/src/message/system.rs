//! Wiring facelock into the system: the daemon unit and legacy group cleanup.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Daemon unit setup and legacy `facelock` group cleanup.
///
/// Variant and field names are the machine vocabulary: [`Message::machine`]
/// derives its event line from them.
#[derive(Debug, Clone, PartialEq)]
pub enum SystemMessage {
    // -- enrollment and test steps --
    ConfirmDaemonMode,
    SystemdNotDetected,
    SystemdDeclined,
    SystemdSkippedFlag,
    SystemdFromCommandLine,

    // -- bringing the daemon up --
    DaemonRestarted,
    DaemonRunning,
    DaemonNotReady { seconds: u64 },

    // -- the legacy facelock system group (ADR 010) --
    RetiredFacelockGroup,

    // -- validating installed assets and controlling the unit --
    DisablingSystemdUnits,
    SystemdUnitsDisabled,
    ValidatingSystemAssets,
    RemovedLegacySystemAsset { path: String },
    PreservedLocalDbusPolicy { path: String },
    SystemAssetsValidated,
    SystemctlDaemonReloadDone,
    SystemctlEnableDone { unit: String },
    DbusActivationEnabled,
}

impl Message for SystemMessage {
    fn localized(&self) -> String {
        use SystemMessage::*;
        match self {
            ConfirmDaemonMode => translate("Enable daemon mode with D-Bus activation?"),
            SystemdNotDetected => translate(
                "  systemd not detected. Skipping daemon configuration.\n  Facelock will use oneshot mode for authentication.",
            ),
            SystemdDeclined => {
                translate("  Skipping systemd setup. Facelock will use oneshot mode.")
            }
            SystemdSkippedFlag => translate(
                "  Skipping daemon configuration (--no-systemd).\n  No unit files are written and systemctl is not invoked.",
            ),
            SystemdFromCommandLine => translate("  Answered on the command line."),
            DaemonRestarted => translate(
                "  facelock-daemon was already running; restarted so enrollment uses\n  the new configuration.",
            ),
            DaemonRunning => translate("  facelock-daemon is running."),
            DaemonNotReady { seconds } => fill(
                translate(
                    "  facelock-daemon did not answer within {seconds}s.\n  Continuing with direct camera access; check: systemctl status facelock-daemon",
                ),
                &[("seconds", seconds.to_string())],
            ),
            RetiredFacelockGroup => {
                translate("  Removed the legacy 'facelock' group; face unlock no longer uses it.")
            }
            DisablingSystemdUnits => translate("Disabling facelock-daemon systemd units..."),
            SystemdUnitsDisabled => translate("facelock-daemon service disabled and stopped."),
            ValidatingSystemAssets => {
                translate("Validating installed facelock-daemon systemd and D-Bus assets...")
            }
            RemovedLegacySystemAsset { path } => fill(
                translate("  Removed exact known legacy {path}"),
                &[("path", path.clone())],
            ),
            PreservedLocalDbusPolicy { path } => fill(
                translate(
                    "  Preserved merged local D-Bus policy {path}; review it if Facelock bus authorization is unexpected.",
                ),
                &[("path", path.clone())],
            ),
            SystemAssetsValidated => translate("  Installed systemd and D-Bus assets validated."),
            SystemctlDaemonReloadDone => translate("  systemctl daemon-reload done."),
            SystemctlEnableDone { unit } => fill(
                translate("  systemctl enable {unit} done."),
                &[("unit", unit.clone())],
            ),
            DbusActivationEnabled => {
                translate("\nfacelock-daemon D-Bus activation is now enabled.")
            }
        }
    }
}

/// One sample per variant, in enum order, for the sweeps in [`super::Samples`].
///
/// The list is flat, so it cannot cycle and cannot name a variant twice
/// without saying so; `VARIANT_COUNT` is what fails the sweep when a new
/// variant is not sampled at all. The compiler's share of this is `localized`
/// above: no wildcard arm, so a variant that renders nothing does not build.
#[cfg(test)]
impl super::Samples for SystemMessage {
    const VARIANT_COUNT: usize = 18;

    fn samples() -> Vec<Self> {
        use SystemMessage::*;
        vec![
            ConfirmDaemonMode,
            SystemdNotDetected,
            SystemdDeclined,
            SystemdSkippedFlag,
            SystemdFromCommandLine,
            DaemonRestarted,
            DaemonRunning,
            DaemonNotReady { seconds: 20 },
            RetiredFacelockGroup,
            DisablingSystemdUnits,
            SystemdUnitsDisabled,
            ValidatingSystemAssets,
            RemovedLegacySystemAsset { path: s("/p") },
            PreservedLocalDbusPolicy { path: s("/p") },
            SystemAssetsValidated,
            SystemctlDaemonReloadDone,
            SystemctlEnableDone {
                unit: s("u.service"),
            },
            DbusActivationEnabled,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unit-install narration, pinned to the bytes `run_systemd`
    /// printed. `facelock setup --systemd` is a scripted entry point
    /// (packaging, Omarchy), so these lines are read by more than humans.
    #[test]
    fn system_fallback_is_byte_identical() {
        use SystemMessage::*;

        assert_eq!(
            DisablingSystemdUnits.localized(),
            "Disabling facelock-daemon systemd units..."
        );
        assert_eq!(
            SystemdUnitsDisabled.localized(),
            "facelock-daemon service disabled and stopped."
        );
        assert_eq!(
            ValidatingSystemAssets.localized(),
            "Validating installed facelock-daemon systemd and D-Bus assets..."
        );
        assert_eq!(
            RemovedLegacySystemAsset {
                path: "/etc/systemd/system/facelock-daemon.service".into()
            }
            .localized(),
            "  Removed exact known legacy /etc/systemd/system/facelock-daemon.service"
        );
        assert_eq!(
            PreservedLocalDbusPolicy {
                path: "/etc/dbus-1/system.d/90-facelock-admin.conf".into()
            }
            .localized(),
            "  Preserved merged local D-Bus policy /etc/dbus-1/system.d/90-facelock-admin.conf; review it if Facelock bus authorization is unexpected."
        );
        assert_eq!(
            SystemAssetsValidated.localized(),
            "  Installed systemd and D-Bus assets validated."
        );
        assert_eq!(
            SystemctlDaemonReloadDone.localized(),
            "  systemctl daemon-reload done."
        );
        assert_eq!(
            SystemctlEnableDone {
                unit: "facelock-daemon.service".into()
            }
            .localized(),
            "  systemctl enable facelock-daemon.service done."
        );
        assert_eq!(
            DbusActivationEnabled.localized(),
            "\nfacelock-daemon D-Bus activation is now enabled."
        );
    }
}
