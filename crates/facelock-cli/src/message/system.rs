//! Wiring facelock into the system: the daemon unit and the `facelock` group.

#[cfg(test)]
use super::sample_text as s;
use super::{Message, fill, translate};

/// Daemon unit and `facelock` group setup.
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
    SystemdDeferred,

    // -- the facelock system group --
    CreatingFacelockGroup,

    // -- installing and removing the unit files --
    DisablingSystemdUnits,
    SystemdUnitsDisabled,
    InstallingSystemdUnits,
    WroteFile { path: String },
    RefreshedLegacyFile { path: String },
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
            SystemdDeferred => {
                translate("  Answered on the command line; applied once setup finishes.")
            }
            CreatingFacelockGroup => translate("  Creating 'facelock' system group..."),
            DisablingSystemdUnits => translate("Disabling facelock-daemon systemd units..."),
            SystemdUnitsDisabled => translate("facelock-daemon service disabled and stopped."),
            InstallingSystemdUnits => {
                translate("Installing facelock-daemon systemd and D-Bus units...")
            }
            WroteFile { path } => fill(translate("  Wrote {path}"), &[("path", path.clone())]),
            RefreshedLegacyFile { path } => fill(
                translate("  Refreshed legacy {path}"),
                &[("path", path.clone())],
            ),
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
    const VARIANT_COUNT: usize = 14;

    fn samples() -> Vec<Self> {
        use SystemMessage::*;
        vec![
            ConfirmDaemonMode,
            SystemdNotDetected,
            SystemdDeclined,
            SystemdSkippedFlag,
            SystemdDeferred,
            CreatingFacelockGroup,
            DisablingSystemdUnits,
            SystemdUnitsDisabled,
            InstallingSystemdUnits,
            WroteFile { path: s("/p") },
            RefreshedLegacyFile { path: s("/p") },
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
            InstallingSystemdUnits.localized(),
            "Installing facelock-daemon systemd and D-Bus units..."
        );
        assert_eq!(
            WroteFile {
                path: "/etc/systemd/system/facelock-daemon.service".into()
            }
            .localized(),
            "  Wrote /etc/systemd/system/facelock-daemon.service"
        );
        assert_eq!(
            RefreshedLegacyFile {
                path: "/usr/lib/systemd/system/facelock-daemon.service".into()
            }
            .localized(),
            "  Refreshed legacy /usr/lib/systemd/system/facelock-daemon.service"
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
