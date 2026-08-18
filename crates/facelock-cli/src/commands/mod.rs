pub mod audit;
pub mod auth;
pub mod bench;
pub mod capabilities;
pub mod clear;
pub mod config;
pub mod daemon;
pub mod devices;
pub mod encrypt;
pub mod enroll;
pub mod enrollment_marker;
pub mod hyprlock;
pub mod is_enrolled;
pub mod list;
pub mod pam;
pub mod preview;
pub mod remove;
pub mod setup;
pub mod status;
pub mod status_json;
pub mod test_cmd;
pub mod tpm;

/// Re-exported so the historical `commands::TpmCommand` path keeps working;
/// the enum itself lives beside its dispatcher in [`tpm`].
pub use tpm::TpmCommand;
