pub mod audit;
pub mod auth;
pub mod bench;
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
pub mod test_cmd;
pub mod tpm;

use clap::Subcommand;

#[derive(Subcommand)]
pub enum TpmCommand {
    /// Report TPM availability and configuration
    Status,
    /// Seal the AES encryption key with TPM (migrate keyfile → tpm)
    SealKey,
    /// Unseal the AES key from TPM back to a plaintext keyfile (migrate tpm → keyfile)
    UnsealKey,
    /// Read-only check that the sealed AES key currently unseals (verifies PCR
    /// policy is satisfied). Writes nothing; exits non-zero if unseal fails.
    UnsealCheck,
    /// Display current PCR values for configured indices
    PcrBaseline,
}
