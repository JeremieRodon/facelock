//! Shared clap argument groups for the `facelock` binary.
//!
//! Flag spelling is a compatibility surface — `pam_facelock.so` spawns a
//! `facelock auth` argv byte for byte, and wrapper scripts hard-code the rest —
//! but it was previously re-declared per command, so it drifted: `--user` had
//! `-u` on six commands and not on `auth`, `--yes` accepted `--no-confirm` on
//! `setup` alone. One struct per flag family removes the opportunity: a command
//! flattens the family or does not offer the flag, and cannot spell it a third
//! way. `cli_flag_conformance` in `main.rs` fails the build if one tries.
//!
//! These types are deliberately bin-private (declared by `main.rs`, absent from
//! `lib.rs`). Nothing outside the binary consumes clap types.

use clap::{Args, Subcommand};

use facelock_cli::commands::pam::{PamAction, PamRequest};
use facelock_cli::commands::setup::{
    EncryptionChoice, ExecutionProviderChoice, ModelPreset, SetupArgs,
};

/// The user a command operates on.
#[derive(Args)]
pub struct UserArg {
    /// Username (default: current user)
    #[arg(short = 'u', long)]
    pub user: Option<String>,
}

/// Confirmation bypass for the commands whose only prompt is "are you sure?" —
/// `remove` and `clear`. `setup` deliberately declares its own `yes` instead,
/// because there the flag also unlocks a gate; see [`SetupCli`].
///
/// `--no-confirm` shipped on `setup` only; it is carried as a hidden alias on
/// every site so a wrapper written against either spelling keeps working.
#[derive(Args)]
pub struct ConfirmArg {
    /// Skip confirmation prompts (also: --no-confirm)
    #[arg(short = 'y', long, alias = "no-confirm")]
    pub yes: bool,
}

/// Machine-readable output. The payload goes to stdout and nothing else does —
/// see `docs/contracts.md`, "CLI Output Streams".
#[derive(Args)]
pub struct JsonArg {
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

/// Declared ahead of its first consumer so the spelling is fixed once rather
/// than invented per command: the destructive commands flatten it in gap G3
/// (#168). No `#[allow(dead_code)]` is needed in the meantime — the derived
/// `FromArgMatches` reads the field, so it does not read as dead.
#[derive(Args)]
pub struct DryRunArg {
    /// Report what would change, and change nothing
    #[arg(long)]
    pub dry_run: bool,
}

/// `facelock setup`'s command line.
///
/// Its only job is to become a [`SetupArgs`]. Naming the 16 fields once means
/// `main` and the tests reach the resolver through the same conversion; when
/// they were two hand-written destructures, a field added to one could be
/// silently missing from the other.
#[derive(Args)]
pub struct SetupCli {
    /// Run in non-interactive mode (skip wizard)
    #[arg(long)]
    pub non_interactive: bool,
    // Not a shared `ConfirmArg`: on `setup` the flag means more than it does
    // elsewhere. It skips the per-file "Proceed?" prompt *and* unlocks the
    // gate that otherwise refuses to write into a sensitive PAM service
    // (`SENSITIVE_SERVICES` in commands/pam.rs). Rendering that as plain
    // prompt suppression would understate what the user is authorizing.
    // Spelling still cannot drift: `cli_flag_conformance` pins `-y` and the
    // `no-confirm` alias on every arg named `yes`, wherever it is declared.
    /// Skip confirmation prompts, and unlock the system-auth/login/sshd gate (also: --no-confirm)
    #[arg(short = 'y', long, alias = "no-confirm")]
    pub yes: bool,

    // -- Action pairs. A later flag wins over an earlier one, so a wrapper
    //    script can append an override to a command it did not construct.
    /// Install or manage PAM module configuration
    #[arg(long, overrides_with = "no_pam")]
    pub pam: bool,
    /// Do not touch PAM configuration at all (no prompt, no write)
    #[arg(long = "no-pam", overrides_with = "pam")]
    pub no_pam: bool,
    /// Install and enable systemd units
    #[arg(long, overrides_with = "no_systemd")]
    pub systemd: bool,
    /// Do not install or enable systemd units
    #[arg(long = "no-systemd", overrides_with = "systemd")]
    pub no_systemd: bool,
    /// Enroll a face during setup
    #[arg(long, overrides_with = "no_enroll")]
    pub enroll: bool,
    /// Do not enroll a face during setup
    #[arg(long = "no-enroll", overrides_with = "enroll")]
    pub no_enroll: bool,

    // -- Action modifiers
    /// Used with --systemd: disable and stop systemd units instead
    #[arg(long, requires = "systemd")]
    pub disable: bool,
    /// Used with --pam: target PAM service (default: sudo)
    #[arg(long, requires = "pam")]
    pub service: Option<String>,
    /// Used with --pam: remove the PAM line instead of adding it
    #[arg(long, requires = "pam")]
    pub remove: bool,
    /// Used with --pam --remove: treat an absent service file as success
    #[arg(long = "if-present", requires = "remove")]
    pub if_present: bool,

    // -- Choice flags. Supplying a value answers the question, and so skips
    //    the matching wizard step.
    /// Camera device path, or `auto` to re-detect from hardware
    #[arg(long)]
    pub camera: Option<String>,
    /// Model quality preset
    #[arg(long, value_enum)]
    pub models: Option<ModelPreset>,
    /// ONNX Runtime execution provider
    #[arg(long, value_enum)]
    pub execution_provider: Option<ExecutionProviderChoice>,
    /// Embedding encryption method
    #[arg(long, value_enum)]
    pub encryption: Option<EncryptionChoice>,
}

impl From<SetupCli> for SetupArgs {
    fn from(cli: SetupCli) -> Self {
        let SetupCli {
            non_interactive,
            yes,
            pam,
            no_pam,
            systemd,
            no_systemd,
            enroll,
            no_enroll,
            disable,
            service,
            remove,
            if_present,
            camera,
            models,
            execution_provider,
            encryption,
        } = cli;
        SetupArgs {
            non_interactive,
            yes,
            pam,
            no_pam,
            systemd,
            no_systemd,
            enroll,
            no_enroll,
            disable,
            service,
            remove,
            if_present,
            camera,
            models,
            execution_provider,
            encryption,
        }
    }
}

/// The services a `facelock pam` verb acts on.
///
/// Repeatable, which is the point: the old `setup --pam --service X` took one
/// `Option<String>`, so configuring three services meant three processes, three
/// root checks and no atomicity across them. Empty means `sudo`, preserving
/// what bare `--pam` has always meant.
#[derive(Args)]
pub struct PamServiceArg {
    /// PAM service to act on; repeat for several (default: sudo)
    #[arg(long, num_args = 1, action = clap::ArgAction::Append, value_name = "SERVICE")]
    pub service: Vec<String>,
}

/// `facelock pam add | remove | status`.
///
/// Becomes a [`PamRequest`], the same way [`SetupCli`] becomes a [`SetupArgs`]:
/// clap types stay in the binary, and the library sees plain data it can also
/// construct in a test.
#[derive(Subcommand)]
pub enum PamCli {
    /// Add the facelock line to one or more /etc/pam.d service files
    #[command(after_help = "\
--yes/--no-confirm only skips the per-file confirmation. Editing the sensitive \
services system-auth, login or sshd additionally requires --allow-sensitive; \
neither flag implies the other. Every service is validated before any file is \
written, so a rejected service leaves the rest untouched.")]
    Add {
        #[command(flatten)]
        service: PamServiceArg,
        #[command(flatten)]
        confirm: ConfirmArg,
        /// Also permit the sensitive services: system-auth, login, sshd
        #[arg(long)]
        allow_sensitive: bool,
        /// Treat a missing service file as success instead of an error
        #[arg(long = "if-present")]
        if_present: bool,
        #[command(flatten)]
        dry_run: DryRunArg,
        #[command(flatten)]
        json: JsonArg,
    },
    /// Remove the facelock line from one or more /etc/pam.d service files
    #[command(after_help = "\
Removal is never gated by the sensitive-service list and never prompts — it can \
only take away a way to authenticate, and the .facelock-backup file written by \
`add` is left in place. --yes/--no-confirm is accepted for symmetry with `add`.")]
    Remove {
        #[command(flatten)]
        service: PamServiceArg,
        #[command(flatten)]
        confirm: ConfirmArg,
        /// Treat a missing service file as success instead of an error
        #[arg(long = "if-present")]
        if_present: bool,
        #[command(flatten)]
        dry_run: DryRunArg,
        #[command(flatten)]
        json: JsonArg,
    },
    /// Report whether services carry the facelock line (exit 0 = all do, 1 = one does not, 2 = error)
    #[command(after_help = "\
Reads only; needs no root. This is the probe to branch on instead of grepping \
/etc/pam.d yourself.")]
    Status {
        #[command(flatten)]
        service: PamServiceArg,
        #[command(flatten)]
        json: JsonArg,
    },
}

impl From<PamCli> for PamRequest {
    fn from(cli: PamCli) -> Self {
        match cli {
            PamCli::Add {
                service,
                confirm,
                allow_sensitive,
                if_present,
                dry_run,
                json,
            } => PamRequest {
                action: PamAction::Add,
                services: service.service,
                no_confirm: confirm.yes,
                allow_sensitive,
                if_present,
                dry_run: dry_run.dry_run,
                json: json.json,
            },
            PamCli::Remove {
                service,
                confirm,
                if_present,
                dry_run,
                json,
            } => PamRequest {
                action: PamAction::Remove,
                services: service.service,
                no_confirm: confirm.yes,
                allow_sensitive: false,
                if_present,
                dry_run: dry_run.dry_run,
                json: json.json,
            },
            PamCli::Status { service, json } => PamRequest {
                action: PamAction::Status,
                services: service.service,
                json: json.json,
                ..PamRequest::default()
            },
        }
    }
}
