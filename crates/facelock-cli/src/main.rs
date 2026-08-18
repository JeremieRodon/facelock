//! The `facelock` binary: clap wiring plus top-level dispatch into the
//! `facelock_cli` library. The domain layer (backend, health, message,
//! resolved, logging, …) lives in `lib.rs` so it stays testable and shareable
//! (gap D6); this file keeps only the `Cli`/`Commands` types and `main`.
//!
//! The conformance suites that check this surface live in [`conformance`] —
//! flag spelling, the capability predicates, and reference-doc coverage. They
//! are bin-crate tests rather than integration tests because each one asks a
//! question of `Cli::command()`, and only the binary declares that tree.

mod args;
#[cfg(test)]
mod conformance;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use facelock_cli::commands::TpmCommand;
use facelock_cli::commands::bench::BenchCommand;
use facelock_cli::commands::config::ConfigCommand;
use facelock_cli::commands::daemon::DaemonCommand;
use facelock_cli::commands::hyprlock::HyprlockCommand;
use facelock_cli::commands::setup::{SetupArgs, resolve_setup_plan};
use facelock_cli::{commands, logging, message, notifications, resolved};

use args::{ConfirmArg, JsonArg, PamCli, SetupCli, UserArg};

#[derive(Parser)]
#[command(name = "facelock", about = "Linux face authentication", version)]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', long, global = true)]
    config: Option<String>,
    /// Suppress informational stdout; errors, prompts and exit codes are unchanged
    #[arg(short = 'q', long, global = true)]
    quiet: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Download models and create directories
    Setup(SetupCli),
    /// Report whether a user has a usable face enrollment (exit 0 = enrolled, 1 = not enrolled, 2 = error)
    IsEnrolled {
        #[command(flatten)]
        user: UserArg,
        #[command(flatten)]
        json: JsonArg,
    },
    /// Report what this build can do, as capability names (--json for a machine-readable document)
    Capabilities {
        #[command(flatten)]
        json: JsonArg,
    },
    /// Capture and store a face
    Enroll {
        #[command(flatten)]
        user: UserArg,
        /// Label for this face model
        #[arg(short, long)]
        label: Option<String>,
        /// Skip the setup completion check
        #[arg(long)]
        skip_setup_check: bool,
    },
    /// Remove a face model
    Remove {
        /// Model ID to remove
        model_id: u32,
        #[command(flatten)]
        user: UserArg,
        #[command(flatten)]
        confirm: ConfirmArg,
    },
    /// Remove all face models for a user
    Clear {
        #[command(flatten)]
        user: UserArg,
        #[command(flatten)]
        confirm: ConfirmArg,
    },
    /// List enrolled face models
    List {
        #[command(flatten)]
        user: UserArg,
        #[command(flatten)]
        json: JsonArg,
    },
    /// Test face recognition
    Test {
        #[command(flatten)]
        user: UserArg,
    },
    /// Live camera preview with detection overlay
    // `--text-only` is the name this flag shipped under, and it always
    // emitted JSON — one object per frame. `mut_arg` re-labels the shared
    // `JsonArg` here rather than a second declaration of the flag, so the
    // spelling still comes from one struct and `cli_flag_conformance` still
    // sees an arg with id `json`. The alias is hidden: it parses forever, and
    // `--help` teaches the one spelling.
    #[command(mut_arg("json", |arg: clap::Arg| arg
        .alias("text-only")
        .help("Print one JSON object per frame instead of the graphical preview")))]
    Preview {
        #[command(flatten)]
        json: JsonArg,
        #[command(flatten)]
        user: UserArg,
    },
    /// Show or edit configuration
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommand>,
    },
    /// Check system status
    Status,
    /// List available camera devices
    Devices {
        #[command(flatten)]
        json: JsonArg,
    },
    /// Run or restart the persistent authentication daemon
    Daemon {
        #[command(subcommand)]
        command: Option<DaemonCommand>,
    },
    /// One-shot authentication (used by PAM module)
    Auth {
        // Required, unlike every other `--user`, and so not a `UserArg`:
        // `pam_facelock.so` names the subject explicitly and must never fall
        // back to the process owner. A plain comment, not a doc comment, so
        // `auth --help` keeps clap's short template.
        /// Username to authenticate
        #[arg(short = 'u', long)]
        user: String,
    },
    /// Benchmark and calibration tools
    Bench {
        #[command(subcommand)]
        command: BenchCommand,
    },
    /// Manage the encryption key and the TPM that can seal it (key material, TPM or not)
    Tpm {
        #[command(subcommand)]
        command: TpmCommand,
    },
    /// Manage the facelock line in /etc/pam.d service files
    Pam {
        #[command(subcommand)]
        command: PamCli,
    },
    /// Manage hyprlock lock-screen integration (no root required)
    Hyprlock {
        #[command(subcommand)]
        command: HyprlockCommand,
    },
    /// View structured audit log
    Audit {
        /// Follow mode: watch for new entries
        #[arg(short = 'f', long)]
        follow: bool,
        /// Number of recent entries to show
        #[arg(short, long, default_value = "20")]
        lines: usize,
    },
}

fn main() -> anyhow::Result<()> {
    // Localization first: user-facing text (D10) may render before any
    // subcommand dispatch. Log/tracing output is unaffected by design (D2).
    message::init();

    let Cli {
        config,
        quiet,
        command,
    } = Cli::parse();

    // `--config` is declared once, `global = true`, so it is accepted on either
    // side of the subcommand and lands here whichever side it was given on.
    // This override is also how the path reaches the daemon: startup, the live
    // reload and the mtime watch all resolve through it.
    if let Some(path) = config.as_deref() {
        facelock_core::paths::set_process_config_override(PathBuf::from(path));
    }

    // `--quiet` is likewise global, and lands at the message sink rather than
    // at any call site: it silences the two suppressible stdout sinks
    // (`Terminal::info` for human text, `message::payload` for machine
    // output) and nothing else, so errors, prompts, exit codes and the
    // `RUST_LOG` event stream are unchanged. Written unconditionally so the
    // global is initialised exactly once, on either branch.
    message::set_verbosity(if quiet {
        message::Verbosity::Quiet
    } else {
        message::Verbosity::Normal
    });

    match command {
        // Daemon and auth init their own tracing, so handle them separately.
        //
        // The whole `daemon` group is dispatched here, in one arm, even though
        // only `run` needs to precede the tracing init. Splitting it across
        // two levels of this match — `run` here, `restart` in the D7 block —
        // is what let a future `DaemonCommand::Reload` compile and then panic
        // on the `unreachable!()` arm below. Matched exhaustively on
        // `DaemonCommand` in one place, a new verb is a compile error at this
        // `match` instead. The duplicated `init_stderr` line is that guarantee's
        // whole cost.
        //
        // Bare `facelock daemon` is `daemon run`: the five init-system units
        // and setup.rs's `ExecStart` marker all invoke the bare form (ADR 009 §4).
        Commands::Daemon { command } => match command {
            None | Some(DaemonCommand::Run) => {
                commands::daemon::run(notifications::daemon_notifier_factory())
            }
            // `restart` only talks to systemd: no parsed Config, and nothing
            // from the D7 block it used to sit in except this tracing init
            // (`message::init` already ran at the top of `main`, for every
            // command alike).
            Some(DaemonCommand::Restart) => {
                logging::init_stderr(false);
                commands::daemon::restart()
            }
        },
        Commands::Auth { user } => {
            // `auth` is its own one-shot process and loads the config itself,
            // so it takes the explicit path rather than re-deriving it.
            let exit_code = commands::auth::run(user, config);
            std::process::exit(exit_code);
        }
        other => {
            // Default tracing init for all other commands. Diagnostics land on
            // stderr, which is what leaves stdout free for the payload these
            // commands print — `devices --json`, `list --json`,
            // `is-enrolled --json` (#149). See `crate::logging`.
            logging::init_stderr(false);

            match other {
                // -- Dispatched before the shared config parse (D7). --
                //
                // `is-enrolled` runs unprivileged on lock screens and must stay
                // in front of all config/resolution machinery: it tolerates a
                // missing or broken config and probes nothing (see
                // commands/is_enrolled.rs). `hyprlock` edits the user's own
                // dotfiles and `config` operates on the config file itself —
                // neither consumes a parsed Config.
                //
                // `capabilities` reports on the binary itself — its own clap
                // tree and constants. It reads no file at all, so it sits
                // ahead even of `is-enrolled`, which at least opens a marker.
                Commands::Capabilities { json } => {
                    commands::capabilities::run(json.json);
                    Ok(())
                }
                Commands::IsEnrolled { user, json } => {
                    std::process::exit(commands::is_enrolled::run(user.user, json.json))
                }
                // `pam` reads the config for itself, best-effort, and that
                // is why it is still dispatched here rather than below: it
                // needs `[pam] config_dirs` to know which directories a
                // service name resolves through, and it must keep working
                // when that file is missing or broken — `add`/`remove` edit
                // `/etc/pam.d` and `status` reads it, and an unrelated config
                // mistake is not a reason to stop an operator repairing an
                // auth stack. A failed read yields the default search path;
                // see `commands::pam::PamDirs::system`. Its exit code is its
                // own — `status` answers on grep's 0/1/2 scale — so it exits
                // here rather than returning `()`.
                Commands::Pam { command } => {
                    std::process::exit(commands::pam::run(command.into())?)
                }
                Commands::Hyprlock { command } => commands::hyprlock::run(command),
                // `config show` (and bare `config`) is the unprivileged read
                // DEC-6 lists; `config edit` takes root inside the command,
                // ahead of the editor (C6).
                Commands::Config { command } => commands::config::run(command),

                // Setup bootstraps the config file — creates the default when
                // missing and edits it in place — so it owns its own load; see
                // the commented sites in commands/setup.rs.
                Commands::Setup(setup) => {
                    commands::setup::run_with_plan(resolve_setup_plan(SetupArgs::from(setup)))
                }

                other => {
                    // The one parse for this process (D7): every remaining
                    // command consumes this Config and none re-reads the file.
                    let loaded = resolved::ConfigLoad::read();

                    // `status` reports on the config file itself, so a load
                    // failure is a finding to render, not an exit.
                    if matches!(other, Commands::Status) {
                        return commands::status::run(loaded);
                    }
                    let config = loaded.require()?;

                    match other {
                        Commands::Enroll {
                            user,
                            label,
                            skip_setup_check,
                        } => commands::enroll::run(&config, user.user, label, skip_setup_check),
                        Commands::Remove {
                            model_id,
                            user,
                            confirm,
                        } => commands::remove::run(&config, model_id, user.user, confirm.yes),
                        Commands::Clear { user, confirm } => {
                            commands::clear::run(&config, user.user, confirm.yes)
                        }
                        Commands::List { user, json } => {
                            commands::list::run(&config, user.user, json.json)
                        }
                        Commands::Test { user } => commands::test_cmd::run(&config, user.user),
                        Commands::Preview { json, user } => {
                            commands::preview::run(&config, json.json, user.user)
                        }
                        Commands::Devices { json } => commands::devices::run(&config, json.json),
                        Commands::Bench { command } => commands::bench::run(&config, command),
                        // `tpm encrypt|decrypt|reseal` land here, which is
                        // where the top-level spellings landed before the
                        // rename: they take the one parsed Config (D7).
                        Commands::Tpm { command } => commands::tpm::run(&config, command),
                        Commands::Audit { follow, lines } => {
                            commands::audit::run(&config, follow, lines)
                        }
                        // Already handled above. `Daemon` is dispatched
                        // exhaustively in the top-level match, so this arm
                        // cannot be reached by any `DaemonCommand`; it stays
                        // only because `other` is typed `Commands` and this
                        // match must still cover every variant of it.
                        Commands::Daemon { .. }
                        | Commands::Auth { .. }
                        | Commands::IsEnrolled { .. }
                        | Commands::Capabilities { .. }
                        | Commands::Pam { .. }
                        | Commands::Hyprlock { .. }
                        | Commands::Config { .. }
                        | Commands::Setup(..)
                        | Commands::Status => unreachable!(),
                    }
                }
            }
        }
    }
}
