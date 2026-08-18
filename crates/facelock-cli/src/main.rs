//! The `facelock` binary: clap wiring plus top-level dispatch into the
//! `facelock_cli` library. The domain layer (backend, health, message,
//! resolved, logging, …) lives in `lib.rs` so it stays testable and shareable
//! (gap D6); this file keeps only the `Cli`/`Commands` types and `main`.

mod args;

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
                // `pam` consumes no `Config` either: `add`/`remove` edit
                // `/etc/pam.d` and `status` reads it, and neither wants a
                // missing or broken config file to be the thing that stops
                // them. Its exit code is its own — `status` answers on grep's
                // 0/1/2 scale — so it exits here rather than returning `()`.
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

#[cfg(test)]
mod tests {
    use clap::CommandFactory;

    use super::*;
    use commands::setup::{
        BaseMode, CameraChoice, EncryptionChoice, ExecutionProviderChoice, ModelPreset, PamPref,
        SetupPlan, SystemdPref,
    };

    #[test]
    fn verify_cli() {
        // Validates the clap derive structure
        Cli::command().debug_assert();
    }

    /// Parse a `facelock setup ...` command line and resolve it, exercising the
    /// exact path `main` takes. Pure: no root, no camera, no network.
    fn plan(args: &[&str]) -> SetupPlan {
        let argv: Vec<&str> = ["facelock", "setup"].iter().chain(args).copied().collect();
        let cli = Cli::try_parse_from(argv).expect("expected these args to parse");
        let Commands::Setup(setup) = cli.command else {
            panic!("expected the Setup variant");
        };
        resolve_setup_plan(SetupArgs::from(setup))
    }

    fn parse_error(args: &[&str]) -> clap::Error {
        let argv: Vec<&str> = ["facelock", "setup"].iter().chain(args).copied().collect();
        Cli::try_parse_from(argv)
            .err()
            .expect("expected a parse error")
    }

    fn install(service: Option<&str>) -> PamPref {
        PamPref::Install {
            service: service.map(str::to_string),
        }
    }

    // -----------------------------------------------------------------------
    // §2.4 compatibility matrix — one test per row.
    // -----------------------------------------------------------------------

    #[test]
    fn matrix_row_bare_setup_is_the_full_wizard() {
        assert_eq!(plan(&[]), SetupPlan::default());
        // Spelled out, since `default()` is what every other row is diffed against.
        let p = plan(&[]);
        assert_eq!(p.base, Some(BaseMode::Wizard));
        assert_eq!(p.systemd, SystemdPref::Ask);
        assert_eq!(p.pam, PamPref::Ask);
        assert_eq!(p.enroll, None);
        assert_eq!(p.camera, None);
        assert_eq!(p.models, None);
        assert_eq!(p.execution_provider, None);
        assert_eq!(p.encryption, None);
        assert!(!p.yes);
    }

    #[test]
    fn matrix_row_non_interactive_skips_every_action() {
        let p = plan(&["--non-interactive"]);
        assert_eq!(p.base, Some(BaseMode::NonInteractive));
        // Ask under a non-interactive base means "do nothing", as today.
        assert_eq!(p.systemd, SystemdPref::Ask);
        assert_eq!(p.pam, PamPref::Ask);
        assert_eq!(p.enroll, None);
    }

    #[test]
    fn matrix_row_pam_with_service_is_standalone() {
        let p = plan(&["--pam", "--service", "sudo"]);
        assert_eq!(p.base, None);
        assert_eq!(p.pam, install(Some("sudo")));
        assert_eq!(p.systemd, SystemdPref::Ask);
    }

    /// Standalone `--pam` / `--systemd` must NOT go through the interactive
    /// root pre-check: it prompts and re-execs under sudo on a TTY, which those
    /// invocations never did. They bail from their own root checks instead.
    /// A base setup, which always did prompt, still must.
    #[test]
    fn only_a_base_setup_takes_the_interactive_root_precheck() {
        for args in [
            vec!["--pam"],
            vec!["--pam", "--service", "sudo"],
            vec!["--pam", "--remove"],
            vec!["--systemd"],
            vec!["--systemd", "--disable"],
            vec!["--systemd", "--pam"],
        ] {
            let p = plan(&args);
            assert_eq!(p.base, None, "{args:?} must stay standalone");
            assert!(
                !commands::setup::needs_root_precheck(&p),
                "{args:?} must not trigger the sudo re-exec prompt"
            );
        }

        for args in [
            vec![],
            vec!["--non-interactive"],
            vec!["--no-pam"],
            vec!["--non-interactive", "--pam"],
            vec!["--camera", "auto"],
        ] {
            let p = plan(&args);
            assert!(
                commands::setup::needs_root_precheck(&p),
                "{args:?} runs a base setup and must keep the root pre-check"
            );
        }
    }

    #[test]
    fn matrix_row_systemd_is_standalone() {
        let p = plan(&["--systemd"]);
        assert_eq!(p.base, None);
        assert_eq!(p.systemd, SystemdPref::Install);
        assert_eq!(p.pam, PamPref::Ask);
    }

    #[test]
    fn matrix_row_systemd_and_pam_runs_both() {
        // Today `--pam` is silently dropped here.
        let p = plan(&["--systemd", "--pam"]);
        assert_eq!(p.base, None);
        assert_eq!(p.systemd, SystemdPref::Install);
        assert_eq!(p.pam, install(None));
    }

    #[test]
    fn matrix_row_non_interactive_and_pam_runs_base_and_pam() {
        // Today `--non-interactive` is silently dropped here.
        let p = plan(&["--non-interactive", "--pam"]);
        assert_eq!(p.base, Some(BaseMode::NonInteractive));
        assert_eq!(p.pam, install(None));
    }

    #[test]
    fn matrix_row_no_pam_suppresses_step_nine() {
        let p = plan(&["--no-pam"]);
        assert_eq!(p.base, Some(BaseMode::Wizard));
        assert_eq!(p.pam, PamPref::Skip);
    }

    #[test]
    fn matrix_row_yes_with_execution_provider() {
        let p = plan(&["-y", "--execution-provider=cuda"]);
        assert_eq!(p.base, Some(BaseMode::Wizard));
        assert!(p.yes);
        assert_eq!(p.execution_provider, Some(ExecutionProviderChoice::Cuda));
    }

    // -----------------------------------------------------------------------
    // Action modifiers
    // -----------------------------------------------------------------------

    #[test]
    fn pam_remove_with_explicit_service() {
        let p = plan(&["--pam", "--remove", "--service", "sudo"]);
        assert_eq!(p.base, None);
        assert_eq!(
            p.pam,
            PamPref::Remove {
                service: "sudo".to_string(),
                if_present: false,
            }
        );
    }

    #[test]
    fn pam_remove_defaults_to_sudo() {
        // Removal needs a concrete service, so the default is applied eagerly.
        assert_eq!(
            plan(&["--pam", "--remove"]).pam,
            PamPref::Remove {
                service: "sudo".to_string(),
                if_present: false,
            }
        );
    }

    #[test]
    fn pam_remove_if_present_reaches_the_resolved_plan() {
        assert_eq!(
            plan(&[
                "--pam",
                "--service",
                "omarchy-lock-face",
                "--remove",
                "--if-present",
            ])
            .pam,
            PamPref::Remove {
                service: "omarchy-lock-face".to_string(),
                if_present: true,
            }
        );
    }

    #[test]
    fn systemd_disable_is_standalone() {
        let p = plan(&["--systemd", "--disable"]);
        assert_eq!(p.base, None);
        assert_eq!(p.systemd, SystemdPref::Disable);
    }

    // -----------------------------------------------------------------------
    // `overrides_with`: the later flag wins for every action pair.
    // -----------------------------------------------------------------------

    #[test]
    fn later_pam_flag_wins() {
        assert_eq!(plan(&["--pam", "--no-pam"]).pam, PamPref::Skip);
        assert_eq!(plan(&["--no-pam", "--pam"]).pam, install(None));
    }

    #[test]
    fn later_systemd_flag_wins() {
        assert_eq!(
            plan(&["--systemd", "--no-systemd"]).systemd,
            SystemdPref::Skip
        );
        assert_eq!(
            plan(&["--no-systemd", "--systemd"]).systemd,
            SystemdPref::Install
        );
    }

    #[test]
    fn later_enroll_flag_wins() {
        assert_eq!(plan(&["--enroll", "--no-enroll"]).enroll, Some(false));
        assert_eq!(plan(&["--no-enroll", "--enroll"]).enroll, Some(true));
    }

    // -----------------------------------------------------------------------
    // Choice flags
    // -----------------------------------------------------------------------

    #[test]
    fn choice_flag_forces_the_base_setup_to_run() {
        // The regression guard: `--camera` must not be silently dropped in
        // favour of PAM-only mode the way the old `else if` chain did.
        let p = plan(&["--camera=/dev/video2", "--pam"]);
        assert_eq!(p.base, Some(BaseMode::Wizard));
        assert_eq!(p.pam, install(None));
        assert_eq!(
            p.camera,
            Some(CameraChoice::Path("/dev/video2".to_string()))
        );
    }

    #[test]
    fn camera_auto_is_distinct_from_a_path() {
        assert_eq!(plan(&["--camera", "auto"]).camera, Some(CameraChoice::Auto));
        assert_eq!(
            plan(&["--camera", "/dev/video2"]).camera,
            Some(CameraChoice::Path("/dev/video2".to_string()))
        );
    }

    #[test]
    fn models_preset_parses() {
        assert_eq!(plan(&["--models", "high"]).models, Some(ModelPreset::High));
        assert_eq!(
            plan(&["--models", "balanced"]).models,
            Some(ModelPreset::Balanced)
        );
        assert_eq!(
            plan(&["--models", "standard"]).models,
            Some(ModelPreset::Standard)
        );
    }

    #[test]
    fn encryption_choice_parses() {
        assert_eq!(
            plan(&["--encryption", "tpm"]).encryption,
            Some(EncryptionChoice::Tpm)
        );
        assert_eq!(
            plan(&["--encryption", "auto"]).encryption,
            Some(EncryptionChoice::Auto)
        );
        assert_eq!(
            plan(&["--encryption", "none"]).encryption,
            Some(EncryptionChoice::None)
        );
    }

    // -----------------------------------------------------------------------
    // Action modifiers require their action. Today these are silently dropped.
    // -----------------------------------------------------------------------

    #[test]
    fn remove_without_pam_is_a_parse_error() {
        assert_eq!(
            parse_error(&["--remove"]).kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn if_present_requires_remove_and_pam() {
        for args in [
            &["--if-present"][..],
            &["--pam", "--if-present"],
            &["--remove", "--if-present"],
        ] {
            assert_eq!(
                parse_error(args).kind(),
                clap::error::ErrorKind::MissingRequiredArgument,
                "unexpected error kind for {args:?}"
            );
        }
    }

    #[test]
    fn setup_help_documents_if_present() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("setup")
            .expect("setup subcommand")
            .render_long_help()
            .to_string();

        assert!(help.contains("--if-present"));
        assert!(help.contains("treat an absent service file as success"));
    }

    #[test]
    fn service_without_pam_is_a_parse_error() {
        assert_eq!(
            parse_error(&["--service", "sudo"]).kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    #[test]
    fn disable_without_systemd_is_a_parse_error() {
        assert_eq!(
            parse_error(&["--disable"]).kind(),
            clap::error::ErrorKind::MissingRequiredArgument
        );
    }

    // -----------------------------------------------------------------------
    // is-enrolled
    // -----------------------------------------------------------------------

    /// Clap derives the subcommand name from the variant, so `IsEnrolled` must
    /// spell itself `is-enrolled` on the command line.
    #[test]
    fn is_enrolled_flags_parse() {
        let cli = Cli::try_parse_from([
            "facelock",
            "is-enrolled",
            "--user",
            "alice",
            "--json",
            "--quiet",
        ])
        .expect("is-enrolled args should parse");
        // `--quiet` is global now, so it is read off `Cli`, not the variant.
        assert!(cli.quiet);
        let Commands::IsEnrolled { user, json } = cli.command else {
            panic!("expected the IsEnrolled variant");
        };
        assert_eq!(user.user.as_deref(), Some("alice"));
        assert!(json.json);
    }

    // -----------------------------------------------------------------------
    // Flag spelling (#167)
    // -----------------------------------------------------------------------

    /// The top-level command set, in `--help` order.
    ///
    /// A top-level name is the spelling every wrapper script, unit file and
    /// lock screen hard-codes, so gaining or losing one is a decision, not a
    /// side effect of adding a variant. The rule that decides whether a new
    /// command belongs here or inside a noun group is written down in
    /// `docs/contracts.md` §CLI Subcommands; ADR 009 adopted it.
    ///
    /// Checked in both directions against `Cli::command()`, like
    /// `JSON_COMMANDS`: a name here that the binary does not offer fails, and
    /// a command the binary offers that is not here fails too. Nested verbs
    /// (`daemon restart`, `tpm encrypt`, `pam status`) are deliberately absent
    /// — they are their group's business, and moving one is not a change to
    /// this surface.
    const TOP_LEVEL_COMMANDS: &[&str] = &[
        "setup",
        "is-enrolled",
        "capabilities",
        "enroll",
        "remove",
        "clear",
        "list",
        "test",
        "preview",
        "config",
        "status",
        "devices",
        "daemon",
        "auth",
        "bench",
        "tpm",
        "pam",
        "hyprlock",
        "audit",
    ];

    #[test]
    fn top_level_commands_match_the_registry() {
        let root = Cli::command();
        let actual: Vec<&str> = root
            .get_subcommands()
            .map(|c| c.get_name())
            .filter(|name| *name != "help")
            .collect();

        for name in TOP_LEVEL_COMMANDS {
            assert!(
                actual.contains(name),
                "`facelock {name}` is in TOP_LEVEL_COMMANDS but the binary does not offer it"
            );
        }
        for name in &actual {
            assert!(
                TOP_LEVEL_COMMANDS.contains(name),
                "`facelock {name}` is a top-level command with no row in \
                 TOP_LEVEL_COMMANDS; add one only if it names a user task that \
                 fits no existing noun group (docs/contracts.md §CLI Subcommands)"
            );
        }
    }

    /// The short-letter registry.
    ///
    /// Short letters are a single namespace shared by every subcommand: once
    /// `-l` means `--label` on one command, spending it on something else
    /// elsewhere makes both a trap. Each row is a letter and the long names
    /// allowed to bind it. `cli_flag_conformance` fails on a letter that is not
    /// listed, and on a listed letter bound to a name outside its row, so
    /// widening the namespace is a deliberate edit here rather than a side
    /// effect of adding a flag.
    ///
    /// `l` maps to two names because `enroll --label` and `audit --lines` both
    /// ship today and both must keep working. `v` has no site at all — it is a
    /// reservation for `--verbose`, held so the letter cannot be spent on
    /// something else first.
    const SHORT_REGISTRY: &[(char, &[&str])] = &[
        ('u', &["user"]),
        ('y', &["yes"]),
        ('c', &["config"]),
        ('q', &["quiet"]),
        ('l', &["label", "lines"]),
        ('f', &["follow"]),
        ('v', &["verbose"]),
    ];

    /// Every command that offers `--json`, by full invocation path.
    ///
    /// The list is the contract, in both directions: a command here without a
    /// `json` arg fails, and a `json` arg on a command not here fails too. So
    /// `--json` cannot appear because a matrix looked incomplete — adding a
    /// row is the moment someone states who parses the output, which is the
    /// rule `docs/contracts.md` records under "CLI Machine Output".
    ///
    /// `preview` is on the list because it always emitted JSON; it just spelled
    /// the flag `--text-only`, which survives as a hidden alias.
    const JSON_COMMANDS: &[&str] = &[
        "facelock is-enrolled",
        "facelock capabilities",
        "facelock list",
        "facelock devices",
        "facelock preview",
        "facelock pam add",
        "facelock pam remove",
        "facelock pam status",
    ];

    /// Collect every command in the tree, keyed by its full invocation path
    /// (`facelock bench camera-reopen`), so a failure names the offender.
    fn walk<'a>(
        command: &'a clap::Command,
        prefix: &str,
        out: &mut Vec<(String, &'a clap::Command)>,
    ) {
        let path = if prefix.is_empty() {
            command.get_name().to_string()
        } else {
            format!("{prefix} {}", command.get_name())
        };
        for sub in command.get_subcommands() {
            walk(sub, &path, out);
        }
        out.push((path, command));
    }

    /// Descend by subcommand name, naming the missing command on failure.
    fn sub<'a>(command: &'a clap::Command, name: &str) -> &'a clap::Command {
        command
            .get_subcommands()
            .find(|c| c.get_name() == name)
            .unwrap_or_else(|| panic!("no `{name}` subcommand"))
    }

    /// Look an argument up by its clap **id**, which the derive takes from the
    /// Rust field name (`no_pam`), not from the long spelling (`--no-pam`).
    fn arg<'a>(command: &'a clap::Command, id: &str) -> &'a clap::Arg {
        command
            .get_arguments()
            .find(|a| a.get_id().as_str() == id)
            .unwrap_or_else(|| panic!("`{}` has no `{id}` argument", command.get_name()))
    }

    /// Assert both halves: the id exists *and* it spells the long name a
    /// caller types. Asserting the id alone would let a rename of the
    /// spelling pass.
    fn assert_long(command: &clap::Command, id: &str, long: &str) {
        assert_eq!(
            arg(command, id).get_long(),
            Some(long),
            "`{}`: the `{id}` arg must spell `--{long}`",
            command.get_name()
        );
    }

    /// Pins flag spelling across the whole command tree.
    ///
    /// This is the test that outlives the refactor that produced it. The shared
    /// arg structs in `args.rs` stop drift at the sites that use them; this
    /// stops it at the sites that do not — a hand-rolled `--user` on a new
    /// command, a second `-c`, a `--json` that grew a short letter.
    ///
    /// **Recorded deviation from the G1 plan.** The plan called for a single
    /// `UserArg` (an `Option<String>`) on every user-scoped command including
    /// `auth`. `auth --user` is required today and `pam_facelock.so` spawns
    /// `facelock auth --user <name>`; making it optional would let the subject
    /// default to the process owner, which is an auth-semantics change, not a
    /// spelling one. So `auth` keeps a required `String` and only gains `-u`,
    /// and the requiredness rule below is asserted per command rather than
    /// assumed uniform.
    #[test]
    fn cli_flag_conformance() {
        let root = Cli::command();
        let mut commands = Vec::new();
        walk(&root, "", &mut commands);

        for (path, command) in &commands {
            let about = command
                .get_about()
                .map(ToString::to_string)
                .unwrap_or_default();
            assert!(
                !about.trim().is_empty(),
                "`{path}` has no about text, so it renders blank in `--help`"
            );

            for arg in command.get_arguments() {
                let id = arg.get_id().as_str();
                // clap owns `-h`/`-V`; the registry governs our own flags only.
                if id == "help" || id == "version" {
                    continue;
                }
                let long = arg.get_long();

                match id {
                    "user" => {
                        assert_eq!(
                            arg.get_short(),
                            Some('u'),
                            "`{path} --user` must also spell `-u`"
                        );
                        assert_eq!(long, Some("user"), "`{path}`: user arg spelled oddly");
                        if path == "facelock auth" {
                            assert!(
                                arg.is_required_set(),
                                "`auth --user` must stay required — PAM names the subject"
                            );
                        } else {
                            assert!(
                                !arg.is_required_set(),
                                "`{path} --user` must stay optional (defaults to current user)"
                            );
                        }
                    }
                    "yes" => {
                        assert_eq!(arg.get_short(), Some('y'), "`{path} --yes` must spell `-y`");
                        assert_eq!(long, Some("yes"));
                        assert!(
                            arg.get_all_aliases()
                                .unwrap_or_default()
                                .contains(&"no-confirm"),
                            "`{path} --yes` must accept the historical `--no-confirm`"
                        );
                    }
                    "json" | "dry_run" => {
                        assert_eq!(
                            arg.get_short(),
                            None,
                            "`{path} --{id}` must not claim a short letter"
                        );
                        // The long spelling is the whole contract for these,
                        // so assert it too: without this a `--json-output`
                        // would satisfy the short-letter rule vacuously.
                        let expected = id.replace('_', "-");
                        assert_eq!(
                            long,
                            Some(expected.as_str()),
                            "`{path}`: the `{id}` arg must spell `--{expected}`"
                        );
                    }
                    "quiet" => {
                        assert_eq!(
                            arg.get_short(),
                            Some('q'),
                            "`{path} --quiet` must spell `-q`"
                        );
                        assert_eq!(long, Some("quiet"), "`{path}`: quiet arg spelled oddly");
                    }
                    _ => {}
                }

                let mut shorts: Vec<char> = arg.get_short().into_iter().collect();
                shorts.extend(arg.get_all_short_aliases().unwrap_or_default());
                for short in shorts {
                    let Some((_, allowed)) =
                        SHORT_REGISTRY.iter().find(|(letter, _)| *letter == short)
                    else {
                        panic!(
                            "`{path}` binds -{short} (--{}), which is not in SHORT_REGISTRY; \
                             add a row there if the letter is really meant to be spent",
                            long.unwrap_or(id)
                        );
                    };
                    let name = long.unwrap_or(id);
                    assert!(
                        allowed.contains(&name),
                        "`{path}` binds -{short} to --{name}; the registry reserves \
                         that letter for {allowed:?}"
                    );
                }
            }
        }

        // -- `--json` coverage (#169) ------------------------------------
        //
        // Spelling is pinned above; these pin *where* the flag appears, and
        // that nothing else spells machine output a second way.

        let offers_json = |path: &str| {
            commands
                .iter()
                .find(|(p, _)| p == path)
                .unwrap_or_else(|| panic!("`{path}` is in JSON_COMMANDS but not in the tree"))
                .1
                .get_arguments()
                .any(|arg| arg.get_id() == "json")
        };
        for path in JSON_COMMANDS {
            assert!(
                offers_json(path),
                "`{path}` is in JSON_COMMANDS but binds no `--json`"
            );
        }
        for (path, command) in &commands {
            if command.get_arguments().any(|arg| arg.get_id() == "json") {
                assert!(
                    JSON_COMMANDS.contains(&path.as_str()),
                    "`{path}` offers `--json` without a row in JSON_COMMANDS; add one \
                     naming the consumer that asked for it"
                );
            }
        }

        // A flag that advertises JSON is named `json`. Without this, a later
        // `--output json` or a second `--text-only` would satisfy every rule
        // above by never being called `json` in the first place. Clap aliases
        // are not `Arg`s and carry no help, so a hidden historical spelling is
        // exempt by construction.
        //
        // Everything a user could read on the flag counts, concatenated
        // rather than one-or-the-other: short help, long help, and the
        // possible values with their own help. A `--format <FORMAT>` over
        // `{json, text}` documented as "Output format" says JSON nowhere in
        // its help text and only the value list gives it away.
        //
        // This is deliberately over-broad. A future *input* flag such as
        // `--from-json <path>` would trip it despite emitting nothing. Rename
        // that arg rather than relaxing the rule: the tripwire is worth more
        // than the one name it costs.
        for (path, command) in &commands {
            for arg in command.get_arguments() {
                let mut advertised = String::new();
                for text in [arg.get_help(), arg.get_long_help()].into_iter().flatten() {
                    advertised.push_str(&text.to_string());
                    advertised.push(' ');
                }
                for value in arg.get_possible_values() {
                    advertised.push_str(value.get_name());
                    advertised.push(' ');
                    if let Some(text) = value.get_help() {
                        advertised.push_str(&text.to_string());
                        advertised.push(' ');
                    }
                }
                if advertised.to_lowercase().contains("json") {
                    assert_eq!(
                        arg.get_id().as_str(),
                        "json",
                        "`{path} --{}` advertises JSON but is not the shared \
                         `json` arg; machine output has one spelling",
                        arg.get_long().unwrap_or_else(|| arg.get_id().as_str())
                    );
                }
            }
        }
    }

    /// Every invocation that parsed before the shared arg structs landed must
    /// still parse. The refactor is additive or it is a regression, and only a
    /// table of real argv can tell those apart.
    #[test]
    fn legacy_invocations_still_parse() {
        for argv in [
            &["facelock", "setup", "--pam", "--service", "sudo", "--yes"][..],
            &[
                "facelock",
                "setup",
                "--pam",
                "--service",
                "sudo",
                "--remove",
                "--yes",
            ],
            &[
                "facelock",
                "setup",
                "--pam",
                "--service",
                "sudo",
                "--remove",
                "--yes",
                "--if-present",
            ],
            &["facelock", "setup", "--no-pam", "--systemd", "--enroll"],
            &["facelock", "setup", "--pam", "--no-confirm"],
            &["facelock", "preview", "--text-only"],
            &["facelock", "preview", "--json"],
            &["facelock", "remove", "1", "-y"],
            &["facelock", "clear", "-u", "alice", "--yes"],
            &["facelock", "enroll", "-u", "alice", "-l", "laptop"],
            &["facelock", "audit", "-f", "-l", "5"],
            &["facelock", "list", "-u", "alice", "--json"],
            &["facelock", "devices", "--json"],
            // `facelock pam` (#174). The new verb is additive: every row above
            // is what `setup --pam` accepted before it existed, and both
            // spellings keep working.
            &["facelock", "pam", "add"],
            &["facelock", "pam", "add", "--service", "sudo"],
            &[
                "facelock",
                "pam",
                "add",
                "--service",
                "sudo",
                "--service",
                "polkit-1",
                "--no-confirm",
                "--dry-run",
                "--json",
            ],
            &[
                "facelock",
                "pam",
                "add",
                "--service",
                "system-auth",
                "--allow-sensitive",
                "-y",
            ],
            &["facelock", "pam", "add", "--service", "x", "--if-present"],
            &["facelock", "pam", "remove"],
            &[
                "facelock",
                "pam",
                "remove",
                "--service",
                "sudo",
                "--if-present",
                "--no-confirm",
            ],
            &["facelock", "pam", "status"],
            &["facelock", "pam", "status", "--service", "sudo", "--json"],
            &["facelock", "--quiet", "pam", "status", "--json"],
            // ADR 009. The bare forms are what five init-system units and
            // `commands::setup::run_systemd`'s `ExecStart` marker invoke, and
            // what a reader types; the explicit forms are the new spellings.
            // The four deleted top-level spellings get no rows here: this
            // table pins what must keep parsing, and ADR 009 decided they
            // must not. They are pinned as parse errors further down.
            &["facelock", "daemon"],
            &["facelock", "daemon", "run"],
            &["facelock", "daemon", "restart"],
            &["facelock", "config"],
            &["facelock", "config", "show"],
            &["facelock", "config", "edit"],
            &["facelock", "tpm", "encrypt"],
            &["facelock", "tpm", "encrypt", "--generate-key"],
            &["facelock", "tpm", "decrypt"],
            &["facelock", "tpm", "reseal"],
        ] {
            Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{}` must still parse: {e}", argv.join(" ")));
        }

        // The PAM module spawns exactly this argv (crates/pam-facelock/src/lib.rs).
        // `auth` no longer declares its own `--config`; this parses only because
        // the one on `Cli` is `global = true` and is therefore still accepted
        // after the subcommand name. Drop `global` and PAM breaks silently.
        let cli = Cli::try_parse_from([
            "facelock",
            "auth",
            "--user",
            "alice",
            "--config",
            "/etc/facelock/config.toml",
        ])
        .expect("the argv pam_facelock.so spawns must parse");
        assert_eq!(cli.config.as_deref(), Some("/etc/facelock/config.toml"));
        let Commands::Auth { user } = cli.command else {
            panic!("expected the Auth variant");
        };
        assert_eq!(user, "alice");

        // `daemon -c X` kept its spelling when the per-command flag was deleted:
        // the global one gained `-c`. Both sides of the subcommand work, and
        // the bare form still reaches the daemon under `Option<DaemonCommand>`
        // (ADR 009): were `None` ever to mean `Restart`, every service unit
        // would restart the daemon at boot instead of starting it.
        for argv in [
            &["facelock", "daemon", "-c", "/tmp/x.toml"][..],
            &["facelock", "-c", "/tmp/x.toml", "daemon"],
        ] {
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{}` must parse: {e}", argv.join(" ")));
            assert_eq!(cli.config.as_deref(), Some("/tmp/x.toml"));
            assert!(matches!(cli.command, Commands::Daemon { command: None }));
        }

        // The `None` arms are the compatibility surface: bare `daemon` runs
        // the daemon and bare `config` shows the file. A future `Option` that
        // defaulted to anything else would be a silent behaviour change.
        assert!(matches!(
            Cli::try_parse_from(["facelock", "daemon"])
                .expect("bare `facelock daemon` must parse")
                .command,
            Commands::Daemon { command: None }
        ));
        assert!(matches!(
            Cli::try_parse_from(["facelock", "config"])
                .expect("bare `facelock config` must parse")
                .command,
            Commands::Config { command: None }
        ));

        // Deleted, not hidden (ADR 009): the old spellings must not parse.
        for argv in [
            &["facelock", "restart"][..],
            &["facelock", "encrypt"],
            &["facelock", "encrypt", "--generate-key"],
            &["facelock", "decrypt"],
            &["facelock", "reseal"],
            &["facelock", "config", "--edit"],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "`{}` was renamed and must no longer parse",
                argv.join(" ")
            );
        }

        // `--quiet` moved off `is-enrolled` onto the root, so both positions
        // must reach the same field.
        for argv in [
            &["facelock", "is-enrolled", "--quiet"][..],
            &["facelock", "--quiet", "is-enrolled"],
            &["facelock", "is-enrolled", "-q"],
        ] {
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{}` must parse: {e}", argv.join(" ")));
            assert!(cli.quiet, "`{}` must set the global quiet", argv.join(" "));
        }

        // `--no-confirm` was `setup`-only; it is the alias everywhere now.
        let cli = Cli::try_parse_from(["facelock", "clear", "--no-confirm"])
            .expect("`clear --no-confirm` must parse");
        let Commands::Clear { confirm, .. } = cli.command else {
            panic!("expected the Clear variant");
        };
        assert!(confirm.yes);
    }

    // -----------------------------------------------------------------------
    // `facelock pam` (#174)
    // -----------------------------------------------------------------------

    fn pam_request(args: &[&str]) -> facelock_cli::commands::pam::PamRequest {
        let argv: Vec<&str> = ["facelock", "pam"].iter().chain(args).copied().collect();
        let cli = Cli::try_parse_from(argv).expect("expected these args to parse");
        let Commands::Pam { command } = cli.command else {
            panic!("expected the Pam variant");
        };
        command.into()
    }

    /// The defect the verb exists to fix: one process, several services. The
    /// old surface took a single `Option<String>`, so a wrapper wanting three
    /// services ran three of them.
    #[test]
    fn pam_service_is_repeatable_and_ordered() {
        assert_eq!(
            pam_request(&["add", "--service", "sudo", "--service", "polkit-1"]).services,
            ["sudo", "polkit-1"]
        );
        // Empty is not "no services" — it is `sudo`, resolved in the command.
        assert!(pam_request(&["add"]).services.is_empty());
    }

    /// **`--no-confirm` must never imply `--allow-sensitive`.** They are
    /// separate authorizations: "do not ask me" and "yes, edit system-auth".
    /// `setup --yes` keeps the combined meaning and is the sole exception.
    #[test]
    fn no_confirm_and_allow_sensitive_are_independent() {
        for skip_prompts in [
            &["add", "--no-confirm"][..],
            &["add", "--yes"],
            &["add", "-y"],
        ] {
            let request = pam_request(skip_prompts);
            assert!(request.no_confirm, "{skip_prompts:?}");
            assert!(
                !request.allow_sensitive,
                "{skip_prompts:?} must not unlock the sensitive services"
            );
        }

        let request = pam_request(&["add", "--allow-sensitive"]);
        assert!(request.allow_sensitive);
        assert!(
            !request.no_confirm,
            "--allow-sensitive accepts a risk; it does not skip the question"
        );

        // `setup --yes` is the documented exception, unchanged.
        assert!(plan(&["--pam", "--yes"]).yes);
    }

    /// `--allow-sensitive` is an `add`-only flag: removal can only take away a
    /// way to authenticate, so there is nothing to gate.
    #[test]
    fn remove_and_status_do_not_offer_allow_sensitive() {
        for argv in [
            &["facelock", "pam", "remove", "--allow-sensitive"][..],
            &["facelock", "pam", "status", "--allow-sensitive"],
            &["facelock", "pam", "status", "--dry-run"],
        ] {
            assert!(
                Cli::try_parse_from(argv).is_err(),
                "`{}` must not parse",
                argv.join(" ")
            );
        }
    }

    // -----------------------------------------------------------------------
    // `facelock capabilities` (#165)
    // -----------------------------------------------------------------------

    /// Every emitted capability name is backed by the clap surface it names.
    ///
    /// This is what makes the list a probe rather than documentation: a name
    /// that nothing declares is a lie a consumer would act on. It lives in the
    /// binary's test module because only the binary can call `Cli::command()`.
    ///
    /// Each predicate proves the **surface** exists — the subcommand, the
    /// argument, its long spelling. What a surface *means* is pinned by the
    /// section of `docs/contracts.md` that owns it and by that command's own
    /// tests; duplicating semantics here would only make both places drift.
    ///
    /// `&str` patterns cannot be exhaustive, so the wildcard arm **is** the
    /// exhaustiveness check: it must panic, so that adding a name to
    /// `CAPABILITIES` without adding a predicate fails the build.
    #[test]
    fn capability_names_are_all_implemented() {
        use facelock_cli::commands::capabilities::CAPABILITIES;

        let root = Cli::command();
        let pam = sub(&root, "pam");
        let setup = sub(&root, "setup");
        let tpm = sub(&root, "tpm");

        for name in CAPABILITIES {
            match *name {
                "capabilities" => {
                    sub(&root, "capabilities");
                }
                // ADR 009 renamed five invocations. A consumer cannot tell a
                // build that offers `daemon restart` from one that still wants
                // `restart` by any means except asking, so each new spelling
                // is its own name. One name, one promise: that the subcommand
                // at this path exists — not what it does, which the
                // docs/contracts.md row it is checked against owns.
                "config-edit" => {
                    sub(sub(&root, "config"), "edit");
                }
                "daemon-restart" => {
                    sub(sub(&root, "daemon"), "restart");
                }
                "tpm-decrypt" => {
                    sub(tpm, "decrypt");
                }
                "tpm-encrypt" => {
                    sub(tpm, "encrypt");
                }
                "tpm-reseal" => {
                    sub(tpm, "reseal");
                }
                "devices-json" => assert_long(sub(&root, "devices"), "json", "json"),
                "is-enrolled" => {
                    sub(&root, "is-enrolled");
                }
                "is-enrolled-json" => assert_long(sub(&root, "is-enrolled"), "json", "json"),
                "pam-allow-sensitive" => {
                    assert_long(sub(pam, "add"), "allow_sensitive", "allow-sensitive");
                    // The half that is not a spelling: `remove` must *not*
                    // offer it, because removal is never gated.
                    assert!(
                        !sub(pam, "remove")
                            .get_arguments()
                            .any(|a| a.get_id() == "allow_sensitive"),
                        "`pam remove` must not offer --allow-sensitive"
                    );
                }
                "pam-dry-run" => {
                    for verb in ["add", "remove"] {
                        assert_long(sub(pam, verb), "dry_run", "dry-run");
                    }
                }
                "pam-if-present" => {
                    for verb in ["add", "remove", "status"] {
                        assert_long(sub(pam, verb), "if_present", "if-present");
                    }
                }
                "pam-json" => {
                    for verb in ["add", "remove", "status"] {
                        assert_long(sub(pam, verb), "json", "json");
                    }
                }
                "pam-multi-service" => {
                    for verb in ["add", "remove", "status"] {
                        let verb_command = sub(pam, verb);
                        assert_long(verb_command, "service", "service");
                        // "multi" is the whole promise: a single `Option` here
                        // is what forced one process per service.
                        assert!(
                            matches!(
                                arg(verb_command, "service").get_action(),
                                clap::ArgAction::Append
                            ),
                            "`pam {verb} --service` must be repeatable"
                        );
                    }
                }
                "pam-status" => {
                    sub(pam, "status");
                }
                "quiet" => {
                    assert_long(&root, "quiet", "quiet");
                    assert!(
                        arg(&root, "quiet").is_global_set(),
                        "`--quiet` must be global — every command honours it"
                    );
                }
                "setup-if-present" => assert_long(setup, "if_present", "if-present"),
                "setup-no-pam" => assert_long(setup, "no_pam", "no-pam"),
                "setup-systemd" => assert_long(setup, "systemd", "systemd"),
                other => {
                    panic!("capability `{other}` has no predicate: a name nothing backs is a lie")
                }
            }
        }
    }

    /// Nothing legacy invokes this command, so these are their own table
    /// rather than rows in `legacy_invocations_still_parse`.
    #[test]
    fn capabilities_invocations_parse() {
        for argv in [
            &["facelock", "capabilities"][..],
            &["facelock", "capabilities", "--json"],
            &["facelock", "--quiet", "capabilities", "--json"],
            &["facelock", "capabilities", "--quiet"],
        ] {
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{}` must parse: {e}", argv.join(" ")));
            assert!(
                matches!(cli.command, Commands::Capabilities { .. }),
                "`{}` must reach the Capabilities variant",
                argv.join(" ")
            );
            // The global flag on either side of the subcommand name reaches
            // the same field — the `CLI Flag Spelling` invariant.
            assert_eq!(
                cli.quiet,
                argv.contains(&"--quiet"),
                "`{}`: global --quiet must land on Cli::quiet wherever it sits",
                argv.join(" ")
            );
        }
    }

    // -----------------------------------------------------------------------
    // Reference-doc coverage (#172)
    // -----------------------------------------------------------------------

    /// `docs/cli.md` is the user-facing CLI reference. Reached the way
    /// `commands/capabilities.rs` reaches `docs/contracts.md` and `setup.rs`
    /// reaches the systemd unit: embedded, so a doc that stops describing the
    /// binary breaks the build rather than the reader.
    const CLI_DOC: &str = include_str!("../../../docs/cli.md");

    /// The book ships a second copy of the same reference. It is a near-copy,
    /// not a generated one, so it rots independently — `docs/cli.md` gained
    /// `is-enrolled` long before this file did.
    const BOOK_CLI_DOC: &str = include_str!("../../../book/src/cli-reference.md");

    /// The man page. Matched only through [`unescaped_man_page`].
    const MAN_PAGE: &str = include_str!("../../../man/facelock.1");

    /// Both prose copies of the CLI reference, by repository path so a failure
    /// names the file that is missing the entry rather than just the entry.
    const MARKDOWN_REFERENCES: &[(&str, &str)] = &[
        ("docs/cli.md", CLI_DOC),
        ("book/src/cli-reference.md", BOOK_CLI_DOC),
    ];

    /// `man(7)` writes a literal hyphen as `\-`, so `system-auth` is on disk as
    /// `system\-auth` and a plain substring search for it fails. Undoing that
    /// one escape is the whole normalization these checks need; nothing here
    /// looks at roff structure.
    fn unescaped_man_page() -> String {
        MAN_PAGE.replace(r"\-", "-")
    }

    /// The body of one `##` section, so a check scoped to a section cannot be
    /// satisfied by matching text somewhere else in the file.
    fn section_of<'a>(doc: &'a str, heading: &str) -> &'a str {
        let start = doc
            .find(heading)
            .unwrap_or_else(|| panic!("`{}` is missing from the document", heading.trim()));
        let body = &doc[start + heading.len()..];
        match body.find("\n## ") {
            Some(end) => &body[..end],
            None => body,
        }
    }

    /// Every subcommand the binary offers is written down.
    ///
    /// The rot this exists to stop was real: `is-enrolled`, `hyprlock`,
    /// `reseal`, `pam` and `capabilities` all shipped without ever reaching
    /// the reference, and `is-enrolled` is the one command Omarchy's
    /// integration depends on.
    ///
    /// **Top-level commands get a `## facelock <name>` heading of their own.**
    /// A nested verb (`bench camera-reopen`, `tpm unseal-check`, `pam status`,
    /// `hyprlock enable`) does *not*: it is documented under its parent's
    /// section, which is how the file already reads and how a reader looks one
    /// up. So the assertion for a nested verb is weaker on purpose — the full
    /// invocation must appear somewhere in the file — but it is still enough
    /// to catch a whole verb going undocumented, which is what happened to
    /// `tpm unseal-check`.
    ///
    /// Clap's built-in `help` pseudo-command is skipped at every level.
    ///
    /// Both prose copies are checked. The book's is a hand-maintained near-copy
    /// rather than a generated one, so holding only `docs/cli.md` to this would
    /// leave the copy that rots more freely unpinned.
    #[test]
    fn docs_cli_documents_every_subcommand() {
        let root = Cli::command();

        for (doc_path, doc) in MARKDOWN_REFERENCES {
            for command in root.get_subcommands() {
                let name = command.get_name();
                if name == "help" {
                    continue;
                }
                let heading = format!("\n## facelock {name}\n");
                assert!(
                    doc.contains(&heading),
                    "`facelock {name}` ships but `{doc_path}` has no \
                     `## facelock {name}` heading"
                );

                for nested in command.get_subcommands() {
                    let nested_name = nested.get_name();
                    if nested_name == "help" {
                        continue;
                    }
                    let invocation = format!("facelock {name} {nested_name}");
                    assert!(
                        doc.contains(&invocation),
                        "`{invocation}` ships but is not mentioned anywhere in \
                         `{doc_path}`; document it under the `## facelock {name}` section"
                    );
                }
            }
        }
    }

    /// The `## Machine-readable output` section names every command that
    /// offers `--json`.
    ///
    /// That section is a third copy of a list the binary already holds twice —
    /// the `JSON_COMMANDS` registry above, and the table in
    /// `docs/contracts.md`. Prose is the copy that rots silently, because
    /// nothing fails when a newly added `--json` never reaches it.
    /// `JSON_COMMANDS` is pinned against the clap tree and not against this
    /// text, so the two checks do not prop each other up: the walk below is the
    /// clap tree, and a command satisfies it only by being written down.
    ///
    /// One direction only. Asserting that nothing *else* is named there would
    /// mean parsing prose for command names, and the reverse direction is
    /// already covered — a command named here that binds no `--json` fails
    /// `cli_flag_conformance` against `JSON_COMMANDS` first.
    ///
    /// `docs/cli.md` only, unlike the coverage and example checks either side
    /// of it. The book's copy has no `## Machine-readable output` section at
    /// all, so holding it to this would not find rot — it would demand a
    /// section that has never existed, which is a decision about what the book
    /// contains rather than a check that it is accurate.
    #[test]
    fn docs_cli_machine_output_section_names_every_json_command() {
        let root = Cli::command();
        let mut commands = Vec::new();
        walk(&root, "", &mut commands);

        let section = section_of(CLI_DOC, "\n## Machine-readable output\n");

        for (path, command) in &commands {
            if !command.get_arguments().any(|arg| arg.get_id() == "json") {
                continue;
            }
            assert!(
                section.contains(path.as_str()),
                "`{path}` offers `--json` but the `## Machine-readable output` \
                 section of docs/cli.md does not name it"
            );
        }
    }

    /// Every `facelock …` line the reference shows must actually parse.
    ///
    /// A reference example is a promise that the command line works, and the
    /// cheapest way to break that promise is to document a flag that was
    /// renamed or never existed. This does not prove an example *succeeds* —
    /// most need root, a camera or a TPM — only that clap accepts it, which is
    /// the half a unit test can own.
    ///
    /// Extraction rules, and why each one is what it is:
    ///
    /// - only ```` ```bash ```` blocks, so prose that names a flag inline is
    ///   left alone (the `setup` section deliberately cites the invocation
    ///   that *refuses*, as prose, to explain the sensitive-service gate);
    /// - a leading `sudo ` is stripped, since half the examples need root;
    /// - a trailing ` # …` comment is stripped;
    /// - the invocation ends at the first shell operator (`|`, `||`, `&&`,
    ///   `;`, `&`), so a piped example documents a real pipeline and still
    ///   gets its `facelock` half checked;
    /// - **no placeholders.** A `<user>` or `<model_id>` in an example is
    ///   rejected outright rather than substituted, because a reference
    ///   example should be runnable as written — and a substituted
    ///   placeholder would make `--user <user>` pass while `remove <id>`
    ///   failed, which is an arbitrary line. Angle brackets are used for
    ///   metavariables in the flag *tables*, which are not bash blocks.
    ///
    /// Takes the document rather than reading `CLI_DOC` directly, because the
    /// book ships a second, hand-maintained copy of this reference. Checking
    /// only `docs/cli.md` left the copy that rots more freely — the one a
    /// reader is likelier to arrive at from a search engine — free to document
    /// a command line that does not parse.
    fn documented_invocations(doc: &str) -> Vec<Vec<String>> {
        const OPERATORS: &[&str] = &["|", "||", "&&", ";", "&"];

        let mut invocations = Vec::new();
        let mut in_bash = false;

        for line in doc.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("```") {
                in_bash = !in_bash && trimmed == "```bash";
                continue;
            }
            if !in_bash {
                continue;
            }

            let command = trimmed.strip_prefix("sudo ").unwrap_or(trimmed).trim();
            if command != "facelock" && !command.starts_with("facelock ") {
                continue;
            }
            // ` #` rather than `#`: a `#` can legitimately open an argument.
            let command = match command.split_once(" #") {
                Some((before, _)) => before.trim(),
                None => command,
            };

            let argv: Vec<String> = command
                .split_whitespace()
                .take_while(|token| !OPERATORS.contains(token))
                .map(str::to_string)
                .collect();

            for token in &argv {
                assert!(
                    !token.contains('<') && !token.contains('>'),
                    "`{command}` carries a placeholder or redirect (`{token}`); \
                     a reference example must be runnable as written"
                );
            }
            invocations.push(argv);
        }

        assert!(
            invocations.len() > 20,
            "extracted only {} invocations — the extractor is probably broken, \
             not the doc",
            invocations.len()
        );
        invocations
    }

    #[test]
    fn docs_cli_examples_all_parse() {
        for (doc_path, doc) in MARKDOWN_REFERENCES {
            for argv in documented_invocations(doc) {
                Cli::try_parse_from(&argv).unwrap_or_else(|e| {
                    panic!("`{}` in {doc_path} must parse: {e}", argv.join(" "))
                });
            }
        }
    }

    /// No example installs into a gated PAM service without the flag that
    /// unlocks it.
    ///
    /// This is the bug that motivated the gap: `docs/cli.md` documented
    /// `facelock setup --pam --service login`, and `login` is in
    /// `SENSITIVE_SERVICES`, so the command as written **fails**. Parsing
    /// cannot catch it — the gate is a runtime refusal, not a parse error —
    /// so the check has to resolve the invocation the way `main` does and ask
    /// the writer's own question.
    ///
    /// Only the add direction is gated. `pam remove --service login` is a
    /// documented example precisely because removal is never gated.
    #[test]
    fn docs_cli_examples_never_install_into_a_gated_service() {
        use facelock_cli::commands::pam::{PamAction, SENSITIVE_SERVICES};

        // Which services are gated is enumerated in prose in every reference,
        // and a reader who cannot look the list up has to discover it by being
        // refused. `SENSITIVE_SERVICES` is the only copy that decides anything,
        // so every other copy is checked against it.
        //
        // Containment is a deliberately loose test: `login` would also match
        // "login managers". It still catches the failure that matters, which is
        // a name added to `SENSITIVE_SERVICES` and written down nowhere.
        let man = unescaped_man_page();
        let mut references = MARKDOWN_REFERENCES.to_vec();
        references.push(("man/facelock.1", &man));
        for (doc_path, doc) in &references {
            for service in SENSITIVE_SERVICES {
                assert!(
                    doc.contains(service),
                    "`{doc_path}` never names the gated service `{service}`"
                );
            }
        }

        let gated = |services: &[String]| -> Option<String> {
            services
                .iter()
                .find(|s| SENSITIVE_SERVICES.contains(&s.as_str()))
                .cloned()
        };

        for (doc_path, doc) in MARKDOWN_REFERENCES {
            for argv in documented_invocations(doc) {
                let rendered = argv.join(" ");
                let cli =
                    Cli::try_parse_from(&argv).expect("checked by docs_cli_examples_all_parse");

                match cli.command {
                    Commands::Pam { command } => {
                        let request: facelock_cli::commands::pam::PamRequest = command.into();
                        if request.action != PamAction::Add || request.allow_sensitive {
                            continue;
                        }
                        if let Some(service) = gated(&request.services) {
                            panic!(
                                "`{rendered}` in {doc_path} installs into the gated service \
                                 `{service}` without --allow-sensitive, so it fails as written"
                            );
                        }
                    }
                    Commands::Setup(setup) => {
                        let plan = resolve_setup_plan(SetupArgs::from(setup));
                        // `setup --yes` is the documented exception: it maps onto
                        // --allow-sensitive as well as --no-confirm.
                        if plan.yes {
                            continue;
                        }
                        let PamPref::Install {
                            service: Some(service),
                        } = &plan.pam
                        else {
                            continue;
                        };
                        if let Some(service) = gated(std::slice::from_ref(service)) {
                            panic!(
                                "`{rendered}` in {doc_path} installs into the gated service \
                                 `{service}` without -y, so it fails as written"
                            );
                        }
                    }
                    _ => {}
                }
            }
        }
    }
}
