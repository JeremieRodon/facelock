//! The `facelock` binary: clap wiring plus top-level dispatch into the
//! `facelock_cli` library. The domain layer (backend, health, message,
//! resolved, logging, …) lives in `lib.rs` so it stays testable and shareable
//! (gap D6); this file keeps only the `Cli`/`Commands` types and `main`.

mod args;

use std::path::PathBuf;

use clap::{Parser, Subcommand};

use facelock_cli::commands::TpmCommand;
use facelock_cli::commands::bench::BenchCommand;
use facelock_cli::commands::hyprlock::HyprlockCommand;
use facelock_cli::commands::setup::{SetupArgs, resolve_setup_plan};
use facelock_cli::{commands, logging, message, notifications, resolved};

use args::{ConfirmArg, JsonArg, SetupCli, UserArg};

#[derive(Parser)]
#[command(name = "facelock", about = "Linux face authentication", version)]
struct Cli {
    /// Path to config file
    #[arg(short = 'c', long, global = true)]
    config: Option<String>,
    /// Suppress non-essential stdout; report the result through the exit code
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
    Preview {
        /// Print detection results to stdout instead of graphical preview
        #[arg(long)]
        text_only: bool,
        #[command(flatten)]
        user: UserArg,
    },
    /// Show or edit configuration
    Config {
        /// Open config file in editor
        #[arg(long)]
        edit: bool,
    },
    /// Check system status
    Status,
    /// List available camera devices
    Devices {
        #[command(flatten)]
        json: JsonArg,
    },
    /// Run the persistent authentication daemon
    Daemon,
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
    /// TPM integration status and management
    Tpm {
        #[command(subcommand)]
        command: TpmCommand,
    },
    /// Manage hyprlock lock-screen integration (no root required)
    Hyprlock {
        #[command(subcommand)]
        command: HyprlockCommand,
    },
    /// Encrypt all unencrypted embeddings with AES-256-GCM
    Encrypt {
        /// Generate a new encryption key (does not encrypt)
        #[arg(long)]
        generate_key: bool,
    },
    /// Decrypt all software-encrypted embeddings
    Decrypt,
    /// Re-seal the TPM AES key under current PCRs (recovery after a firmware/kernel change)
    Reseal,
    /// Restart the facelock daemon
    Restart,
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

    match command {
        // Daemon and auth init their own tracing, so handle them separately
        Commands::Daemon => commands::daemon::run(notifications::daemon_notifier_factory()),
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
                // dotfiles, `config` operates on the config file itself, and
                // `restart` only talks to systemd — none consume a parsed
                // Config.
                Commands::IsEnrolled { user, json } => {
                    std::process::exit(commands::is_enrolled::run(user.user, json.json, quiet))
                }
                Commands::Hyprlock { command } => commands::hyprlock::run(command),
                Commands::Config { edit } => commands::config::run(edit),
                Commands::Restart => commands::config::restart(),

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
                        Commands::Preview { text_only, user } => {
                            commands::preview::run(&config, text_only, user.user)
                        }
                        Commands::Devices { json } => commands::devices::run(&config, json.json),
                        Commands::Bench { command } => commands::bench::run(&config, command),
                        Commands::Tpm { command } => commands::tpm::run(&config, command),
                        Commands::Encrypt { generate_key } => {
                            commands::encrypt::run_encrypt(&config, generate_key)
                        }
                        Commands::Decrypt => commands::encrypt::run_decrypt(&config),
                        Commands::Reseal => commands::tpm::run_reseal(&config),
                        Commands::Audit { follow, lines } => {
                            commands::audit::run(&config, follow, lines)
                        }
                        // Already handled above
                        Commands::Daemon
                        | Commands::Auth { .. }
                        | Commands::IsEnrolled { .. }
                        | Commands::Hyprlock { .. }
                        | Commands::Config { .. }
                        | Commands::Restart
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
            &["facelock", "remove", "1", "-y"],
            &["facelock", "clear", "-u", "alice", "--yes"],
            &["facelock", "enroll", "-u", "alice", "-l", "laptop"],
            &["facelock", "audit", "-f", "-l", "5"],
            &["facelock", "list", "-u", "alice", "--json"],
            &["facelock", "devices", "--json"],
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
        // the global one gained `-c`. Both sides of the subcommand work.
        for argv in [
            &["facelock", "daemon", "-c", "/tmp/x.toml"][..],
            &["facelock", "-c", "/tmp/x.toml", "daemon"],
        ] {
            let cli = Cli::try_parse_from(argv)
                .unwrap_or_else(|e| panic!("`{}` must parse: {e}", argv.join(" ")));
            assert_eq!(cli.config.as_deref(), Some("/tmp/x.toml"));
            assert!(matches!(cli.command, Commands::Daemon));
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
}
