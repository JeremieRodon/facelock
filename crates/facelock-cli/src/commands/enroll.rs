use chrono::Local;

use facelock_core::Config;

use crate::backend::Backend;
use crate::ipc_client;
use crate::message::{FaceMessage, Terminal, fail};

/// The escalation hint `enroll`'s two root checks name — `main`'s gate (C6)
/// and [`run`]'s own backstop. When the setup marker is absent (and
/// `--skip-setup-check` not given), the remedy the refusal names is `setup`
/// — the command [`run`] will offer to execute it — rather than `enroll`
/// itself.
pub fn sudo_hint(skip_setup_check: bool) -> &'static str {
    if !skip_setup_check && !std::path::Path::new(super::setup::SETUP_COMPLETE_MARKER).exists() {
        "sudo facelock setup"
    } else {
        "sudo facelock enroll"
    }
}

pub fn run(
    config: &Config,
    user: Option<String>,
    label: Option<String>,
    skip_setup_check: bool,
) -> anyhow::Result<()> {
    // Belt and braces on `main`'s `require_root_for` gate, which establishes
    // root ahead of the config parse and owns the interactive escalation
    // (C6, issue #191). This second check is for the callers that never
    // reach that gate: `setup` invokes `run` directly, from the wizard's
    // step 7 and from `--enroll`. Those are covered today only by
    // `run_with_plan`'s precheck, which is conditional on
    // `plan.base.is_some()` — a future standalone plan that enrolled would
    // walk straight past it, and the gate would never see the command at
    // all. Under root, which is every path that exists now, this costs one
    // `getuid` (issue #288).
    //
    // Hard-error class deliberately, where the gate's is interactive: the
    // gate already offered the sudo re-exec for the CLI spelling, and
    // re-execing `facelock enroll` from inside a half-finished `setup` would
    // resume the wrong command.
    ipc_client::require_root_scripted(sudo_hint(skip_setup_check))?;

    // Setup gate: prompt user if setup hasn't been run.
    // Setup includes model downloads, encryption, and face enrollment,
    // so if setup runs successfully we're done — no need to enroll again.
    if !skip_setup_check {
        let marker = std::path::Path::new(super::setup::SETUP_COMPLETE_MARKER);
        if !marker.exists() {
            Terminal.info(&FaceMessage::SetupNotCompleted);
            if Terminal.confirm(&FaceMessage::ConfirmRunSetupNow)? {
                super::setup::run(false)?;
                if !marker.exists() {
                    return Err(fail(FaceMessage::SetupDidNotComplete));
                }
                // Setup includes face enrollment (Step 7), so we're done
                return Ok(());
            } else {
                Terminal.info(&FaceMessage::RunSetupWhenReady);
                return Ok(());
            }
        }
    }

    // Encryption posture (Plan 04): refuse plaintext enrollment unless opted in;
    // warn prominently when the opt-in is active.
    if config.encryption.method == facelock_core::config::EncryptionMethod::None {
        if config.security.allow_plaintext {
            Terminal.error(&FaceMessage::PlaintextEnrollWarning);
        } else if let Err(message) = config.ensure_enroll_encryption_allowed() {
            anyhow::bail!(message);
        }
    }

    // Models must exist before anything opens a camera. One probe through the
    // shared fact (D7) instead of a per-command re-derivation.
    if !crate::resolved::ModelFiles::probe(config).all_present() {
        return Err(fail(FaceMessage::ModelsMissing {
            dir: config.daemon.model_dir.clone(),
        }));
    }

    let user = ipc_client::resolve_user(user.as_deref());

    // One selection for the whole enrollment (D1). The probe is
    // `name_has_owner`, which never triggers D-Bus activation — the old
    // per-site convention this replaces existed because an unconditional
    // D-Bus call here would *activate* the daemon and silently flip the
    // subsequent enrollment from direct to daemon mode (issue #89 validation
    // fallout). Now the transport cannot change between the label scan and
    // the enrollment.
    let backend = Backend::select(config);

    let label = match label {
        Some(label) => label,
        None => {
            let date = Local::now().format("%Y-%m-%d").to_string();
            next_label(&date, &user, &backend)?
        }
    };

    // Warn if existing models use a different embedder than currently
    // configured. One failure policy (C4, issue #105), owned by the seam: a
    // store or daemon failure propagates instead of silently skipping the
    // warning — the enrollment ahead needs the very store this check just
    // failed to read. A provably absent store reads as "no models, nothing
    // stale" without being created.
    {
        let config_embedder = &config.recognition.embedder_model;
        let has_stale = backend.has_models(&user)?
            && !backend.has_models_for_embedder(&user, config_embedder)?;
        if has_stale {
            Terminal.info(&FaceMessage::StaleEmbedderNote {
                embedder: config_embedder.clone(),
            });
        }
    }

    Terminal.info(&FaceMessage::Enrolling {
        user: user.clone(),
        label: label.clone(),
    });
    Terminal.info(&FaceMessage::EnrollLookAtCamera);

    let (model_id, embedding_count) = backend.enroll(&user, &label)?;

    Terminal.info(&FaceMessage::EnrollComplete {
        model_id,
        count: embedding_count,
        label: label.clone(),
    });
    super::enrollment_marker::refresh(&backend, config, &user);
    check_model_count(&user, &backend);

    Ok(())
}

/// Generate the next available label like "2026-03-15-1", "2026-03-15-2", etc.
///
/// One failure policy (C4, issue #105): a store failure while picking the
/// label propagates via the seam; it must not silently fall back to a "-1"
/// suffix.
fn next_label(date_prefix: &str, user: &str, backend: &Backend) -> anyhow::Result<String> {
    let max_suffix = backend
        .list_models(user)?
        .iter()
        .filter_map(|m| {
            m.label
                .strip_prefix(date_prefix)
                .and_then(|rest| rest.strip_prefix('-'))
                .and_then(|n| n.parse::<u32>().ok())
        })
        .max()
        .unwrap_or(0);

    Ok(format!("{date_prefix}-{}", max_suffix + 1))
}

fn check_model_count(user: &str, backend: &Backend) {
    // Post-success advisory only: the enrollment already committed, so a
    // failed count here must not turn a successful enrollment into a
    // reported failure.
    if let Ok(models) = backend.list_models(user)
        && models.len() > 5
    {
        Terminal.info(&FaceMessage::TooManyModels {
            user: user.to_string(),
            count: models.len(),
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    /// `mode = "oneshot"` pins a DirectByConfig selection without touching
    /// D-Bus.
    fn oneshot_config_with_db(db_path: &Path) -> Config {
        let mut config = Config::parse("[daemon]\nmode = \"oneshot\"\n").expect("config parses");
        config.storage.db_path = db_path.to_string_lossy().into_owned();
        config
    }

    /// The uid/gid a root test runner drops the child to, matching
    /// `tests/cli_smoke.rs`. `setuid`/`setgid` do not consult `/etc/passwd`,
    /// so the account need not exist inside a CI container.
    const NOBODY_UID: u32 = 65534;
    const NOBODY_GID: u32 = 65534;

    /// Set in the re-executed copy of this test binary, to tell it that it is
    /// the child and should run the assertion rather than spawn again.
    const BACKSTOP_CHILD_VAR: &str = "FACELOCK_TEST_ENROLL_BACKSTOP_CHILD";

    /// The line the child prints once the refusal has held, with the uid it
    /// held under. libtest exits 0 when a filter matches nothing, so a
    /// successful child status is not on its own evidence that anything ran.
    const BACKSTOP_WITNESS: &str = "enroll backstop refused as uid";

    /// Issue #288: the backstop at the top of [`run`] is the whole defense
    /// for callers that bypass `main`'s gate, and `setup` is one — it calls
    /// `run` directly, behind a precheck that is conditional on
    /// `plan.base.is_some()`. Nothing about the gate's exhaustive match
    /// would notice a future standalone plan enrolling unprivileged.
    ///
    /// `run` is called in-process, so unlike the rows in `tests/cli_smoke.rs`
    /// there is no child to drop privileges on — and a test that returned
    /// early under a root runner would assert nothing in CI, where both test
    /// jobs are root in a container (issues #189, #303). So this re-executes
    /// the test binary at itself and drops *that* child, which puts the
    /// assertion back under the same rule every spawning row follows.
    ///
    /// The re-exec is unconditional. A branch that only spawned under root
    /// would leave the path CI takes as the one path no developer ever runs,
    /// which is the shape of the bug being fixed.
    #[test]
    fn run_refuses_a_non_root_caller_on_its_own() {
        if std::env::var_os(BACKSTOP_CHILD_VAR).is_some() {
            backstop_assertion();
            return;
        }

        // Derived rather than spelled out, so moving the module does not
        // silently turn the filter into a no-match. libtest names a test by
        // its module path with the crate root stripped.
        let module = module_path!()
            .split_once("::")
            .map_or(module_path!(), |(_, rest)| rest);
        let test_name = format!("{module}::run_refuses_a_non_root_caller_on_its_own");

        let mut command = std::process::Command::new(
            std::env::current_exe().expect("path to the running test binary"),
        );
        command
            .args([&test_name, "--exact", "--nocapture"])
            .env(BACKSTOP_CHILD_VAR, "1")
            .stdin(std::process::Stdio::null());

        let dropped_privileges = nix::unistd::Uid::effective().is_root();
        if dropped_privileges {
            use std::os::unix::process::CommandExt;
            command.uid(NOBODY_UID).gid(NOBODY_GID);
        }

        let output = command.output().unwrap_or_else(|e| {
            let hint = if dropped_privileges {
                format!(
                    "\nA root test runner re-execs this test as uid {NOBODY_UID}, so the \
                     test binary and every directory above it must be traversable and \
                     executable by other users — mode 0755, not 0700."
                )
            } else {
                String::new()
            };
            panic!("failed to re-exec the test binary: {e}{hint}");
        });

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        let uid: u32 = stdout
            .lines()
            .find_map(|line| line.trim().strip_prefix(BACKSTOP_WITNESS))
            .and_then(|rest| rest.trim().parse().ok())
            .unwrap_or_else(|| {
                panic!(
                    "the child never reached the assertion — a renamed test makes \
                     `--exact {test_name}` match nothing, and libtest reports that as \
                     a pass:\nstdout: {stdout}\nstderr: {stderr}"
                )
            });

        assert!(
            output.status.success(),
            "the re-executed backstop assertion failed:\nstdout: {stdout}\nstderr: {stderr}"
        );
        assert_ne!(
            uid, 0,
            "the assertion ran as root, where the backstop passes by design and \
             witnesses nothing:\nstdout: {stdout}"
        );
    }

    /// The assertion proper, run only in the re-executed child.
    ///
    /// The store path is a temp dir that must survive untouched: the refusal
    /// has to land ahead of every read `run` would otherwise do.
    fn backstop_assertion() {
        // `/tmp` is world-writable, so this holds for the dropped child too;
        // a `TMPDIR` only root can write would defeat it.
        let dir = tempfile::tempdir().expect("a temp dir the current uid can create");
        let db_path = dir.path().join("facelock.db");
        let config = oneshot_config_with_db(&db_path);

        // `skip_setup_check: true` takes the branch with no prompt in it, so
        // a regression that dropped the check runs on to a file read rather
        // than blocking on stdin.
        let err = run(
            &config,
            Some("nonexistent-test-user".to_string()),
            None,
            true,
        )
        .expect_err("enroll::run must refuse a non-root caller without help from main");

        assert!(
            err.to_string().contains("Root required"),
            "expected the root refusal, got: {err}"
        );
        assert!(
            !db_path.exists(),
            "the refusal must precede every store access"
        );

        println!(
            "{BACKSTOP_WITNESS} {}",
            nix::unistd::Uid::effective().as_raw()
        );
    }

    /// `Absent` vs everything else at the pre-enrollment reads: a fresh
    /// install reads as "no models, nothing stale" and the probes create
    /// nothing — enrollment proper is what brings the database into being.
    #[test]
    fn absent_store_reads_as_no_models_without_creating() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        let config = oneshot_config_with_db(&db_path);
        let backend = Backend::select(&config);

        let has_stale = backend.has_models("alice").unwrap()
            && !backend
                .has_models_for_embedder("alice", "embedder")
                .unwrap();
        assert!(!has_stale);
        assert_eq!(
            next_label("2026-08-13", "alice", &backend).unwrap(),
            "2026-08-13-1"
        );
        assert!(
            !db_path.exists(),
            "pre-enrollment reads must not create the database"
        );
    }

    /// The counterpart: an unreadable (present) store is NOT `Absent` — the
    /// stale-embedder check propagates it instead of skipping the warning.
    #[test]
    fn stale_embedder_check_propagates_unreadable_store() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let config = oneshot_config_with_db(&db_path);
        let backend = Backend::select(&config);
        assert!(backend.has_models("alice").is_err());
    }

    /// C4: a store failure while picking the next label propagates — it must
    /// not silently fall back to a "-1" suffix.
    #[test]
    fn next_label_propagates_store_failure() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        std::fs::write(&db_path, b"this is not a sqlite database").unwrap();

        let config = oneshot_config_with_db(&db_path);
        let backend = Backend::select(&config);
        assert!(next_label("2026-08-13", "alice", &backend).is_err());
    }

    #[test]
    fn next_label_counts_existing_labels() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("facelock.db");
        {
            let store = facelock_store::FaceStore::create(&db_path).unwrap();
            let emb = [0.5f32; 512];
            store
                .add_model("alice", "2026-08-13-1", &emb, "embedder")
                .unwrap();
            store
                .add_model("alice", "2026-08-13-2", &emb, "embedder")
                .unwrap();
        }

        let config = oneshot_config_with_db(&db_path);
        let backend = Backend::select(&config);
        assert_eq!(
            next_label("2026-08-13", "alice", &backend).unwrap(),
            "2026-08-13-3"
        );
        // A fresh prefix (or user) starts at -1.
        assert_eq!(
            next_label("2026-08-14", "alice", &backend).unwrap(),
            "2026-08-14-1"
        );
        assert_eq!(
            next_label("2026-08-13", "bob", &backend).unwrap(),
            "2026-08-13-1"
        );
    }
}
