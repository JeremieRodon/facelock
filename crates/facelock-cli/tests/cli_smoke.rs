//! Smoke tests for the facelock CLI binary.

use std::process::{Command, Stdio};

fn facelock_bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_facelock"))
}

/// DEC-6/C6 contract: every root-required command must refuse *before*
/// emitting any prompt text or touching state, when invoked non-root with no
/// TTY attached. Closing stdin (rather than leaving it inherited) forces
/// `require_root`'s non-interactive branch: `isatty(0)` is false on a closed
/// pipe, so it hard-errors instead of offering to re-exec with sudo — which
/// would otherwise hang waiting for input that never arrives.
///
/// Skips (rather than failing) under an actual root test runner: these
/// commands may proceed past the root check and then fail for unrelated
/// reasons, and this contract has nothing to assert in that case.
fn assert_refuses_before_output(args: &[&str], forbidden_substrings: &[&str]) {
    if nix::unistd::Uid::effective().is_root() {
        eprintln!("skipping {args:?}: non-root refusal cannot be tested as root");
        return;
    }

    let output = facelock_bin()
        .args(args)
        .stdin(Stdio::null())
        .output()
        .unwrap_or_else(|e| panic!("failed to execute facelock {args:?}: {e}"));

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        stderr.contains("Root required"),
        "facelock {args:?} should refuse with 'Root required', got:\nstdout: {stdout}\nstderr: {stderr}"
    );

    for forbidden in forbidden_substrings {
        assert!(
            !stdout.contains(forbidden) && !stderr.contains(forbidden),
            "facelock {args:?} must refuse BEFORE emitting {forbidden:?} (C6 ordering), \
             got:\nstdout: {stdout}\nstderr: {stderr}"
        );
    }
}

#[test]
fn status_refuses_before_root_non_root() {
    assert_refuses_before_output(&["status"], &["facelock system status"]);
}

#[test]
fn devices_refuses_before_root_non_root() {
    assert_refuses_before_output(
        &["devices"],
        &["Available video devices", "No video devices found"],
    );
}

#[test]
fn preview_refuses_before_root_non_root() {
    assert_refuses_before_output(
        &["preview", "--text-only"],
        &["Graphical preview", "text-only mode"],
    );
}

#[test]
fn test_cmd_refuses_before_root_non_root() {
    assert_refuses_before_output(
        &["test", "--user", "nonexistent-test-user"],
        &["Testing face recognition", "No face models enrolled"],
    );
}

#[test]
fn audit_refuses_before_root_non_root() {
    // audit is scripted/hard-error only (never an interactive prompt), but
    // the non-interactive refusal path is identical either way.
    assert_refuses_before_output(&["audit"], &["Audit logging"]);
}

#[test]
fn bench_refuses_before_root_non_root() {
    assert_refuses_before_output(&["bench", "cold-auth"], &["cold auth", "Cold Auth"]);
}

#[test]
fn config_edit_refuses_before_root_non_root() {
    assert_refuses_before_output(&["config", "--edit"], &["Config file:", "Config saved"]);
}

#[test]
fn list_refuses_before_root_non_root() {
    assert_refuses_before_output(
        &["list", "--user", "nonexistent-test-user"],
        &["Face models for user", "No face models enrolled"],
    );
}

#[test]
fn remove_refuses_before_confirmation_prompt_non_root() {
    // C6: historically remove.rs asked for Y/N confirmation *before* checking
    // root. Pin that the root check now runs first — the confirmation prompt
    // text must never appear.
    assert_refuses_before_output(
        &["remove", "1", "--user", "nonexistent-test-user"],
        &["Remove face model #1"],
    );
}

#[test]
fn clear_refuses_before_confirmation_prompt_non_root() {
    assert_refuses_before_output(
        &["clear", "--user", "nonexistent-test-user"],
        &["Remove ALL face models", "No face models enrolled"],
    );
}

#[test]
fn pam_add_refuses_before_touching_pam_d_non_root() {
    // C6: the root check is the first statement in `commands::pam::run`, ahead
    // of the module-presence check, the plan, and `--dry-run`. A dry run that
    // succeeded unprivileged would be a preview of a command that cannot run.
    assert_refuses_before_output(
        &["pam", "add", "--service", "sudo", "--dry-run"],
        &[
            "About to modify",
            "Would add the facelock PAM line",
            "==> facelock PAM line",
        ],
    );
}

#[test]
fn pam_remove_refuses_before_touching_pam_d_non_root() {
    assert_refuses_before_output(
        &["pam", "remove", "--service", "sudo", "--dry-run"],
        &[
            "Would remove the facelock PAM line",
            "Removed facelock PAM line",
        ],
    );
}

#[test]
fn help_exits_successfully() {
    let output = facelock_bin()
        .arg("--help")
        .output()
        .expect("failed to execute facelock --help");

    assert!(
        output.status.success(),
        "facelock --help should exit 0, got: {}",
        output.status
    );
}

#[test]
fn version_exits_successfully() {
    let output = facelock_bin()
        .arg("--version")
        .output()
        .expect("failed to execute facelock --version");

    assert!(
        output.status.success(),
        "facelock --version should exit 0, got: {}",
        output.status
    );
}

#[test]
fn version_output_contains_package_name() {
    let output = facelock_bin()
        .arg("--version")
        .output()
        .expect("failed to execute facelock --version");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("facelock"),
        "version output should contain 'facelock', got: {stdout}"
    );
}

#[test]
fn help_output_contains_expected_subcommands() {
    let output = facelock_bin()
        .arg("--help")
        .output()
        .expect("failed to execute facelock --help");

    let stdout = String::from_utf8_lossy(&output.stdout);

    let expected_subcommands = [
        "setup", "enroll", "remove", "clear", "list", "test", "preview", "config", "status",
        "devices",
    ];

    for subcmd in &expected_subcommands {
        assert!(
            stdout.to_lowercase().contains(subcmd),
            "help output should mention subcommand '{subcmd}', got:\n{stdout}"
        );
    }
}

#[test]
fn no_args_shows_error_or_help() {
    let output = facelock_bin()
        .output()
        .expect("failed to execute facelock with no args");

    // clap with required subcommand exits non-zero when no subcommand is given
    assert!(
        !output.status.success(),
        "facelock with no args should exit non-zero"
    );

    // Should show some usage information on stderr
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage") || stderr.contains("usage") || stderr.contains("facelock"),
        "stderr should contain usage info, got: {stderr}"
    );
}
