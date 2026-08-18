//! The Messages seam (D10): user-facing text as typed events.
//!
//! A message is a thing the CLI wants to tell a human — an event carrying
//! data, not a string. Rendering happens at the edge, per sink, through the
//! [`Message`] trait:
//!
//! - [`Message::localized`] — gettext-translated text for a human (terminal
//!   via [`Terminal`], desktop notification bodies, `anyhow` errors whose
//!   `Display` lands on stderr via [`fail`]).
//! - [`Message::machine`] — a C-locale, locale-independent event line for the
//!   tracing side channel.
//!
//! `machine()` is a derived `Debug` rendering, which makes it a debugging aid
//! and not a serialization format — renaming a field changes the output with
//! nothing to catch it. Persisted records go through the audit crate's serde
//! path, which owns its own field names and its own compatibility rules; do
//! not route `machine()` into `audit.jsonl` or any other stored artifact.
//!
//! This is how D2 ("logs stay English") holds *by construction*: a message
//! routed through this type cannot reach a log sink in translated form,
//! because the log rendering never consults gettext. The boundary is the
//! sink, not the string — `bail!` text a human reads on stderr localizes,
//! the same event written to audit/syslog/tracing does not.
//!
//! # Three sinks write to stdout, and `--quiet` knows all three
//!
//! `--quiet` acts here rather than at the call sites: [`set_verbosity`] is
//! read by the sinks themselves, so no caller ever asks whether it should be
//! printing.
//!
//! | Sink | Renders | Under `--quiet` |
//! |---|---|---|
//! | [`Terminal::info`] | localized | silenced |
//! | [`payload`] | never localized | silenced |
//! | [`Terminal::notice`] | localized | still prints |
//!
//! [`payload`] is the machine half of stdout: `--json` documents, `is-enrolled`'s
//! state word, `capabilities`' name list. It takes an already-rendered `&str`,
//! so no catalog is consulted on the way out — a payload cannot pick up a
//! translation by being routed through the seam. [`Terminal::notice`] is for
//! the rare human line that must be seen and must stay on stdout for byte
//! compatibility.
//!
//! One rule follows: **`--quiet` suppresses stdout, and on a command whose
//! stdout *is* the payload that means the payload too — the exit code is the
//! answer.** Errors, prompts, exit codes and the `RUST_LOG` event stream are
//! unchanged.
//!
//! # The vocabulary is split by domain
//!
//! There is no single `Message` enum. Each domain owns its own, and this
//! module owns everything they share — the trait, the sinks, and the gettext
//! plumbing ([`init`]). A feature touching one domain does not touch the
//! others' files, and no list here has to grow when a domain does:
//!
//! | Module | What it says |
//! |---|---|
//! | [`access`] | config load, privilege, which backend answered |
//! | [`face`] | `enroll` / `test` / `remove` / `clear` |
//! | [`status`] | the `facelock status` report's prose |
//! | [`notify`] | notification bodies (rendered `NotifyEvent`s) |
//! | [`setup`] | the wizard spine, step failures, closing summary |
//! | [`device`] | camera and inference-device selection |
//! | [`download`] | model download and verification |
//! | [`system`] | daemon unit and `facelock` group setup |
//! | [`pam`] | `/etc/pam.d/*` configuration |
//!
//! # Adding a message (the conversion pattern)
//!
//! 1. Pick the domain module, and add a variant carrying the data (not the
//!    formatted string): `EnrollComplete { model_id: u32, count: u32, label:
//!    String }`.
//! 2. Add one arm to that domain's `localized`. The English template is the
//!    msgid: keep it on a **single source line** with explicit `\n` escapes
//!    (no `\`-continuations, no raw strings) so `just pot` can extract it,
//!    and use **named placeholders** (`{user}`) filled via [`fill`] so
//!    translators can reorder them. Pre-format numbers that need precision
//!    (`format!("{similarity:.2}")`) before filling — Rust formatting is
//!    locale-independent, so numbers stay stable across locales.
//! 3. Add a sample to that domain's [`Samples`] list and bump its
//!    [`Samples::VARIANT_COUNT`]. The compiler forces step 2 (the `localized`
//!    match is wildcard-free); the count is what forces this step, and the
//!    sweep says so when the two disagree.
//! 4. Replace the `println!`/`eprintln!`/`bail!` site with
//!    `Terminal.info(&msg)` / `Terminal.error(&msg)` / `return Err(fail(msg))`.
//!
//! The English fallback (no `.mo` installed, or the C locale) renders
//! byte-identically to the string the call site used to print; container
//! tests that grep CLI output rely on this.
//!
//! # What must NOT come through here
//!
//! Machine-facing output never localizes: `--json` output, `is-enrolled`'s
//! stdout contract, `audit.jsonl`, syslog/tracing lines, and D-Bus error
//! strings (PAM substring-matches those on the wire — see
//! `pam_code_for_daemon_error` in `pam-facelock`). Route none of them
//! through [`Message::localized`].
//!
//! The first two still belong on stdout, and still have to obey `--quiet`, so
//! they go through [`payload`] instead: same global, no gettext. The rest are
//! not stdout at all and do not come through this module.
//!
//! # Why this lives in `facelock-cli`
//!
//! The two decided constraints (domain map §7): gettext everywhere (D1, via
//! the same ~20-line libc FFI the PAM module uses — `pam_facelock` keeps its
//! own copy and its own text domain), and logs stay English (D2). No non-CLI
//! crate renders user text today, and `facelock-core`'s dependency contract
//! excludes libc — when the daemon D-Bus server moves out of this crate
//! (H7), the seam moves with it or into core alongside that work.

use std::ffi::{CStr, CString};

pub mod access;
pub mod device;
pub mod download;
pub mod face;
pub mod notify;
pub mod pam;
pub mod setup;
pub mod status;
pub mod system;

pub use access::AccessMessage;
pub use device::DeviceMessage;
pub use download::DownloadMessage;
pub use face::FaceMessage;
pub use notify::NotifyMessage;
pub use pam::PamMessage;
pub use setup::SetupMessage;
pub use status::StatusMessage;
pub use system::SystemMessage;

// ---------------------------------------------------------------------------
// Gettext (libc FFI) — the CLI's copy of pam-facelock's wrapper, domain
// "facelock". Kept dependency-free on purpose: gettext ships in glibc.
// ---------------------------------------------------------------------------

/// Text domain for CLI translations (`/usr/share/locale/<lang>/LC_MESSAGES/facelock.mo`).
const GETTEXT_DOMAIN: &CStr = c"facelock";

unsafe extern "C" {
    safe fn dgettext(
        domainname: *const libc::c_char,
        msgid: *const libc::c_char,
    ) -> *const libc::c_char;
    safe fn bindtextdomain(
        domainname: *const libc::c_char,
        dirname: *const libc::c_char,
    ) -> *const libc::c_char;
    safe fn bind_textdomain_codeset(
        domainname: *const libc::c_char,
        codeset: *const libc::c_char,
    ) -> *const libc::c_char;
    // Not `safe`: glibc marks setlocale MT-Unsafe (const:locale) while
    // dgettext and bindtextdomain are MT-safe. It mutates process-global
    // state every later translation reads, so each call carries a SAFETY
    // note about who else could be running.
    fn setlocale(category: libc::c_int, locale: *const libc::c_char) -> *const libc::c_char;
}

/// Initialize localization for this process. Call once, early in `main`.
///
/// Sets LC_MESSAGES (only) from the environment: translations follow the
/// user's locale without letting LC_NUMERIC and friends leak into in-process
/// C libraries (ONNX Runtime parses floats). Output charset is pinned to
/// UTF-8 regardless of LC_CTYPE. `FACELOCK_LOCALEDIR` overrides the catalog
/// directory — translations only, English fallback otherwise, so it grants
/// nothing security-relevant.
pub fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        // SAFETY: setlocale is MT-Unsafe against concurrent translation.
        // `init` is documented as "call once, early in `main`" and the `Once`
        // enforces the once — at that point the process is single-threaded,
        // so nothing can be inside dgettext while the locale changes.
        unsafe { setlocale(libc::LC_MESSAGES, c"".as_ptr()) };
        let dir =
            std::env::var("FACELOCK_LOCALEDIR").unwrap_or_else(|_| "/usr/share/locale".to_string());
        if let Ok(c_dir) = CString::new(dir) {
            bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c_dir.as_ptr());
        }
        bind_textdomain_codeset(GETTEXT_DOMAIN.as_ptr(), c"UTF-8".as_ptr());
    });
}

/// Translate a msgid via gettext. Falls back to the original English string
/// if no translation is available or if gettext fails.
///
/// This is the xgettext extraction keyword (`just pot` scans the domain
/// modules for `translate("...")`), so every call must pass a string literal.
fn translate(msgid: &str) -> String {
    let Ok(c_msgid) = CString::new(msgid) else {
        return msgid.to_string();
    };
    let result = dgettext(GETTEXT_DOMAIN.as_ptr(), c_msgid.as_ptr());
    if result.is_null() {
        return msgid.to_string();
    }
    unsafe { CStr::from_ptr(result) }
        .to_str()
        .unwrap_or(msgid)
        .to_string()
}

/// Substitute named placeholders (`{user}`) in a translated template.
///
/// Values are substituted in order; a value that itself contains a later
/// placeholder token would be re-substituted, so keep placeholder names
/// unlikely to occur in data (they are).
fn fill(template: String, args: &[(&str, String)]) -> String {
    let mut out = template;
    for (name, value) in args {
        out = out.replace(&format!("{{{name}}}"), value);
    }
    out
}

// ---------------------------------------------------------------------------
// The trait every domain implements
// ---------------------------------------------------------------------------

/// Something the CLI wants to tell a human. Data only — rendering is the
/// sink's job.
pub trait Message: std::fmt::Debug {
    /// Render for a human: gettext at the edge, English fallback
    /// byte-identical to the historical inline string.
    fn localized(&self) -> String;

    /// Render for the tracing side channel: the C-locale event line. Derived
    /// from the variant's `Debug` form — variant and field names are the
    /// vocabulary, values print locale-independently, and gettext is never
    /// consulted, which is what makes D2 hold by construction.
    ///
    /// Derived `Debug` is not a serialization format. This output is for
    /// humans reading `RUST_LOG=facelock=debug`; anything persisted (audit
    /// records above all) goes through serde, where the field names are a
    /// declared contract rather than an accident of the type definition.
    fn machine(&self) -> String {
        format!("{self:?}")
    }
}

// ---------------------------------------------------------------------------
// Verbosity
// ---------------------------------------------------------------------------

/// How much the stdout sinks say.
///
/// **`--quiet` suppresses stdout; errors, prompts and exit codes are
/// unchanged.** [`Terminal::error`] is never suppressed, so a quiet run that
/// fails still says why on stderr and still exits non-zero. That is
/// `is-enrolled --quiet`'s existing semantics (see
/// [`crate::commands::is_enrolled`]) and it is the house rule for every
/// command: on a command whose stdout is a machine payload, `--quiet` takes
/// the payload with it and the exit code is the whole answer. Prompts
/// ([`Terminal::confirm`]) are unaffected — a silenced question is a hang, not
/// a quieter program — and so is [`Terminal::notice`], the sink that exists
/// for the lines that must be seen. The debug side channel (`trace`) also
/// keeps firing: the machine event stream is not user-facing output, so
/// `RUST_LOG=facelock=debug` works the same either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Verbosity {
    #[default]
    Normal,
    Quiet,
}

/// Process-global verbosity, written once from the parsed global `--quiet`
/// flag before any other thread exists.
static VERBOSITY: std::sync::OnceLock<Verbosity> = std::sync::OnceLock::new();

/// Set the process verbosity. Call once, early in `main`, next to [`init`].
///
/// A second call is a programming error — the flag is parsed once and the
/// sinks are allowed to assume the answer does not change under them. The
/// second write is dropped rather than refused, since returning a `Result` to
/// a caller three lines into `main` buys nothing; the `debug_assert` is what
/// makes the drop visible to a test binary that calls this twice instead of
/// leaving it to be discovered as a `--quiet` that stopped working.
///
/// The write is a `let` binding, not the assert's argument: `debug_assert!`
/// compiles its condition out of a release build, which would take the write
/// with it.
pub fn set_verbosity(verbosity: Verbosity) {
    let first_write = VERBOSITY.set(verbosity).is_ok();
    debug_assert!(
        first_write,
        "set_verbosity called twice; the global is written once, from main"
    );
}

/// The process verbosity ([`Verbosity::Normal`] until [`set_verbosity`] runs).
pub(crate) fn verbosity() -> Verbosity {
    VERBOSITY.get().copied().unwrap_or_default()
}

/// What [`Terminal::info`] writes at this verbosity, or `None` when silenced.
///
/// The decision is a pure function of the level rather than of the global, so
/// the rule is testable without mutating process state or capturing stdout —
/// what matters is *what the sink decides*, not what a pipe received.
fn info_at(msg: &dyn Message, verbosity: Verbosity) -> Option<String> {
    (verbosity == Verbosity::Normal).then(|| msg.localized())
}

/// What [`Terminal::notice`] writes at this verbosity: always the message.
///
/// The unused level is the contract, stated in the signature so a test can
/// hold it: this sink is offered the verbosity and ignores it.
fn notice_at(msg: &dyn Message, _verbosity: Verbosity) -> Option<String> {
    Some(msg.localized())
}

/// What [`payload`] writes at this verbosity, or `None` when silenced.
///
/// Borrowed through unchanged: no gettext, no formatting, no allocation. A
/// payload is bytes a script parses, and this sink's whole job is to keep them
/// that way while still answering to `--quiet`.
fn payload_at(text: &str, verbosity: Verbosity) -> Option<&str> {
    (verbosity == Verbosity::Normal).then_some(text)
}

// ---------------------------------------------------------------------------
// Sinks
// ---------------------------------------------------------------------------

/// Emit the machine rendering on the debug side channel. Every sink does this
/// before rendering for a human, so `RUST_LOG=facelock=debug` shows the stable
/// C-locale event stream next to whatever the user saw.
fn trace(msg: &dyn Message) {
    tracing::debug!(target: "facelock::message", "{}", msg.machine());
}

/// The human sink on this terminal. Localized text to stdout/stderr; the
/// same event goes to tracing at debug level in its machine rendering.
pub struct Terminal;

impl Terminal {
    /// Informational message to stdout — the half [`Verbosity::Quiet`]
    /// silences. The machine rendering is emitted either way.
    pub fn info(&self, msg: &dyn Message) {
        trace(msg);
        if let Some(line) = info_at(msg, verbosity()) {
            println!("{line}");
        }
    }

    /// Human message to stdout that `--quiet` does **not** silence.
    ///
    /// For the few lines that must be seen and must stay on stdout, where
    /// [`Terminal::error`]'s stderr would change the stream a caller reads:
    /// [`PamMessage::PamInstalled`]'s rollback instructions (the one message
    /// that tells a locked-out operator how to get back in),
    /// [`SetupMessage::EncryptionDisabledWarning`], and the context a prompt
    /// needs to be answerable. Everything else informational is
    /// [`Terminal::info`] — a `notice` that did not have to be seen is just an
    /// unquietable one.
    pub fn notice(&self, msg: &dyn Message) {
        trace(msg);
        if let Some(line) = notice_at(msg, verbosity()) {
            println!("{line}");
        }
    }

    /// Warning/error message to stderr (the process continues).
    ///
    /// Never suppressed: `--quiet` is about informational chatter, and a
    /// program that hid the reason it failed would be a worse one.
    pub fn error(&self, msg: &dyn Message) {
        trace(msg);
        eprintln!("{}", msg.localized());
    }

    /// Localized confirmation, defaulting to no.
    pub fn confirm(&self, msg: &dyn Message) -> anyhow::Result<bool> {
        trace(msg);
        eprint!("{}", prompt_line(msg, "[y/N]"));
        Ok(matches!(read_answer()?.as_str(), "y" | "yes"))
    }

    /// Localized confirmation, defaulting to yes.
    pub fn confirm_default_yes(&self, msg: &dyn Message) -> anyhow::Result<bool> {
        trace(msg);
        eprint!("{}", prompt_line(msg, "[Y/n]"));
        Ok(!matches!(read_answer()?.as_str(), "n" | "no"))
    }
}

/// The machine sink: one line of payload on stdout, C-locale, `--quiet`-aware.
///
/// This is what a script parses — a `--json` document, `is-enrolled`'s state
/// word, `capabilities`' name list — so it takes an already-rendered `&str`
/// and prints it. Nothing here consults gettext: there is no [`Message`] to
/// call [`Message::localized`] on, so routing a payload through the seam
/// cannot translate it. That is the "boundary is the sink" trick that keeps
/// logs English (D2), pointed the other way — weaker in one direction, since
/// a caller is free to hand this sink text it localized itself.
///
/// It reads the same [`Verbosity`] as [`Terminal::info`], which is the whole
/// point: before this existed `--quiet` had three implementations and a silent
/// no-op — this global, three `quiet: bool` parameters each gating a bare
/// `println!`, and two commands that took the flag and ignored it. One sink,
/// one rule: `--quiet` suppresses stdout and the exit code is the answer.
///
/// Nothing is traced. A payload is not an event: it is already on stdout in a
/// stable form, and copying a JSON document into the debug stream would say
/// nothing the reader cannot see.
///
/// **The one payload that does not come through here** is `preview --json`'s
/// frame stream (`commands/preview/text_only.rs`): it emits a document per
/// frame until the operator interrupts it, so a `--quiet` that silenced it
/// would leave a command that produces nothing forever. That module denies
/// `clippy::print_stdout` and scans itself for the seam's stdout sinks, so the
/// exception cannot spread past the frame loops it was made for.
pub fn payload(text: &str) {
    if let Some(line) = payload_at(text, verbosity()) {
        println!("{line}");
    }
}

/// The exact bytes of an inline prompt: the localized question, the English
/// answer hint, one trailing space, no newline.
fn prompt_line(msg: &dyn Message, hint: &str) -> String {
    format!("{} {hint} ", msg.localized())
}

/// Read one answer from stdin, trimmed and lowercased.
///
/// The hint (`[y/N]`, `[Y/n]`) is appended by the prompting method and the
/// tokens are matched here, so the two halves of the contract sit together.
/// Neither half may enter a catalog: the tokens below are English, so a
/// translated hint would advertise an answer this parser cannot accept.
///
/// This lives in the sink rather than in `ipc_client` — the prompt is written
/// here, so the answer is read here. `ipc_client` imports the message types,
/// so the seam calling back into it was a cycle waiting to bite.
fn read_answer() -> anyhow::Result<String> {
    use anyhow::Context;
    let mut input = String::new();
    std::io::stdin()
        .read_line(&mut input)
        .context("failed to read input")?;
    Ok(input.trim().to_lowercase())
}

/// Localized text for an `anyhow` context layer, traced like any other render.
///
/// `.context(explain(&msg))`, never `.context(msg.localized())`: every sink
/// emits the machine rendering next to the human one, and a context layer
/// that skipped it would show up on stderr while going missing from the
/// `RUST_LOG=facelock=debug` event stream.
pub fn explain(msg: &dyn Message) -> String {
    trace(msg);
    msg.localized()
}

/// An error whose `Display` is destined for a human on stderr (the CLI's
/// `anyhow` exit path) — so it localizes at birth. Never use this for errors
/// that cross the D-Bus wire or land in audit/syslog.
pub fn fail(msg: impl Message) -> anyhow::Error {
    trace(&msg);
    anyhow::anyhow!("{}", msg.localized())
}

// ---------------------------------------------------------------------------
// Test support: the sample list that feeds the sweeps
// ---------------------------------------------------------------------------

/// One constructed sample per variant of a domain, for the sweeps below.
///
/// # What holds this to the vocabulary
///
/// Three things, and it is worth being exact about which is which, because an
/// earlier version of this trait claimed the first one covered all three:
///
/// - **The compiler** proves every variant has a `localized` arm: that `match`
///   is wildcard-free, so a new variant does not build until it renders.
/// - **[`VARIANT_COUNT`](Samples::VARIANT_COUNT)** proves [`samples`](Samples::samples)
///   has not fallen behind: `every_variant_has_a_sample` fails when the list and
///   the count disagree, and fails again if two entries are the same variant.
///   Adding a variant therefore touches the enum, the rendering, the sample
///   list and the count, and the count is the one that says so out loud.
/// - **Nothing** can prove the count itself: stable Rust cannot count enum
///   variants, so a variant added while touching neither the list nor the
///   count is invisible here. What is *not* possible any more is the failure
///   this replaced: a linked-list walk whose arms were compiler-checked while
///   its results were not, so `Foo => Bar` beside `Prev => Bar` compiled,
///   dropped `Foo` from the sweep, and could route the walk into a cycle (the
///   old `assert!(out.len() < 10_000)` was the tell).
#[cfg(test)]
pub(crate) trait Samples: Sized {
    /// How many variants this domain has. Bumped with the sample below it.
    const VARIANT_COUNT: usize;

    /// Every variant of this domain, exactly once, in enum order.
    fn samples() -> Vec<Self>;
}

/// Placeholder-sized string for sample values.
#[cfg(test)]
fn sample_text(v: &str) -> String {
    v.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// In the test environment no facelock .mo is installed for the C locale,
    /// so `localized()` is the English fallback — these pins are exactly the
    /// bytes the historical inline strings produced (container tests grep
    /// some of them).
    ///
    /// The strings pinned here are `face`, `access` and `pam` ones; each
    /// domain module pins its own alongside its `Samples` list.
    #[test]
    fn face_access_and_pam_fallback_is_byte_identical() {
        assert_eq!(
            FaceMessage::EnrollComplete {
                model_id: 3,
                count: 12,
                label: "2026-08-14-1".into()
            }
            .localized(),
            "\nFace enrolled successfully!\n  Model ID: 3\n  Embeddings: 12\n  Label: 2026-08-14-1"
        );
        assert_eq!(
            FaceMessage::TestNoMatch {
                similarity: 0.5,
                seconds: 1.234
            }
            .localized(),
            "No match (best: 0.50) after 1.2s"
        );
        assert_eq!(
            FaceMessage::TestMatchedModel {
                model_id: 7,
                label: "front".into(),
                similarity: 0.876,
                seconds: 0.5
            }
            .localized(),
            "Matched model #7 'front' (similarity: 0.88) in 0.50s"
        );
        assert_eq!(
            AccessMessage::NoConfigFile {
                path: "/etc/facelock/config.toml".into()
            }
            .localized(),
            "no config file at /etc/facelock/config.toml — run 'sudo facelock setup' to create one"
        );
        assert_eq!(
            AccessMessage::RootRequired {
                hint: "sudo facelock enroll".into()
            }
            .localized(),
            "Root required.\n  Run: sudo facelock enroll"
        );
        assert_eq!(
            FaceMessage::ClearedModels {
                count: 2,
                user: "alice".into()
            }
            .localized(),
            "Removed 2 face model(s) for user 'alice'."
        );
        assert_eq!(
            PamMessage::PamServiceAbsent {
                path: "/etc/pam.d/omarchy-lock-face".into()
            }
            .localized(),
            "PAM service file absent: /etc/pam.d/omarchy-lock-face. Nothing to remove."
        );
        // The closing hint of `facelock pam add` was four bare `println!`s in
        // `commands/setup.rs` until #174 folded them into one message. These
        // are those four lines' exact bytes, captured from the commit before
        // the move: a leading blank line, three `==>` lines, and no trailing
        // newline (the sink's `println!` supplies it).
        assert_eq!(
            PamMessage::PamExtensionHint {
                line: "auth      sufficient pam_facelock.so".into()
            }
            .localized(),
            "\n==> facelock PAM line for manual extension to other services:\n\
             ==>   auth      sufficient pam_facelock.so\n\
             ==> Add the above line above the first 'auth' line in any /etc/pam.d/<service> file."
        );
        // Not a historical pin: #174 changed this text on purpose, from
        // `setup --pam --remove --service X` to the verb that now owns the
        // undo. Pinned so the next change to it is also on purpose — this is
        // the one message that tells a locked-out operator how to get back in.
        assert_eq!(
            PamMessage::PamInstalled {
                path: "/etc/pam.d/sudo".into(),
                backup: "/etc/pam.d/sudo.facelock-backup".into(),
                service: "sudo".into()
            }
            .localized(),
            "Installed facelock PAM line into /etc/pam.d/sudo\n\n\
             To rollback:\n  sudo cp /etc/pam.d/sudo.facelock-backup /etc/pam.d/sudo\n\
             \u{20} # or: sudo facelock pam remove --service sudo"
        );
        // Not a historical pin either: #169 renamed `preview --text-only` to
        // `preview --json`, and this is the one runtime string that tells an
        // operator which flag to reach for, so it was changed on purpose.
        // Pinned so the next change to it is also on purpose. The second
        // sentence says "text-only mode" about the mode, not the flag.
        assert_eq!(
            AccessMessage::PreviewGraphicalNeedsDaemonOneshot.localized(),
            "Graphical preview requires the daemon. In oneshot mode, use --json.\n\
             Falling back to text-only mode.\n"
        );
        // The module-missing refusal was an inline `bail!` on the same path.
        assert_eq!(
            PamMessage::PamModuleNotInstalled {
                path: "/lib/security/pam_facelock.so".into()
            }
            .localized(),
            "PAM module not found at /lib/security/pam_facelock.so.\n\
             Install it first: cargo build --release -p pam-facelock && \
             sudo cp target/release/libpam_facelock.so /lib/security/pam_facelock.so"
        );
    }

    /// `--quiet` silences the two suppressible stdout sinks, and only those.
    ///
    /// Asserted on the sinks' decisions rather than on captured stdout: the
    /// decision is the contract, and a capture test would prove the same thing
    /// while making every future sink change a plumbing exercise. The
    /// decisions are pure functions of the level, so nothing here touches the
    /// process global — which is why this test can exist beside a `OnceLock`
    /// that `main` writes exactly once.
    ///
    /// `error`, `confirm` and `confirm_default_yes` are absent because they
    /// are not offered a level at all: they are on stderr, where `--quiet`
    /// has never reached.
    #[test]
    fn quiet_silences_stdout_except_notice() {
        let msg = FaceMessage::ModelsRequired;
        let text = "Models required. Run `facelock setup` to download them.";

        assert_eq!(info_at(&msg, Verbosity::Normal), Some(text.to_string()));
        assert_eq!(info_at(&msg, Verbosity::Quiet), None);

        assert_eq!(payload_at("{}", Verbosity::Normal), Some("{}"));
        assert_eq!(payload_at("{}", Verbosity::Quiet), None);

        // The unsuppressible one: same text at either level.
        assert_eq!(notice_at(&msg, Verbosity::Normal), Some(text.to_string()));
        assert_eq!(
            notice_at(&msg, Verbosity::Quiet),
            Some(text.to_string()),
            "notice exists to be seen; --quiet must not reach it"
        );
    }

    /// An unwritten global reads as `Normal`, so a `main` that forgot
    /// [`set_verbosity`] hides nothing rather than everything.
    ///
    /// Nothing in this crate's tests writes the `OnceLock`; if that changes,
    /// this is the test that says the default stopped being observable.
    #[test]
    fn unset_verbosity_reads_as_normal() {
        assert_eq!(Verbosity::default(), Verbosity::Normal);
        assert_eq!(verbosity(), Verbosity::Normal);
    }

    /// The answer hint is appended by the sink and the question alone is the
    /// msgid, so a translator cannot advertise an answer `read_answer` will
    /// not accept. The composed bytes are the ones these prompts always had.
    #[test]
    fn answer_hints_are_appended_not_translated() {
        assert_eq!(
            AccessMessage::SudoReexecPrompt.localized(),
            "Root required. Re-run with sudo?",
            "the [Y/n] hint must not be part of the msgid"
        );
        assert_eq!(
            prompt_line(&AccessMessage::SudoReexecPrompt, "[Y/n]"),
            "Root required. Re-run with sudo? [Y/n] "
        );
        assert_eq!(
            prompt_line(&FaceMessage::ConfirmRunSetupNow, "[y/N]"),
            "Run setup now? [y/N] "
        );
    }

    /// The domain list the sweeps below run over. Single-sited because it is
    /// the one list here that no compiler checks: a new domain module joins
    /// the seam by being added to this macro.
    macro_rules! every_domain {
        ($sweep:ident) => {{
            $sweep::<AccessMessage>();
            $sweep::<FaceMessage>();
            $sweep::<StatusMessage>();
            $sweep::<NotifyMessage>();
            $sweep::<SetupMessage>();
            $sweep::<DeviceMessage>();
            $sweep::<DownloadMessage>();
            $sweep::<SystemMessage>();
            $sweep::<PamMessage>();
        }};
    }

    /// Every message in every domain renders with all placeholders
    /// substituted — a leftover `{name}` means a template/argument mismatch.
    #[test]
    fn no_unfilled_placeholders() {
        fn sweep<M: Message + Samples>() {
            for msg in M::samples() {
                let rendered = msg.localized();
                assert!(
                    !rendered.contains('{') && !rendered.contains('}'),
                    "unfilled placeholder in {msg:?}: {rendered:?}"
                );
            }
        }
        every_domain!(sweep);
    }

    /// Each domain's sample list holds one sample per variant.
    ///
    /// Two failures, which together are the whole of what [`Samples`]
    /// guarantees (its doc comment says what is left over): a list that has
    /// drifted from `VARIANT_COUNT`, and a list that names the same variant
    /// twice — the copy-paste mistake that used to hide a variant from the
    /// sweep above while still compiling.
    #[test]
    fn every_variant_has_a_sample() {
        fn sweep<M: Message + Samples>() {
            let samples = M::samples();
            assert_eq!(
                samples.len(),
                M::VARIANT_COUNT,
                "{} samples for {} variants — add the missing sample, or fix \
                 VARIANT_COUNT if a variant was removed: {samples:?}",
                samples.len(),
                M::VARIANT_COUNT,
            );
            for (index, sample) in samples.iter().enumerate() {
                for other in &samples[index + 1..] {
                    assert_ne!(
                        std::mem::discriminant(sample),
                        std::mem::discriminant(other),
                        "{sample:?} is sampled twice, so some variant is not \
                         sampled at all"
                    );
                }
            }
        }
        every_domain!(sweep);
    }

    /// The machine rendering names the variant and its data, and never goes
    /// through gettext — the D2 side of the seam.
    #[test]
    fn machine_rendering_is_the_debug_vocabulary() {
        let msg = FaceMessage::EnrollComplete {
            model_id: 3,
            count: 12,
            label: "x".into(),
        };
        let line = msg.machine();
        assert!(line.starts_with("EnrollComplete"), "{line}");
        assert!(line.contains("model_id: 3"), "{line}");
        assert!(line.contains("count: 12"), "{line}");
    }

    /// Unknown msgids fall back to the input string (no catalog installed).
    #[test]
    fn translate_falls_back_to_msgid() {
        // Via a binding so xgettext (which extracts literal `translate("...")`
        // calls) does not sweep this probe into the catalog.
        let probe = "facelock test msgid that no catalog contains";
        assert_eq!(translate(probe), probe);
    }

    #[test]
    fn fill_substitutes_named_placeholders() {
        assert_eq!(
            fill(
                "a {x} b {y} c {x}".to_string(),
                &[("x", "1".to_string()), ("y", "2".to_string())]
            ),
            "a 1 b 2 c 1"
        );
    }

    /// `fail` produces an error whose Display is the localized rendering.
    #[test]
    fn fail_renders_localized_display() {
        let err = fail(FaceMessage::ModelsRequired);
        assert_eq!(
            format!("{err}"),
            "Models required. Run `facelock setup` to download them."
        );
    }

    /// Real gettext lookup through a fixture catalog: build a minimal `.mo`
    /// in a tempdir, point the domain at it, and check that `localized()`
    /// translates while `machine()` does not — the D2 seam, exercised
    /// end to end.
    ///
    /// Locale plumbing is process-global, so this test is written to be
    /// harmless to concurrent tests: the fixture translates exactly one
    /// msgid ("Run setup now?"), which no other test pins in English, and
    /// everything is restored on exit. If the environment offers no usable
    /// non-C locale (LANGUAGE is ignored under "C"), the lookup assertions
    /// are skipped; the manual recipe in the module docs of `just pot`
    /// covers that case.
    #[test]
    fn mo_catalog_lookup_translates_localized_but_not_machine() {
        let dir = tempfile::tempdir().unwrap();
        let mo_dir = dir.path().join("xx/LC_MESSAGES");
        std::fs::create_dir_all(&mo_dir).unwrap();
        std::fs::write(
            mo_dir.join("facelock.mo"),
            build_mo(&[("Run setup now?", "XX-RUN-SETUP-NOW")]),
        )
        .unwrap();

        // A non-C locale for LC_MESSAGES, else glibc ignores LANGUAGE.
        //
        // SAFETY: setlocale is MT-Unsafe and cargo runs tests on parallel
        // threads, so this is the one call site that cannot appeal to being
        // single-threaded. `LOCALE_MUTATION` serializes locale-mutating tests
        // against each other; what remains is a window of a few lines against
        // plain dgettext calls, which is why the fixture translates a single
        // msgid no other test pins.
        let _locale = LOCALE_MUTATION.lock().unwrap_or_else(|e| e.into_inner());
        let original = unsafe { setlocale(libc::LC_MESSAGES, std::ptr::null()) };
        let original: CString = if original.is_null() {
            c"C".to_owned()
        } else {
            unsafe { CStr::from_ptr(original) }.to_owned()
        };
        // C.UTF-8 is still a C-family locale for gettext purposes: glibc
        // deliberately ignores LANGUAGE there even though setlocale accepts it.
        let usable = [c"en_US.UTF-8", c"en_US.utf8"]
            .into_iter()
            .find(|l| !unsafe { setlocale(libc::LC_MESSAGES, l.as_ptr()) }.is_null());
        if usable.is_none() {
            eprintln!("skipping .mo lookup assertions: no usable non-C locale in this environment");
            return;
        }

        // SAFETY: process-global env mutation in a test; restored below.
        unsafe { std::env::set_var("LANGUAGE", "xx") };
        let c_dir = CString::new(dir.path().to_str().unwrap()).unwrap();
        // A fresh binding also invalidates glibc's per-domain catalog cache.
        bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c_dir.as_ptr());
        bind_textdomain_codeset(GETTEXT_DOMAIN.as_ptr(), c"UTF-8".as_ptr());

        let localized = FaceMessage::ConfirmRunSetupNow.localized();
        let machine = FaceMessage::ConfirmRunSetupNow.machine();
        // Binding keeps this probe msgid out of xgettext extraction.
        let absent_probe = "facelock msgid absent from the fixture catalog";
        let missing = translate(absent_probe);

        // Restore before asserting so a failure cannot leak state.
        unsafe { std::env::remove_var("LANGUAGE") };
        // SAFETY: as above, still holding `_locale`.
        unsafe { setlocale(libc::LC_MESSAGES, original.as_ptr()) };
        bindtextdomain(GETTEXT_DOMAIN.as_ptr(), c"/usr/share/locale".as_ptr());

        assert_eq!(localized, "XX-RUN-SETUP-NOW", "catalog hit must translate");
        assert_eq!(machine, "ConfirmRunSetupNow", "machine rendering must not");
        assert_eq!(
            missing, "facelock msgid absent from the fixture catalog",
            "catalog miss must fall back to the msgid"
        );
    }

    /// Held across every test that calls `setlocale`, so two of them cannot
    /// interleave their save/mutate/restore sequences.
    static LOCALE_MUTATION: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Minimal GNU MO encoder: header entry plus the given pairs.
    /// Entries must be sorted by msgid (binary-search format, no hash table).
    fn build_mo(pairs: &[(&str, &str)]) -> Vec<u8> {
        let mut entries: Vec<(Vec<u8>, Vec<u8>)> = vec![(
            Vec::new(),
            b"Content-Type: text/plain; charset=UTF-8\n".to_vec(),
        )];
        entries.extend(
            pairs
                .iter()
                .map(|(id, s)| (id.as_bytes().to_vec(), s.as_bytes().to_vec())),
        );
        entries.sort_by(|a, b| a.0.cmp(&b.0));

        let n = entries.len() as u32;
        let orig_table = 28u32;
        let trans_table = orig_table + 8 * n;
        let mut data_off = trans_table + 8 * n;

        // msgids first, then msgstrs, in table order.
        let texts: Vec<&[u8]> = entries
            .iter()
            .map(|(id, _)| id.as_slice())
            .chain(entries.iter().map(|(_, s)| s.as_slice()))
            .collect();
        let mut tables = Vec::new();
        let mut data = Vec::new();
        for text in texts {
            tables.extend((text.len() as u32).to_le_bytes());
            tables.extend(data_off.to_le_bytes());
            data.extend(text);
            data.push(0);
            data_off += text.len() as u32 + 1;
        }

        let mut mo = Vec::new();
        mo.extend(0x950412deu32.to_le_bytes()); // magic
        mo.extend(0u32.to_le_bytes()); // revision
        mo.extend(n.to_le_bytes());
        mo.extend(orig_table.to_le_bytes());
        mo.extend(trans_table.to_le_bytes());
        mo.extend(0u32.to_le_bytes()); // hash size
        mo.extend(0u32.to_le_bytes()); // hash offset
        mo.extend(tables);
        mo.extend(data);
        mo
    }
}
