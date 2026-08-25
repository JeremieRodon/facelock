// The oneshot exit-code -> PAM mapping. Dependency-free on purpose: this
// file is compiled twice — as `pam_facelock`'s `oneshot_exit` module, and
// `include!`d into `facelock-cli`'s test suite (commands/auth.rs), which
// pins every rejection class's exit code to the PAM code this table gives
// it. `pam_facelock.so` cannot link the daemon crates (its dependency
// ceiling is libc/toml/serde/zbus), so sharing the source is what couples
// the two halves of the contract; nothing here may `use` anything.
//
// The contract is docs/contracts.md ("facelock auth Exit Codes"), with
// three frozen invariants: exit 0, 1 and 2 keep their meanings permanently;
// new codes are allocated only from the space this table's fallback arm
// maps to PAM_IGNORE; and that fallback arm stays PAM_IGNORE forever. A
// binary newer or older than this module therefore degrades to the
// collapsed pre-#141 behavior, never to a wrong answer.

/// Linux-PAM return codes, fixed by the PAM ABI. `i32` rather than
/// `libc::c_int` so this file stays dependency-free; the two are the same
/// type on every Linux target (`lib.rs` aliases its constants to these, so
/// a target where they diverged would fail to compile).
pub(crate) const PAM_SUCCESS: i32 = 0;
pub(crate) const PAM_AUTH_ERR: i32 = 7;
pub(crate) const PAM_AUTHINFO_UNAVAIL: i32 = 9;
pub(crate) const PAM_IGNORE: i32 = 25;

/// The module's reading of one `facelock auth` exit code.
pub(crate) struct OneshotExit {
    /// The PAM return code. This column is frozen protocol.
    pub(crate) pam_code: i32,
    /// Syslog label for a known code; `None` for a code this build does not
    /// know (the caller formats a line naming the raw code).
    pub(crate) label: Option<&'static str>,
    /// Whether the syslog line is a warning rather than info.
    pub(crate) warn: bool,
}

/// Map a `facelock auth` exit code onto its PAM consequence.
///
/// Class for class this matches the daemon transport: a rate-limited
/// rejection fails (the consequence the daemon's frozen "rate limited"
/// message gets), a suppressed attempt reports missing authentication data
/// (the daemon's `-3` sentinel consequence), a dark scan abstains, and an
/// unknown code — a newer binary's future class, or a signal death read as
/// 2 by the caller — abstains too. Never `PAM_SUCCESS` except for exit 0.
pub(crate) fn classify(code: i32) -> OneshotExit {
    match code {
        0 => OneshotExit {
            pam_code: PAM_SUCCESS,
            label: Some("success (oneshot)"),
            warn: false,
        },
        1 => OneshotExit {
            pam_code: PAM_AUTH_ERR,
            label: Some("no_match (oneshot)"),
            warn: false,
        },
        // Deliberate failure, not fall-through: the user's face-auth budget
        // is exhausted; the password modules still run after us. Before
        // #141 this class collapsed to exit 2, so daemon unavailability
        // silently softened it to PAM_IGNORE.
        3 => OneshotExit {
            pam_code: PAM_AUTH_ERR,
            label: Some("rate_limited (oneshot)"),
            warn: true,
        },
        // No enrolled models with `suppress_unknown`.
        4 => OneshotExit {
            pam_code: PAM_AUTHINFO_UNAVAIL,
            label: Some("suppressed (oneshot, no enrolled models)"),
            warn: false,
        },
        // The camera produced no usable image: no opinion about this face.
        5 => OneshotExit {
            pam_code: PAM_IGNORE,
            label: Some("all_frames_dark (oneshot)"),
            warn: true,
        },
        // 2 (error / no opinion) and every code this build does not know:
        // abstain. Frozen — this arm is what makes a binary newer than the
        // module safe.
        _ => OneshotExit {
            pam_code: PAM_IGNORE,
            label: None,
            warn: true,
        },
    }
}
