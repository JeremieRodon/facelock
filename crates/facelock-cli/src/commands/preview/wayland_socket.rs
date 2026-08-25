//! Wayland socket resolution for the root-only preview.
//!
//! The preview always runs as root (DEC-6), and both documented invocations
//! arrive through `sudo`, whose `env_reset` strips `WAYLAND_DISPLAY` and
//! `XDG_RUNTIME_DIR` — so `Connection::connect_to_env()` never reached the
//! compositor and every preview fell back to text-only (issue #297).
//!
//! The fix is deliberately not an environment passthrough. Passing session
//! environment into a root process is the shape this codebase refuses
//! elsewhere (the PAM oneshot spawn pins its child environment down to two
//! SSH variables), and `XDG_RUNTIME_DIR` in particular would let a hostile
//! session point root's socket connect at an arbitrary path. Instead the
//! socket is derived from the invoking user's *identity*: `SUDO_UID` is
//! written by sudo itself, and a logged-in uid's runtime directory is
//! `/run/user/<uid>` (file-hierarchy(7)) regardless of what any inherited
//! variable claims.
//!
//! Environment influence is bounded to one choice: a `WAYLAND_DISPLAY` that
//! is a bare socket name selects among sockets *inside* that directory. A
//! value carrying a path separator is ignored. (The name survives the sudo
//! re-exec via `--preserve-env=WAYLAND_DISPLAY` — see
//! `require_root_preserving` — so a session running several compositors
//! previews on the one that launched the command.)
//!
//! The authority on *what* root then talks to is the connected peer, not the
//! path. `/run/user/<uid>` is writable by the invoking user, so any pathname
//! check races against a swap before `connect(2)` — which follows symlinks.
//! The pre-connect lstat is therefore only a fast, clearer-error filter;
//! after connecting, `SO_PEERCRED` must show a peer process running as the
//! invoking uid or the connection is dropped before a byte of protocol is
//! spoken. The worst a hostile session achieves is steering root's bare
//! `connect()`+close at a path of its choosing, or handing root a Wayland
//! endpoint the user could already run themselves.

use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};

use anyhow::Context;
use wayland_client::Connection;

/// Connect to the invoking user's Wayland compositor.
pub fn connect() -> anyhow::Result<Connection> {
    let env = |key: &str| std::env::var(key).ok();
    let uid = invoking_uid(env, name_to_uid);
    let run_dir = PathBuf::from(format!("/run/user/{uid}"));
    let display = std::env::var("WAYLAND_DISPLAY").ok();

    let mut last_err = None;
    for name in socket_candidates(&run_dir, display.as_deref())? {
        match connect_owned(&run_dir.join(&name), uid) {
            Ok(conn) => return Ok(conn),
            Err(e) => last_err = Some(e),
        }
    }
    // `socket_candidates` never returns an empty list.
    Err(last_err.expect("candidates are non-empty"))
}

/// The uid whose session the preview window belongs on.
///
/// `SUDO_UID` is set by sudo itself across the re-exec (and by a direct
/// `sudo facelock preview`), so it names the real invoking user; `DOAS_USER`
/// keeps parity with `resolve_user`. Without either — a genuine root login —
/// the current uid stands, so a compositor run by root is still found.
fn invoking_uid(
    env: impl Fn(&str) -> Option<String>,
    resolve_name: impl Fn(&str) -> Option<u32>,
) -> u32 {
    if let Some(uid) = env("SUDO_UID").and_then(|v| v.parse::<u32>().ok()) {
        return uid;
    }
    if let Some(uid) = env("DOAS_USER").as_deref().and_then(resolve_name) {
        return uid;
    }
    nix::unistd::Uid::current().as_raw()
}

/// Resolve a user name to a uid via getpwnam.
fn name_to_uid(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    let pw = unsafe { libc::getpwnam(cname.as_ptr()) };
    if pw.is_null() {
        None
    } else {
        Some(unsafe { (*pw).pw_uid })
    }
}

/// Candidate socket names inside the runtime directory.
///
/// A bare-name `WAYLAND_DISPLAY` selects exactly that socket; a value with a
/// path separator is not honoured (root must not follow an
/// environment-supplied path — see module docs) and the directory is scanned
/// instead. Returns at least one name or an error naming the directory.
fn socket_candidates(run_dir: &Path, display: Option<&str>) -> anyhow::Result<Vec<String>> {
    if let Some(name) = display.filter(|d| is_bare_socket_name(d)) {
        return Ok(vec![name.to_string()]);
    }

    let entries = std::fs::read_dir(run_dir)
        .with_context(|| format!("no session runtime directory at {}", run_dir.display()))?;
    let mut names: Vec<String> = entries
        .filter_map(|e| e.ok())
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| is_wayland_socket_name(n))
        .collect();
    names.sort();

    if names.is_empty() {
        anyhow::bail!("no wayland-* socket in {}", run_dir.display());
    }
    Ok(names)
}

/// True for a plain file name with no path traversal potential.
fn is_bare_socket_name(name: &str) -> bool {
    !name.is_empty() && !name.contains('/') && name != "." && name != ".."
}

/// True for the compositor socket naming convention, excluding lock files.
fn is_wayland_socket_name(name: &str) -> bool {
    name.starts_with("wayland-") && !name.ends_with(".lock")
}

/// Connect to `path` and authenticate the connected peer as `uid`.
///
/// The lstat checks are a fast filter with clearer errors, not the security
/// boundary: the runtime dir is writable by the invoking user, so the path
/// can be swapped — including for a symlink, which `connect(2)` follows —
/// between the check and the connect. The boundary is [`verify_peer_uid`]
/// on the connected stream, which no rename can race.
fn connect_owned(path: &Path, uid: u32) -> anyhow::Result<Connection> {
    let meta = std::fs::symlink_metadata(path)
        .with_context(|| format!("no Wayland socket at {}", path.display()))?;
    if !meta.file_type().is_socket() {
        anyhow::bail!("{} is not a socket", path.display());
    }
    if meta.uid() != uid {
        anyhow::bail!(
            "{} is owned by uid {}, not the invoking uid {}",
            path.display(),
            meta.uid(),
            uid
        );
    }
    let stream = UnixStream::connect(path)
        .with_context(|| format!("failed to connect to {}", path.display()))?;
    verify_peer_uid(&stream, uid)
        .with_context(|| format!("refusing Wayland socket {}", path.display()))?;
    Connection::from_socket(stream).context("failed to connect to Wayland display")
}

/// Refuse a connected socket whose peer process does not run as `uid`.
///
/// `SO_PEERCRED` reports the credentials of the process that bound the
/// listening socket, read from the kernel on the already-established
/// connection — the one identity in this module a pathname swap cannot
/// forge. Nothing is written to the stream before this check.
fn verify_peer_uid(stream: &UnixStream, uid: u32) -> anyhow::Result<()> {
    let cred = nix::sys::socket::getsockopt(stream, nix::sys::socket::sockopt::PeerCredentials)
        .context("failed to read peer credentials")?;
    if cred.uid() != uid {
        anyhow::bail!(
            "peer runs as uid {}, not the invoking uid {}",
            cred.uid(),
            uid
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn no_env(_: &str) -> Option<String> {
        None
    }

    #[test]
    fn sudo_uid_wins() {
        let env = |key: &str| match key {
            "SUDO_UID" => Some("1000".to_string()),
            "DOAS_USER" => Some("alice".to_string()),
            _ => None,
        };
        // The resolver must not be consulted when SUDO_UID answers.
        assert_eq!(invoking_uid(env, |_| panic!("resolver called")), 1000);
    }

    #[test]
    fn doas_user_resolves_when_sudo_uid_absent_or_garbage() {
        for sudo_uid in [None, Some("not-a-number".to_string())] {
            let sudo_uid = sudo_uid.clone();
            let env = move |key: &str| match key {
                "SUDO_UID" => sudo_uid.clone(),
                "DOAS_USER" => Some("alice".to_string()),
                _ => None,
            };
            assert_eq!(
                invoking_uid(env, |name| (name == "alice").then_some(1042)),
                1042
            );
        }
    }

    #[test]
    fn falls_back_to_current_uid() {
        assert_eq!(
            invoking_uid(no_env, |_| None),
            nix::unistd::Uid::current().as_raw()
        );
    }

    #[test]
    fn bare_display_name_is_the_single_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let names = socket_candidates(dir.path(), Some("wayland-1")).unwrap();
        assert_eq!(names, vec!["wayland-1"]);
    }

    /// The bound issue #297's fix promises: an environment-supplied path is
    /// never followed. A `WAYLAND_DISPLAY` carrying a separator falls back
    /// to scanning the identity-derived directory.
    #[test]
    fn path_bearing_display_is_ignored() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("wayland-1"), b"").unwrap();
        for hostile in ["/tmp/evil/wayland-0", "../../../tmp/evil", "a/b"] {
            let names = socket_candidates(dir.path(), Some(hostile)).unwrap();
            assert_eq!(names, vec!["wayland-1"], "for {hostile}");
        }
    }

    #[test]
    fn scan_skips_lock_files_and_foreign_names_and_sorts() {
        let dir = tempfile::tempdir().unwrap();
        for name in [
            "wayland-2",
            "wayland-1",
            "wayland-1.lock",
            "pipewire-0",
            "bus",
        ] {
            std::fs::write(dir.path().join(name), b"").unwrap();
        }
        let names = socket_candidates(dir.path(), None).unwrap();
        assert_eq!(names, vec!["wayland-1", "wayland-2"]);
    }

    #[test]
    fn empty_scan_is_an_error_naming_the_directory() {
        let dir = tempfile::tempdir().unwrap();
        let err = socket_candidates(dir.path(), None).unwrap_err();
        assert!(format!("{err:#}").contains(&dir.path().display().to_string()));
    }

    #[test]
    fn missing_runtime_dir_is_an_error() {
        let err = socket_candidates(Path::new("/run/user/999999"), None).unwrap_err();
        assert!(format!("{err:#}").contains("no session runtime directory"));
    }

    #[test]
    fn connect_refuses_a_non_socket() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wayland-1");
        std::fs::write(&path, b"").unwrap();
        let err = connect_owned(&path, nix::unistd::Uid::current().as_raw()).unwrap_err();
        assert!(format!("{err:#}").contains("not a socket"));
    }

    #[test]
    fn connect_refuses_a_wrong_owner() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wayland-1");
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        let not_us = nix::unistd::Uid::current().as_raw() + 1;
        let err = connect_owned(&path, not_us).unwrap_err();
        assert!(format!("{err:#}").contains("not the invoking uid"));
        drop(listener);
    }

    #[test]
    fn connect_accepts_a_listener_running_as_the_invoking_uid() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("wayland-1");
        let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        connect_owned(&path, nix::unistd::Uid::current().as_raw()).unwrap();
    }

    #[test]
    fn peer_running_as_the_invoking_uid_is_accepted() {
        let (a, _b) = UnixStream::pair().unwrap();
        verify_peer_uid(&a, nix::unistd::Uid::current().as_raw()).unwrap();
    }

    /// The race the lstat checks cannot close: the runtime dir is writable
    /// by the invoking user, so the path can be swapped between the check
    /// and `connect(2)`, which follows symlinks. This check runs on the
    /// established connection itself, where no rename can reach — a peer
    /// not running as the invoking uid is refused whatever the path said.
    #[test]
    fn peer_running_as_another_uid_is_refused() {
        let (a, _b) = UnixStream::pair().unwrap();
        let not_us = nix::unistd::Uid::current().as_raw() + 1;
        let err = verify_peer_uid(&a, not_us).unwrap_err();
        assert!(format!("{err:#}").contains("not the invoking uid"));
    }
}
