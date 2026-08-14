//! The `/var/lib/facelock` on-disk layout.
//!
//! ```text
//! /var/lib/facelock/            0710 root:facelock   traverse-only, not listable
//!   facelock.db                 0600 root:root
//!   facelock.db-wal / -shm      0600 root:root
//!   models/                     0755 root:root       public, SHA-256 verified
//!   enrolled/                   0710 root:facelock   is-enrolled markers only
//!     <user>                    0600 <user>:<user>
//! ```
//!
//! Three properties are load-bearing:
//!
//! 1. **"other" is denied at the top.** The state directory has no permission
//!    bits for "other" at all, so a local user outside the `facelock` group can
//!    reach nothing below it — not the database, not the markers, not even the
//!    world-readable models. The group is a D-Bus/enrollment-marker access
//!    grant, and membership in it is what makes anything here reachable.
//! 2. **The group gets traversal, never listing or reads.** `0710` lets a
//!    group member open a path it already knows by name — its own
//!    `enrolled/<user>` marker, a model file — but not enumerate the directory.
//!    The database itself is `0600 root:root`: group members request
//!    authentication through the daemon, they do not read templates.
//! 3. **Applying the layout is idempotent and never touches data.** It is a
//!    handful of `mkdir`/`chmod`/`chown` calls; the database and models never
//!    move, and nothing here creates, copies, or deletes a database. There is
//!    deliberately no migration machinery to get wrong.
//!
//! The guard tests at the bottom pin all three.

use std::fs;
use std::io;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};

use facelock_core::Config;
use facelock_core::fs_security::ensure_private_dir;

// ---------------------------------------------------------------------------
// Names and modes
// ---------------------------------------------------------------------------

/// Per-user `is-enrolled` markers.
pub const ENROLLED_DIR_NAME: &str = "enrolled";

/// ONNX model files, directly in the state directory.
pub const MODELS_DIR_NAME: &str = "models";

/// `root:facelock`, traverse-only: a group member can open `enrolled/<user>`
/// or a model file by name, but cannot list the directory, and "other" cannot
/// reach anything below it at all.
pub const STATE_DIR_MODE: u32 = 0o710;

/// `root:root`. The models are public downloads, SHA-256 verified at load —
/// there is no reason to restrict them; the `0710` state directory above
/// already keeps non-group users out.
pub const MODELS_DIR_MODE: u32 = 0o755;

/// The **mode and the ownership are one contract**: `0710` *and*
/// `root:facelock`. A group member must be able to traverse to their own
/// `0600` marker by name (that traversal is what `facelock is-enrolled`
/// means by "operational for me"), which requires the group-execute bit to be
/// backed by the `facelock` group actually owning the directory. "Fixing" the
/// ownership to `root:root` for consistency with the database silently turns
/// every `is-enrolled` into "not enrolled". The
/// `enrolled_dir_contract_is_mode_and_ownership` guard test pins both halves.
pub const ENROLLED_DIR_MODE: u32 = 0o710;

/// The database and its `-wal`/`-shm` sidecars: `root:root`, no group access.
/// Encrypted biometric templates are read by the daemon (root) only.
pub const DB_FILE_MODE: u32 = 0o600;

const SIDECAR_SUFFIXES: [&str; 2] = ["-wal", "-shm"];

// ---------------------------------------------------------------------------
// Deriving the layout from a config
// ---------------------------------------------------------------------------

/// The state directory implied by a database path: its parent directory.
pub fn state_dir_for_db(db_path: &Path) -> Option<&Path> {
    db_path.parent().filter(|p| !p.as_os_str().is_empty())
}

/// Every path the layout manages, derived from one `storage.db_path`.
///
/// Derived rather than hardcoded so an alternate install root — or a test
/// pointing an entire installation at a tempdir — stays internally consistent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateLayout {
    pub state_dir: PathBuf,
    /// The configured `daemon.model_dir` when derived from a [`Config`],
    /// otherwise the built-in `<state_dir>/models`.
    pub models_dir: PathBuf,
    pub enrolled_dir: PathBuf,
    /// The configured `storage.db_path`.
    pub db_path: PathBuf,
}

impl StateLayout {
    /// Derive the layout from a database path, or `None` when the path has no
    /// usable parent (a bare filename, say).
    pub fn from_db_path(db_path: &Path) -> Option<Self> {
        let state_dir = state_dir_for_db(db_path)?.to_path_buf();
        Some(Self {
            models_dir: state_dir.join(MODELS_DIR_NAME),
            enrolled_dir: state_dir.join(ENROLLED_DIR_NAME),
            db_path: db_path.to_path_buf(),
            state_dir,
        })
    }

    pub fn from_config(config: &Config) -> Option<Self> {
        let mut layout = Self::from_db_path(Path::new(&config.storage.db_path))?;
        layout.models_dir = PathBuf::from(&config.daemon.model_dir);
        Some(layout)
    }

    /// The directories this layout manages, with their modes and owners.
    ///
    /// A `model_dir` pinned outside the state directory is excluded: the guard
    /// property is "everything under the state directory carries these modes",
    /// and a path like `/opt/facelock-models` belongs to whoever pinned it.
    fn dir_specs(&self) -> Vec<DirSpec<'_>> {
        let mut specs = vec![DirSpec {
            path: &self.state_dir,
            mode: STATE_DIR_MODE,
            owner: Ownership::RootGroup,
        }];
        if self.models_dir.starts_with(&self.state_dir) {
            specs.push(DirSpec {
                path: &self.models_dir,
                mode: MODELS_DIR_MODE,
                owner: Ownership::Root,
            });
        }
        specs.push(DirSpec {
            path: &self.enrolled_dir,
            mode: ENROLLED_DIR_MODE,
            owner: Ownership::RootGroup,
        });
        specs
    }

    /// The database file and its WAL sidecars — tightened when present, never
    /// created.
    fn db_files(&self) -> Vec<PathBuf> {
        let mut files = vec![self.db_path.clone()];
        for suffix in SIDECAR_SUFFIXES {
            let mut name = self.db_path.as_os_str().to_os_string();
            name.push(suffix);
            files.push(PathBuf::from(name));
        }
        files
    }
}

/// Who a managed path belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ownership {
    /// `root:root`.
    Root,
    /// `root:facelock`.
    RootGroup,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirSpec<'a> {
    path: &'a Path,
    mode: u32,
    owner: Ownership,
}

// ---------------------------------------------------------------------------
// Ownership
// ---------------------------------------------------------------------------

/// The resolved `facelock` group.
///
/// Kept as a separate, optional step so every mode assertion in the tests can
/// run unprivileged: `chown` to another account requires root, `chmod` on your
/// own files does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Owners {
    pub facelock_gid: u32,
}

impl Owners {
    /// Resolve the `facelock` group, or `None` when it does not exist yet or we
    /// are not root.
    ///
    /// A soft failure on purpose: `facelock setup` calls into the layout before
    /// it has created the group, and applying the modes without the ownership
    /// is strictly better than applying neither. `secure_setup_paths` re-runs
    /// the layout once the group exists.
    pub fn resolve() -> Option<Self> {
        if !nix::unistd::Uid::current().is_root() {
            return None;
        }
        nix::unistd::Group::from_name("facelock")
            .ok()
            .flatten()
            .map(|g| Self {
                facelock_gid: g.gid.as_raw(),
            })
    }

    fn gid_for(&self, owner: Ownership) -> u32 {
        match owner {
            Ownership::Root => 0,
            Ownership::RootGroup => self.facelock_gid,
        }
    }
}

/// `chown(2)` to `root:gid`.
fn chown_root_group(path: &Path, gid: u32) -> anyhow::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .with_context(|| format!("path contains embedded NUL: {}", path.display()))?;
    if unsafe { libc::chown(c_path.as_ptr(), 0, gid) } != 0 {
        bail!(
            "failed to chown {} to root:{gid}: {}",
            path.display(),
            io::Error::last_os_error()
        );
    }
    Ok(())
}

/// Create-or-tighten one directory, then optionally set its owner.
///
/// Already-correct directories are left entirely alone rather than re-`chmod`ed
/// and re-`chown`ed: this can run on the PAM path on every authentication, so
/// the steady state must cost one `stat` per path and no writes.
fn apply_dir(path: &Path, mode: u32, owner_gid: Option<u32>) -> anyhow::Result<()> {
    let current = fs::metadata(path).ok().filter(|m| m.is_dir());
    let mode_ok = current
        .as_ref()
        .is_some_and(|m| m.permissions().mode() & 0o7777 == mode);
    let owner_ok = match (owner_gid, current.as_ref()) {
        (Some(gid), Some(m)) => m.uid() == 0 && m.gid() == gid,
        (None, _) => true,
        (Some(_), None) => false,
    };

    if !mode_ok {
        ensure_private_dir(path, mode)
            .with_context(|| format!("failed to create or secure {}", path.display()))?;
    }
    if !owner_ok && let Some(gid) = owner_gid {
        chown_root_group(path, gid)?;
    }
    Ok(())
}

/// Tighten one file if it exists. Never creates it.
fn apply_file(path: &Path, mode: u32, owner_gid: Option<u32>) -> anyhow::Result<()> {
    let Ok(meta) = fs::metadata(path) else {
        return Ok(());
    };
    if !meta.is_file() {
        return Ok(());
    }
    if meta.permissions().mode() & 0o7777 != mode {
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .with_context(|| format!("failed to chmod {}", path.display()))?;
    }
    if let Some(gid) = owner_gid
        && (meta.uid() != 0 || meta.gid() != gid)
    {
        chown_root_group(path, gid)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Application
// ---------------------------------------------------------------------------

/// Bring the state directory to the layout in the module docs.
///
/// Idempotent, and touches no data: directories are created or re-`chmod`ed,
/// the database is re-`chmod`ed **only if it already exists**, and nothing is
/// ever moved, copied, or deleted. Pass `owners` as `None` to apply modes
/// without ownership — what unprivileged tests do, and what `setup` does
/// before it has created the `facelock` group.
pub fn apply_layout(layout: &StateLayout, owners: Option<Owners>) -> anyhow::Result<()> {
    for spec in layout.dir_specs() {
        apply_dir(spec.path, spec.mode, owners.map(|o| o.gid_for(spec.owner)))?;
    }
    for file in layout.db_files() {
        apply_file(
            &file,
            DB_FILE_MODE,
            owners.map(|o| o.gid_for(Ownership::Root)),
        )?;
    }
    Ok(())
}

/// [`apply_layout`] derived from a config. A config whose `db_path` has no
/// usable parent has no layout to apply and is a no-op.
pub fn ensure_state_layout(config: &Config) -> anyhow::Result<()> {
    match StateLayout::from_config(config) {
        Some(layout) => apply_layout(&layout, Owners::resolve()),
        None => Ok(()),
    }
}

/// Best-effort [`ensure_state_layout`]: applied on the authentication path and
/// in front of every direct-mode store open.
///
/// A failure here must never block the caller: the layout only sets modes,
/// which cannot change what is about to be read. It runs on these paths at all
/// so an install upgraded without re-running `setup` still converges on the
/// documented modes the first time a root invocation comes through.
pub fn ensure_state_layout_best_effort(config: &Config) {
    if let Err(e) = ensure_state_layout(config) {
        tracing::warn!(error = %format!("{e:#}"), "could not fully apply the state directory layout");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_config() -> Config {
        Config::parse("").expect("empty config should parse to defaults")
    }

    fn layout_at(base: &Path) -> StateLayout {
        let state_dir = base.join("facelock");
        StateLayout {
            models_dir: state_dir.join(MODELS_DIR_NAME),
            enrolled_dir: state_dir.join(ENROLLED_DIR_NAME),
            db_path: state_dir.join("facelock.db"),
            state_dir,
        }
    }

    fn mode(path: &Path) -> u32 {
        fs::metadata(path).unwrap().permissions().mode() & 0o7777
    }

    // -----------------------------------------------------------------------
    // Derivation
    // -----------------------------------------------------------------------

    #[test]
    fn default_config_yields_the_documented_layout() {
        let layout = StateLayout::from_config(&test_config()).unwrap();
        assert_eq!(layout.state_dir, Path::new("/var/lib/facelock"));
        assert_eq!(layout.db_path, Path::new("/var/lib/facelock/facelock.db"));
        assert_eq!(layout.models_dir, Path::new("/var/lib/facelock/models"));
        assert_eq!(layout.enrolled_dir, Path::new("/var/lib/facelock/enrolled"));
    }

    #[test]
    fn a_bare_filename_has_no_layout() {
        assert_eq!(StateLayout::from_db_path(Path::new("facelock.db")), None);
    }

    #[test]
    fn a_pinned_model_dir_outside_the_state_dir_is_not_managed() {
        let mut config = test_config();
        config.daemon.model_dir = "/opt/facelock-models".into();
        let layout = StateLayout::from_config(&config).unwrap();
        assert!(
            !layout
                .dir_specs()
                .iter()
                .any(|s| s.path == Path::new("/opt/facelock-models")),
            "a pinned model_dir belongs to whoever pinned it"
        );
    }

    // -----------------------------------------------------------------------
    // The contract: modes and ownership, pinned as data
    // -----------------------------------------------------------------------

    /// The documented layout, spelled out. A change to any mode or owner here
    /// is a change to `docs/contracts.md` and every packaging fragment — this
    /// test failing is the reminder.
    #[test]
    fn the_layout_contract_is_the_documented_one() {
        let layout = StateLayout::from_config(&test_config()).unwrap();
        let specs = layout.dir_specs();

        let find = |path: &Path| {
            specs
                .iter()
                .find(|s| s.path == path)
                .copied()
                .unwrap_or_else(|| panic!("{} is not managed", path.display()))
        };

        let state = find(Path::new("/var/lib/facelock"));
        assert_eq!(state.mode, 0o710);
        assert_eq!(state.owner, Ownership::RootGroup);

        let models = find(Path::new("/var/lib/facelock/models"));
        assert_eq!(models.mode, 0o755);
        assert_eq!(models.owner, Ownership::Root);

        assert_eq!(DB_FILE_MODE, 0o600, "the database is root-only");
    }

    /// F6 guard: `enrolled/` is `0710` **root:facelock**, both halves. The
    /// group-execute bit only means something because the `facelock` group owns
    /// the directory; a "consistency fix" to `root:root` breaks every
    /// unprivileged `is-enrolled` silently. See [`ENROLLED_DIR_MODE`].
    #[test]
    fn enrolled_dir_contract_is_mode_and_ownership() {
        let layout = StateLayout::from_config(&test_config()).unwrap();
        let enrolled = layout
            .dir_specs()
            .into_iter()
            .find(|s| s.path == Path::new("/var/lib/facelock/enrolled"))
            .expect("enrolled/ must be managed by the layout");

        assert_eq!(enrolled.mode, 0o710, "traverse-only for the group");
        assert_eq!(
            enrolled.owner,
            Ownership::RootGroup,
            "must be root:facelock — root:root would deny group members the \
             traversal that makes is-enrolled work at all"
        );
    }

    // -----------------------------------------------------------------------
    // Application
    // -----------------------------------------------------------------------

    #[test]
    fn final_modes_match_the_documented_layout() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());
        fs::create_dir_all(&layout.state_dir).unwrap();
        fs::write(&layout.db_path, b"stub").unwrap();

        apply_layout(&layout, None).unwrap();

        assert_eq!(mode(&layout.state_dir), STATE_DIR_MODE);
        assert_eq!(mode(&layout.models_dir), MODELS_DIR_MODE);
        assert_eq!(mode(&layout.enrolled_dir), ENROLLED_DIR_MODE);
        assert_eq!(mode(&layout.db_path), DB_FILE_MODE);
    }

    #[test]
    fn applying_the_layout_twice_is_a_no_op() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());

        apply_layout(&layout, None).unwrap();
        apply_layout(&layout, None).unwrap();

        assert_eq!(mode(&layout.state_dir), STATE_DIR_MODE);
        assert_eq!(mode(&layout.enrolled_dir), ENROLLED_DIR_MODE);
    }

    #[test]
    fn a_loosened_database_is_retightened() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());
        fs::create_dir_all(&layout.state_dir).unwrap();
        fs::write(&layout.db_path, b"stub").unwrap();
        fs::set_permissions(&layout.db_path, fs::Permissions::from_mode(0o640)).unwrap();

        apply_layout(&layout, None).unwrap();

        assert_eq!(mode(&layout.db_path), 0o600);
    }

    #[test]
    fn apply_layout_never_creates_a_database() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());

        apply_layout(&layout, None).unwrap();

        assert!(!layout.db_path.exists(), "the layout must not create files");
        // And the sidecars stayed absent too.
        assert_eq!(
            fs::read_dir(&layout.state_dir)
                .unwrap()
                .flatten()
                .filter(|e| e.path().is_file())
                .count(),
            0
        );
    }

    #[test]
    fn ensure_state_layout_best_effort_swallows_failures() {
        // A db_path whose parent is a *file* cannot have the layout applied;
        // the auth-path wrapper must absorb that rather than propagate it.
        let tmp = tempfile::tempdir().unwrap();
        let blocker = tmp.path().join("blocker");
        fs::write(&blocker, b"not a directory").unwrap();

        let mut config = test_config();
        config.storage.db_path = blocker.join("facelock.db").to_string_lossy().into_owned();

        ensure_state_layout_best_effort(&config);
    }

    // -----------------------------------------------------------------------
    // The guard: nothing under the state directory is reachable by "other"
    // -----------------------------------------------------------------------

    /// Walks the applied tree and asserts the property the layout exists for:
    /// the state directory grants "other" **nothing**, so nothing below it —
    /// whatever its own mode — is reachable by a user outside root and the
    /// `facelock` group. `models/` is the one entry allowed to carry "other"
    /// bits of its own (it is public data); everything else must be locked
    /// down in its own right as defense in depth.
    #[test]
    fn nothing_under_the_state_directory_is_reachable_by_other() {
        let tmp = tempfile::tempdir().unwrap();
        let layout = layout_at(tmp.path());
        fs::create_dir_all(&layout.state_dir).unwrap();
        fs::write(&layout.db_path, b"stub").unwrap();

        apply_layout(&layout, None).unwrap();
        // Simulate later runtime artifacts.
        fs::write(layout.state_dir.join("facelock.db-wal"), b"stub").unwrap();
        apply_layout(&layout, None).unwrap();

        assert_eq!(
            mode(&layout.state_dir) & 0o007,
            0,
            "the state directory must deny 'other' entirely; every child \
             depends on this single gate"
        );

        fn walk(dir: &Path, allow_other: &dyn Fn(&Path) -> bool) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                let m = fs::metadata(&path).unwrap().permissions().mode() & 0o007;
                if !allow_other(&path) {
                    assert_eq!(
                        m,
                        0,
                        "{} is accessible by 'other'. The state directory holds \
                         biometric data: new entries must carry no 'other' bits \
                         (models/ is the only exception — it is public data \
                         behind the 0710 parent).",
                        path.display()
                    );
                }
                if path.is_dir() {
                    walk(&path, allow_other);
                }
            }
        }
        let models_dir = layout.models_dir.clone();
        walk(&layout.state_dir, &|p: &Path| p.starts_with(&models_dir));
    }
}
