use std::path::{Path, PathBuf};

/// Result alias for this crate's own API.
///
/// `facelock-store` deliberately does not use `facelock_core::error::Result`
/// for its public surface: the store owns the truth about *why* it failed, and
/// keeping the error type local means new failure classes never require
/// editing a crate everything depends on. Callers that still funnel into
/// `FacelockError` get the `From` impl below.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Why the store could not answer.
///
/// The variants are the failure classes callers actually branch on — a guard
/// asking "may I destroy data?" treats [`StoreError::Absent`] (nothing to
/// lose) very differently from [`StoreError::Denied`] (cannot tell), and
/// collapsing them into one string is what historically made destructive
/// paths fail open. Every variant carries the database path and enough detail
/// to render a precise message on its own.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// No database file exists at the path. A fresh install, not a fault:
    /// "absent" is a state a caller may legitimately proceed on. Never
    /// returned by [`crate::FaceStore::create`].
    #[error("no database at {path}")]
    Absent { path: PathBuf },

    /// The path or file exists but cannot be accessed: permissions, a
    /// read-only filesystem, an unstatable parent directory. Unlike
    /// [`StoreError::Absent`], nothing can be concluded about what the
    /// database contains.
    #[error("cannot access database {path}: {detail}")]
    Denied { path: PathBuf, detail: String },

    /// Locked by another connection. Transient; retrying can succeed.
    #[error("database {path} is locked by another process: {detail}")]
    Busy { path: PathBuf, detail: String },

    /// Present but not usable as a database: not SQLite at all, or its
    /// internal structure is broken.
    #[error("database {path} is corrupt or not a database: {detail}")]
    Corrupt { path: PathBuf, detail: String },

    /// The schema could not be brought forward to the current version.
    #[error("database {path} schema migration failed: {detail}")]
    Migration { path: PathBuf, detail: String },

    /// Any other failed operation on an open database — the residual class
    /// for failures no caller policy distinguishes.
    #[error("database {path}: {detail}")]
    Query { path: PathBuf, detail: String },
}

impl StoreError {
    /// Classify a rusqlite failure by its SQLite result code.
    ///
    /// The codes rusqlite surfaces already distinguish exactly what callers
    /// need: `SQLITE_NOTADB`/`CORRUPT` ⇒ corrupt, `SQLITE_BUSY`/`LOCKED` ⇒
    /// locked, `SQLITE_CANTOPEN`/`PERM`/`READONLY` ⇒ inaccessible. `CANTOPEN`
    /// maps to `Denied` rather than `Absent` on purpose: by the time SQLite
    /// reports it the file's existence was already checked, so a `CANTOPEN`
    /// (including the stat-then-open race) reads as "cannot tell", the
    /// fail-closed direction for guards.
    pub(crate) fn classify(path: &Path, e: rusqlite::Error) -> Self {
        use rusqlite::ErrorCode;

        let code = match &e {
            rusqlite::Error::SqliteFailure(err, _) => Some(err.code),
            _ => None,
        };
        let path = path.to_path_buf();
        let detail = e.to_string();
        match code {
            Some(ErrorCode::NotADatabase) | Some(ErrorCode::DatabaseCorrupt) => {
                Self::Corrupt { path, detail }
            }
            Some(ErrorCode::DatabaseBusy) | Some(ErrorCode::DatabaseLocked) => {
                Self::Busy { path, detail }
            }
            Some(ErrorCode::CannotOpen)
            | Some(ErrorCode::PermissionDenied)
            | Some(ErrorCode::ReadOnly) => Self::Denied { path, detail },
            _ => Self::Query { path, detail },
        }
    }
}

/// Compatibility path into the core error type. Preserves the full rendered
/// message, so callers that only display the error lose nothing — but the
/// class is erased, so code that needs to *branch* on failure class must take
/// `StoreError` before this conversion happens.
impl From<StoreError> for facelock_core::error::FacelockError {
    fn from(e: StoreError) -> Self {
        facelock_core::error::FacelockError::Storage(e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sqlite_error(code: std::os::raw::c_int) -> rusqlite::Error {
        rusqlite::Error::SqliteFailure(rusqlite::ffi::Error::new(code), Some("detail".into()))
    }

    #[test]
    fn classify_maps_sqlite_codes_to_failure_classes() {
        let path = Path::new("/var/lib/facelock/facelock.db");
        let cases: &[(std::os::raw::c_int, fn(&StoreError) -> bool)] = &[
            (rusqlite::ffi::SQLITE_NOTADB, |e| {
                matches!(e, StoreError::Corrupt { .. })
            }),
            (rusqlite::ffi::SQLITE_CORRUPT, |e| {
                matches!(e, StoreError::Corrupt { .. })
            }),
            (rusqlite::ffi::SQLITE_BUSY, |e| {
                matches!(e, StoreError::Busy { .. })
            }),
            (rusqlite::ffi::SQLITE_LOCKED, |e| {
                matches!(e, StoreError::Busy { .. })
            }),
            (rusqlite::ffi::SQLITE_CANTOPEN, |e| {
                matches!(e, StoreError::Denied { .. })
            }),
            (rusqlite::ffi::SQLITE_PERM, |e| {
                matches!(e, StoreError::Denied { .. })
            }),
            (rusqlite::ffi::SQLITE_READONLY, |e| {
                matches!(e, StoreError::Denied { .. })
            }),
            (rusqlite::ffi::SQLITE_CONSTRAINT, |e| {
                matches!(e, StoreError::Query { .. })
            }),
            (rusqlite::ffi::SQLITE_IOERR, |e| {
                matches!(e, StoreError::Query { .. })
            }),
        ];
        for (code, is_expected) in cases {
            let classified = StoreError::classify(path, sqlite_error(*code));
            assert!(
                is_expected(&classified),
                "SQLite code {code} classified as {classified:?}"
            );
        }
    }

    /// Extended codes (e.g. `SQLITE_READONLY_CANTINIT`, `SQLITE_CANTOPEN_*`)
    /// carry their primary code in rusqlite's `ErrorCode`, so the mapping
    /// above covers them without enumerating each one.
    #[test]
    fn classify_handles_extended_codes_via_primary() {
        let path = Path::new("/tmp/x.db");
        let e = StoreError::classify(path, sqlite_error(rusqlite::ffi::SQLITE_CANTOPEN_ISDIR));
        assert!(matches!(e, StoreError::Denied { .. }), "got {e:?}");
    }

    #[test]
    fn classify_preserves_path_and_detail_in_message() {
        let path = Path::new("/var/lib/facelock/facelock.db");
        let e = StoreError::classify(path, sqlite_error(rusqlite::ffi::SQLITE_BUSY));
        let msg = e.to_string();
        assert!(msg.contains("/var/lib/facelock/facelock.db"), "{msg}");
        assert!(msg.contains("detail"), "{msg}");
    }

    /// The compatibility conversion may erase the class, never the message.
    #[test]
    fn from_store_error_preserves_full_message() {
        let e = StoreError::Denied {
            path: PathBuf::from("/var/lib/facelock/facelock.db"),
            detail: "permission denied".into(),
        };
        let rendered = e.to_string();
        let core: facelock_core::error::FacelockError = e.into();
        assert!(core.to_string().contains(&rendered), "{core}");
    }
}
