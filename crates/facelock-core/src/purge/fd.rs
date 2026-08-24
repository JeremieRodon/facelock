//! Descriptor-anchored filesystem primitives for the purge engine.
//!
//! Everything here is directory-relative and refuses to follow symbolic
//! links. The Perl reference operates through `/proc/self/fd/<fd>` path
//! strings because Perl has no `openat`; native `*at` syscalls on the pinned
//! descriptors satisfy the same contract requirement (never re-resolve a
//! public pathname for deletion) without the `/proc` indirection.

use std::ffi::{CStr, CString};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};

/// The identity fields the envelope compares. Field-for-field this matches
/// the Perl reference's `stat` slices: dev, ino, mode, nlink, uid, gid, size.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Stat {
    pub dev: u64,
    pub ino: u64,
    pub mode: u32,
    pub nlink: u64,
    pub uid: u32,
    pub gid: u32,
    pub size: i64,
}

impl Stat {
    // libc::stat field widths vary by target; the casts are identity on
    // x86_64 but required elsewhere.
    #[allow(clippy::unnecessary_cast)]
    fn from_raw(st: &libc::stat) -> Self {
        Stat {
            dev: st.st_dev as u64,
            ino: st.st_ino as u64,
            mode: st.st_mode as u32,
            nlink: st.st_nlink as u64,
            uid: st.st_uid as u32,
            gid: st.st_gid as u32,
            size: st.st_size as i64,
        }
    }

    pub fn is_dir(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFDIR
    }

    pub fn is_regular(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFREG
    }

    pub fn is_symlink(&self) -> bool {
        self.mode & libc::S_IFMT == libc::S_IFLNK
    }

    /// Full identity: dev, ino, mode, nlink, uid, gid. Used for regular
    /// files, where a changed link count is itself a refusal.
    pub fn same_identity(&self, other: &Stat) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mode == other.mode
            && self.nlink == other.nlink
            && self.uid == other.uid
            && self.gid == other.gid
    }

    /// Directory identity skips nlink: removing a subdirectory legitimately
    /// changes the parent's link count mid-traversal.
    pub fn same_directory_identity(&self, other: &Stat) -> bool {
        self.dev == other.dev
            && self.ino == other.ino
            && self.mode == other.mode
            && self.uid == other.uid
            && self.gid == other.gid
    }
}

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Open an absolute directory path as the fixed traversal anchor.
pub(crate) fn open_dir(path: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: `path` is a valid NUL-terminated string; the returned fd is
    // owned by the OwnedFd.
    let fd = cvt(unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: fd is a freshly opened, valid descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open one directory component relative to its pinned parent, refusing
/// symbolic links.
pub(crate) fn open_dir_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: as `open_dir`, relative to a live parent descriptor.
    let fd = cvt(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: fd is a freshly opened, valid descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// Open a regular-file candidate relative to its pinned parent. `O_NOFOLLOW`
/// refuses a symlink swapped in after inspection; `O_NONBLOCK` keeps an
/// object swapped to a FIFO from blocking the open (the identity re-proof
/// then rejects it).
pub(crate) fn open_file_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<OwnedFd> {
    // SAFETY: as `open_dir_at`.
    let fd = cvt(unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC,
        )
    })?;
    // SAFETY: fd is a freshly opened, valid descriptor.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

/// `lstat` of an absolute path (only used for the fixed anchor).
pub(crate) fn lstat_path(path: &CStr) -> io::Result<Stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid path pointer and stat buffer.
    cvt(unsafe { libc::lstat(path.as_ptr(), st.as_mut_ptr()) })?;
    // SAFETY: the syscall succeeded, so the buffer is initialized.
    let st = unsafe { st.assume_init() };
    Ok(Stat::from_raw(&st))
}

/// `lstat` of a name relative to a pinned parent descriptor.
pub(crate) fn lstat_at(parent: BorrowedFd<'_>, name: &CStr) -> io::Result<Stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid parent fd, name pointer, and stat buffer.
    cvt(unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    })?;
    // SAFETY: the syscall succeeded, so the buffer is initialized.
    let st = unsafe { st.assume_init() };
    Ok(Stat::from_raw(&st))
}

/// `fstat` of an already opened descriptor.
pub(crate) fn fstat(fd: BorrowedFd<'_>) -> io::Result<Stat> {
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: valid fd and stat buffer.
    cvt(unsafe { libc::fstat(fd.as_raw_fd(), st.as_mut_ptr()) })?;
    // SAFETY: the syscall succeeded, so the buffer is initialized.
    let st = unsafe { st.assume_init() };
    Ok(Stat::from_raw(&st))
}

/// Atomic no-replace rename within one pinned parent directory.
///
/// Uses the raw `renameat2` syscall so an old libc cannot silently substitute
/// a check-then-rename fallback. Unlike the Perl reference, which hardcodes
/// the x86_64 syscall number and fails closed on every other architecture,
/// `libc::SYS_renameat2` is arch-correct, so no architecture restriction is
/// needed; a kernel without the syscall still fails closed with `ENOSYS`.
pub(crate) fn rename_noreplace(parent: BorrowedFd<'_>, from: &CStr, to: &CStr) -> io::Result<()> {
    // SAFETY: valid parent fd and NUL-terminated name pointers.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            parent.as_raw_fd(),
            from.as_ptr(),
            parent.as_raw_fd(),
            to.as_ptr(),
            libc::RENAME_NOREPLACE as libc::c_uint,
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `unlinkat` relative to the pinned parent; `remove_dir` selects `rmdir`
/// semantics.
pub(crate) fn unlink_at(parent: BorrowedFd<'_>, name: &CStr, remove_dir: bool) -> io::Result<()> {
    let flags = if remove_dir { libc::AT_REMOVEDIR } else { 0 };
    // SAFETY: valid parent fd and name pointer.
    cvt(unsafe { libc::unlinkat(parent.as_raw_fd(), name.as_ptr(), flags) })?;
    Ok(())
}

/// The mount ID of an opened descriptor, from `/proc/self/fdinfo`. `None`
/// means the identity cannot be proven, which callers treat as a refusal.
pub(crate) fn mount_id(fd: BorrowedFd<'_>) -> Option<u64> {
    let text = std::fs::read_to_string(format!("/proc/self/fdinfo/{}", fd.as_raw_fd())).ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("mnt_id:") {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// An open directory enumeration stream over a duplicated descriptor.
///
/// The pinned directory fd itself stays available for identity re-proof;
/// enumeration runs on a `F_DUPFD_CLOEXEC` duplicate owned by `fdopendir`.
pub(crate) struct DirStream {
    dir: *mut libc::DIR,
}

impl DirStream {
    pub fn open(fd: BorrowedFd<'_>) -> io::Result<DirStream> {
        // SAFETY: valid fd; the duplicate is handed to fdopendir below.
        let dup = cvt(unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) })?;
        // SAFETY: dup is a valid directory descriptor; on success fdopendir
        // owns it, on failure we close it ourselves.
        let dir = unsafe { libc::fdopendir(dup) };
        if dir.is_null() {
            let err = io::Error::last_os_error();
            // SAFETY: dup is still owned by us when fdopendir failed.
            unsafe { libc::close(dup) };
            return Err(err);
        }
        Ok(DirStream { dir })
    }

    /// Next raw entry name, including `.` and `..`. `Ok(None)` is end of
    /// directory; `Err` is a read failure, which the engine treats as
    /// abandoning the whole root.
    pub fn next_entry(&mut self) -> io::Result<Option<CString>> {
        loop {
            // SAFETY: self.dir is a live DIR stream. errno must be cleared
            // first to distinguish end-of-stream from failure.
            let entry = unsafe {
                *libc::__errno_location() = 0;
                libc::readdir(self.dir)
            };
            if entry.is_null() {
                let err = io::Error::last_os_error();
                return match err.raw_os_error() {
                    Some(0) => Ok(None),
                    _ => Err(err),
                };
            }
            // SAFETY: entry points at a valid dirent until the next readdir;
            // d_name is NUL-terminated by the kernel. Copy it out immediately.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_owned();
            let bytes = name.as_bytes();
            if bytes == b"." || bytes == b".." {
                continue;
            }
            return Ok(Some(name));
        }
    }

    pub fn rewind(&mut self) {
        // SAFETY: self.dir is a live DIR stream.
        unsafe { libc::rewinddir(self.dir) };
    }

    /// Close the stream, surfacing a close failure (the reference reports
    /// "cannot finish reading directory" and refuses the directory).
    pub fn finish(mut self) -> io::Result<()> {
        let dir = std::mem::replace(&mut self.dir, std::ptr::null_mut());
        // SAFETY: dir was a live DIR stream and is closed exactly once; the
        // null swap keeps Drop from double-closing.
        if unsafe { libc::closedir(dir) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

impl Drop for DirStream {
    fn drop(&mut self) {
        if !self.dir.is_null() {
            // SAFETY: self.dir is a live DIR stream, closed exactly once.
            unsafe { libc::closedir(self.dir) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsFd;

    fn c(s: &str) -> CString {
        CString::new(s).expect("no interior NUL")
    }

    #[test]
    fn stat_identity_compares_all_envelope_fields() {
        let base = Stat {
            dev: 1,
            ino: 2,
            mode: libc::S_IFREG | 0o600,
            nlink: 1,
            uid: 3,
            gid: 4,
            size: 5,
        };
        assert!(base.same_identity(&base));
        for field in 0..6 {
            let mut other = base;
            match field {
                0 => other.dev += 1,
                1 => other.ino += 1,
                2 => other.mode |= 0o020,
                3 => other.nlink += 1,
                4 => other.uid += 1,
                _ => other.gid += 1,
            }
            assert!(!base.same_identity(&other), "field {field} must differ");
        }
        // Size is deliberately not part of identity, matching the reference.
        let mut grown = base;
        grown.size += 1;
        assert!(base.same_identity(&grown));
    }

    #[test]
    fn directory_identity_ignores_nlink() {
        let base = Stat {
            dev: 1,
            ino: 2,
            mode: libc::S_IFDIR | 0o755,
            nlink: 3,
            uid: 0,
            gid: 0,
            size: 0,
        };
        let mut fewer_links = base;
        fewer_links.nlink = 2;
        assert!(base.same_directory_identity(&fewer_links));
        let mut chmodded = base;
        chmodded.mode |= 0o020;
        assert!(!base.same_directory_identity(&chmodded));
    }

    #[test]
    fn open_dir_refuses_symlink() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let real = tmp.path().join("real");
        std::fs::create_dir(&real).expect("mkdir");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");
        let err = open_dir(&c(link.to_str().expect("utf8"))).expect_err("must refuse symlink");
        // The kernel reports O_NOFOLLOW refusal as ELOOP, or ENOTDIR when
        // O_DIRECTORY is also set; either way the link is never followed.
        assert!(matches!(
            err.raw_os_error(),
            Some(libc::ELOOP) | Some(libc::ENOTDIR)
        ));
    }

    #[test]
    fn rename_noreplace_refuses_existing_destination() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("a"), b"a").expect("write");
        std::fs::write(tmp.path().join("b"), b"b").expect("write");
        let dir = open_dir(&c(tmp.path().to_str().expect("utf8"))).expect("open");
        let err = rename_noreplace(dir.as_fd(), &c("a"), &c("b")).expect_err("must not replace");
        assert_eq!(err.raw_os_error(), Some(libc::EEXIST));
        rename_noreplace(dir.as_fd(), &c("a"), &c("q")).expect("free name works");
        assert!(tmp.path().join("q").exists());
        assert_eq!(std::fs::read(tmp.path().join("b")).expect("read"), b"b");
    }

    #[test]
    fn dir_stream_lists_and_rewinds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::fs::write(tmp.path().join("one"), b"").expect("write");
        std::fs::write(tmp.path().join("two"), b"").expect("write");
        let dir = open_dir(&c(tmp.path().to_str().expect("utf8"))).expect("open");
        let mut stream = DirStream::open(dir.as_fd()).expect("stream");
        let mut names = Vec::new();
        while let Some(name) = stream.next_entry().expect("read") {
            names.push(name.into_string().expect("utf8"));
        }
        names.sort();
        assert_eq!(names, ["one", "two"]);
        stream.rewind();
        assert!(stream.next_entry().expect("read").is_some());
        stream.finish().expect("close");
    }

    #[test]
    fn mount_id_matches_between_descriptors_of_one_directory() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = c(tmp.path().to_str().expect("utf8"));
        let first = open_dir(&path).expect("open");
        let second = open_dir(&path).expect("open");
        let a = mount_id(first.as_fd()).expect("mount id");
        let b = mount_id(second.as_fd()).expect("mount id");
        assert_eq!(a, b);
    }
}
