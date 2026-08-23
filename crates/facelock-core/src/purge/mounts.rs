//! Mount topology snapshot from `/proc/self/mountinfo`.
//!
//! Two facts are extracted per line: the mount ID (field 0), so descriptor
//! mount IDs from `/proc/self/fdinfo` can be proven current, and the
//! mountpoint path (field 4, octal-escaped by the kernel), so a bind mount
//! whose device number is unchanged is still detected by name.

use std::collections::HashSet;
use std::io;
use std::path::Path;

#[derive(Debug, Default)]
pub(crate) struct MountTable {
    ids: HashSet<u64>,
    mountpoints: HashSet<Vec<u8>>,
}

impl MountTable {
    pub fn load(path: &Path) -> io::Result<MountTable> {
        let raw = std::fs::read(path)?;
        let mut table = MountTable::default();
        for line in raw.split(|byte| *byte == b'\n') {
            let fields: Vec<&[u8]> = line.split(|byte| *byte == b' ').collect();
            if fields.len() < 6 {
                continue;
            }
            if let Ok(text) = std::str::from_utf8(fields[0])
                && let Ok(id) = text.parse::<u64>()
            {
                table.ids.insert(id);
            }
            table.mountpoints.insert(decode_mount_path(fields[4]));
        }
        Ok(table)
    }

    /// Whether a descriptor mount ID names a currently mounted filesystem.
    pub fn contains_id(&self, id: u64) -> bool {
        self.ids.contains(&id)
    }

    /// Whether the actual (prefix-joined) path is itself a mountpoint.
    pub fn is_mountpoint(&self, actual_path: &[u8]) -> bool {
        self.mountpoints.contains(actual_path)
    }
}

/// Decode the kernel's `\NNN` octal escapes (space, tab, newline, backslash)
/// in a mountinfo path field.
fn decode_mount_path(raw: &[u8]) -> Vec<u8> {
    let mut decoded = Vec::with_capacity(raw.len());
    let mut rest = raw;
    while let Some((&byte, tail)) = rest.split_first() {
        if byte == b'\\'
            && tail.len() >= 3
            && tail[..3].iter().all(|digit| (b'0'..=b'7').contains(digit))
        {
            let value = tail[..3]
                .iter()
                .fold(0u32, |acc, digit| acc * 8 + u32::from(digit - b'0'));
            if value <= 0xff {
                decoded.push(value as u8);
                rest = &tail[3..];
                continue;
            }
        }
        decoded.push(byte);
        rest = tail;
    }
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_octal_escapes() {
        assert_eq!(
            decode_mount_path(b"/mnt/with\\040space"),
            b"/mnt/with space"
        );
        assert_eq!(decode_mount_path(b"/plain"), b"/plain");
        assert_eq!(decode_mount_path(b"/back\\134slash"), b"/back\\slash");
        // A truncated or non-octal escape is kept literally.
        assert_eq!(decode_mount_path(b"/bad\\04"), b"/bad\\04");
        assert_eq!(decode_mount_path(b"/bad\\049"), b"/bad\\049");
    }

    #[test]
    fn loads_ids_and_mountpoints() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let path = tmp.path().join("mountinfo");
        std::fs::write(
            &path,
            b"36 25 0:32 / /mnt/state rw,relatime shared:1 - tmpfs tmpfs rw\n\
              37 25 0:33 / /mnt/with\\040space rw - tmpfs tmpfs rw\n\
              short line\n",
        )
        .expect("write");
        let table = MountTable::load(&path).expect("load");
        assert!(table.contains_id(36));
        assert!(table.contains_id(37));
        assert!(!table.contains_id(99));
        assert!(table.is_mountpoint(b"/mnt/state"));
        assert!(table.is_mountpoint(b"/mnt/with space"));
        assert!(!table.is_mountpoint(b"/mnt/other"));
    }

    #[test]
    fn load_fails_on_missing_topology() {
        assert!(MountTable::load(Path::new("/nonexistent/mountinfo")).is_err());
    }
}
