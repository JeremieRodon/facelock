use serde::Deserialize;
use std::path::Path;
use tracing::{debug, info, warn};

use crate::device::DeviceInfo;

/// A hardware quirk entry loaded from a TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct Quirk {
    /// USB vendor ID (hex string, e.g. "8086")
    #[serde(default)]
    pub vendor_id: Option<String>,
    /// USB product ID (hex string, e.g. "0b07")
    #[serde(default)]
    pub product_id: Option<String>,
    /// Regex pattern to match against device name (fallback when IDs unavailable)
    #[serde(default)]
    pub name_pattern: Option<String>,
    /// Force this device to be treated as an IR camera
    #[serde(default)]
    pub force_ir: Option<bool>,
    /// UVC Extension Unit GUID for IR emitter control
    #[serde(default)]
    pub emitter_xu_guid: Option<String>,
    /// UVC XU control selector for emitter toggle
    #[serde(default)]
    pub emitter_xu_selector: Option<u8>,
    /// Override warmup frames for this camera
    #[serde(default)]
    pub warmup_frames: Option<u32>,
    /// Preferred pixel format
    #[serde(default)]
    pub format_preference: Option<String>,
    /// Image rotation in degrees
    #[serde(default)]
    pub rotation: Option<u16>,
    /// Human-readable notes
    #[serde(default)]
    pub notes: Option<String>,
}

/// Container for a list of quirks in a TOML file.
#[derive(Debug, Deserialize)]
struct QuirksFile {
    #[serde(default)]
    quirk: Vec<Quirk>,
}

/// Provenance of a [`QuirksDb`] match — how strongly the match is
/// corroborated by evidence the device cannot forge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuirkMatchKind {
    /// Matched by USB vendor:product ID, read from sysfs. Not spoofable by
    /// a virtual device (e.g. v4l2loopback exposes no real USB node, so it
    /// can never win a USB-ID match).
    UsbId,
    /// Matched by `name_pattern` against the free-text device/card name
    /// only. The name is attacker-controlled on virtual devices — see
    /// `facelock_camera::device::ir_source_with_quirks` for how a
    /// `force_ir = true` name-only match is required to be corroborated
    /// before it is trusted (#98 Task 3).
    NameOnly,
}

/// Database of hardware quirks loaded from TOML files.
#[derive(Debug, Default)]
pub struct QuirksDb {
    quirks: Vec<Quirk>,
}

impl QuirksDb {
    /// Load quirks from both system and user directories.
    /// System: `/usr/share/facelock/quirks.d/`
    /// User overrides: `/etc/facelock/quirks.d/`
    /// Files are loaded in alphabetical order; later files can override earlier ones.
    pub fn load() -> Self {
        let mut db = Self::default();
        for dir in &["/usr/share/facelock/quirks.d", "/etc/facelock/quirks.d"] {
            db.load_dir(Path::new(dir));
        }
        if db.quirks.is_empty() {
            debug!("no hardware quirks loaded");
        } else {
            info!(count = db.quirks.len(), "loaded hardware quirks");
        }
        db
    }

    /// Load quirks from a specific directory.
    pub fn load_dir(&mut self, dir: &Path) {
        let entries = match std::fs::read_dir(dir) {
            Ok(e) => e,
            Err(_) => return, // Directory doesn't exist, that's fine
        };

        let mut paths: Vec<_> = entries
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().is_some_and(|ext| ext == "toml"))
            .map(|e| e.path())
            .collect();
        paths.sort();

        for path in paths {
            match Self::load_file(&path) {
                Ok(quirks) => {
                    debug!(file = %path.display(), count = quirks.len(), "loaded quirks file");
                    self.quirks.extend(quirks);
                }
                Err(e) => {
                    warn!(file = %path.display(), "failed to load quirks file: {e}");
                }
            }
        }
    }

    fn load_file(path: &Path) -> Result<Vec<Quirk>, String> {
        let content = std::fs::read_to_string(path).map_err(|e| format!("read error: {e}"))?;
        let file: QuirksFile = toml::from_str(&content).map_err(|e| format!("parse error: {e}"))?;
        Ok(file.quirk)
    }

    /// Find a matching quirk for the given device.
    /// Matches by USB vendor:product ID first, then by name pattern.
    pub fn find_match(&self, device: &DeviceInfo) -> Option<&Quirk> {
        self.find_match_with_ids(device, read_usb_ids(&device.path).as_ref())
    }

    /// Like [`find_match`](Self::find_match) but with the device's USB
    /// vendor:product IDs supplied by the caller instead of read from sysfs.
    /// This keeps the sysfs read at the call boundary so classification is
    /// testable and so callers that already resolved the identity (e.g.
    /// multi-node sibling grouping) don't re-read sysfs per lookup.
    pub fn find_match_with_ids(
        &self,
        device: &DeviceInfo,
        usb_ids: Option<&(String, String)>,
    ) -> Option<&Quirk> {
        self.find_match_with_kind(device, usb_ids).map(|(q, _)| q)
    }

    /// Like [`find_match_with_ids`](Self::find_match_with_ids) but also
    /// reports HOW the quirk matched. Callers that gate a security-relevant
    /// decision (like `force_ir`, see `facelock_camera::device`) on the
    /// result need this: a [`QuirkMatchKind::NameOnly`] match rests on the
    /// free-text device name, which is attacker-controlled on virtual
    /// devices such as v4l2loopback, and should not be trusted the same way
    /// as a [`QuirkMatchKind::UsbId`] match.
    pub fn find_match_with_kind(
        &self,
        device: &DeviceInfo,
        usb_ids: Option<&(String, String)>,
    ) -> Option<(&Quirk, QuirkMatchKind)> {
        // First pass: match by USB vendor:product ID (most specific)
        if let Some((vendor, product)) = usb_ids {
            for quirk in &self.quirks {
                if let (Some(qv), Some(qp)) = (&quirk.vendor_id, &quirk.product_id) {
                    if qv.eq_ignore_ascii_case(vendor) && qp.eq_ignore_ascii_case(product) {
                        debug!(
                            device = %device.path,
                            vendor, product,
                            notes = quirk.notes.as_deref().unwrap_or(""),
                            "matched quirk by USB ID"
                        );
                        return Some((quirk, QuirkMatchKind::UsbId));
                    }
                }
            }
        }

        // Second pass: match by name pattern
        for quirk in &self.quirks {
            if let Some(pattern) = &quirk.name_pattern {
                // Simple case-insensitive substring/pattern matching
                // We avoid the regex crate dependency by using a simple approach
                if name_matches(pattern, &device.name) {
                    debug!(
                        device = %device.path,
                        name = %device.name,
                        pattern,
                        notes = quirk.notes.as_deref().unwrap_or(""),
                        "matched quirk by name pattern"
                    );
                    return Some((quirk, QuirkMatchKind::NameOnly));
                }
            }
        }

        None
    }

    /// Get all quirks for display/debugging.
    pub fn all(&self) -> &[Quirk] {
        &self.quirks
    }

    /// Push a quirk directly (test-only helper for cross-module tests).
    #[cfg(test)]
    pub fn push_quirk_for_test(&mut self, quirk: Quirk) {
        self.quirks.push(quirk);
    }
}

/// Read USB vendor:product IDs from sysfs for a video device.
/// Returns (vendor_id, product_id) as hex strings, or None if unavailable.
pub(crate) fn read_usb_ids(device_path: &str) -> Option<(String, String)> {
    let fp = device_fingerprint(device_path);
    match (fp.vid, fp.pid) {
        (Some(v), Some(p)) => Some((v, p)),
        _ => None,
    }
}

/// Read a stable-ish hardware fingerprint for a video device from sysfs.
///
/// Reads `idVendor`/`idProduct`/`serial` from the same sysfs base used for
/// quirks matching (walking one level up to reach the USB device node), plus
/// the `/dev/v4l/by-path` symlink target. **Tolerates every field being
/// missing** — a camera with no readable USB identity yields an all-`None`
/// fingerprint, which the enroll path stores as a NULL `device_id` so coupling
/// never becomes a hard lockout.
///
/// This is model-granularity (VID:PID) at best and forgeable by a programmable
/// USB device: advisory defense-in-depth, not attestation. See
/// [`facelock_core::types::DeviceFingerprint`].
pub fn device_fingerprint(device_path: &str) -> facelock_core::types::DeviceFingerprint {
    use facelock_core::types::DeviceFingerprint;

    let dev_name = match device_path.strip_prefix("/dev/") {
        Some(n) => n,
        None => return DeviceFingerprint::default(),
    };
    let sysfs_base = format!("/sys/class/video4linux/{dev_name}/device");
    let parent = format!("{sysfs_base}/..");

    // Vendor/product/serial live on the USB device node, which may be the
    // `device` symlink target itself or one level up.
    let read_attr = |attr: &str| {
        try_read_sysfs_attr(&sysfs_base, attr).or_else(|| try_read_sysfs_attr(&parent, attr))
    };

    DeviceFingerprint {
        // Normalize hex ids to lowercase so the canonical form is stable
        // regardless of sysfs casing.
        vid: read_attr("idVendor").map(|s| s.to_ascii_lowercase()),
        pid: read_attr("idProduct").map(|s| s.to_ascii_lowercase()),
        serial: read_attr("serial"),
        by_path: read_v4l_by_path(device_path),
    }
}

/// Resolve the stable `/dev/v4l/by-path/...` symlink that points at this device.
/// Returns the symlink filename (bus topology), not the resolved `/dev/videoN`.
fn read_v4l_by_path(device_path: &str) -> Option<String> {
    let entries = std::fs::read_dir("/dev/v4l/by-path").ok()?;
    let target = std::fs::canonicalize(device_path).ok()?;
    for entry in entries.filter_map(|e| e.ok()) {
        if let Ok(resolved) = std::fs::canonicalize(entry.path()) {
            if resolved == target {
                return entry.file_name().into_string().ok();
            }
        }
    }
    None
}

fn try_read_sysfs_attr(base: &str, attr: &str) -> Option<String> {
    let path = format!("{base}/{attr}");
    std::fs::read_to_string(&path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

/// Simple pattern matching: supports (?i) prefix for case-insensitive, .* for
/// wildcards. This is a simplified matcher that handles the most common
/// quirks patterns without pulling in the full regex crate.
///
/// Matches against the WHOLE `name`, not a substring of it (#99): a part of
/// the pattern that isn't adjacent to a leading/trailing `.*` must anchor to
/// the corresponding end of `name`. Without this, `(?i)ir.*camera` matches
/// "Sirius Camera" — the "ir" inside "Sirius" satisfies the first part, and
/// "camera" appears later — silently granting `force_ir` to an unrelated RGB
/// webcam. `.*` at either end still means "anything may precede/follow
/// here", so `(?i).*ir camera.*` still matches "Integrated IR Camera 5MP".
fn name_matches(pattern: &str, name: &str) -> bool {
    let (case_insensitive, pattern) = match pattern.strip_prefix("(?i)") {
        Some(p) => (true, p),
        None => (false, pattern),
    };

    let name = if case_insensitive {
        name.to_lowercase()
    } else {
        name.to_string()
    };
    let pattern = if case_insensitive {
        pattern.to_lowercase()
    } else {
        pattern.to_string()
    };

    // Splitting on the literal ".*" tells us, from the emptiness of the
    // first/last raw segment, whether the pattern opens/closes with a
    // wildcard (an empty segment there means ".*" was right at that edge).
    let raw_parts: Vec<&str> = pattern.split(".*").collect();
    let starts_wild = raw_parts.len() > 1 && raw_parts.first().is_some_and(|p| p.is_empty());
    let ends_wild = raw_parts.len() > 1 && raw_parts.last().is_some_and(|p| p.is_empty());
    let parts: Vec<&str> = raw_parts.into_iter().filter(|p| !p.is_empty()).collect();

    if parts.is_empty() {
        // Pattern is empty, or entirely wildcard (".*", ".*.*", ...) — matches anything.
        return true;
    }

    let mut pos = 0usize;
    for (i, part) in parts.iter().enumerate() {
        let is_first = i == 0;
        let is_last = i == parts.len() - 1;
        if is_first && !starts_wild {
            // No leading wildcard: this part must anchor the very start of `name`.
            if !name[pos..].starts_with(part) {
                return false;
            }
            pos += part.len();
            // A single unwildcarded part must also anchor the end.
            if is_last && !ends_wild && pos != name.len() {
                return false;
            }
        } else if is_last && !ends_wild {
            // No trailing wildcard: this part must anchor the very end of
            // `name`, without re-consuming bytes already matched by an
            // earlier part.
            if part.len() > name.len() || name.len() - part.len() < pos || !name.ends_with(part) {
                return false;
            }
            pos = name.len();
        } else {
            match name[pos..].find(part) {
                Some(idx) => pos += idx + part.len(),
                None => return false,
            }
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_device(name: &str) -> DeviceInfo {
        DeviceInfo {
            path: "/dev/nonexistent_test_video".into(),
            name: name.into(),
            driver: "uvcvideo".into(),
            capabilities: vec![],
            formats: vec![],
        }
    }

    #[test]
    fn name_matches_case_insensitive() {
        assert!(name_matches(
            "(?i).*integrated.*ir camera.*",
            "Integrated IR Camera"
        ));
        assert!(name_matches(
            "(?i).*integrated.*infrared camera.*",
            "Integrated Infrared Camera"
        ));
    }

    #[test]
    fn name_matches_anchors_start_and_end() {
        // No wildcard at either end: the pattern must describe the WHOLE name.
        assert!(name_matches("(?i)hp ir camera", "HP IR Camera"));
        assert!(!name_matches("(?i)hp ir camera", "HP IR Camera 5MP"));
        assert!(!name_matches("(?i)hp ir camera", "New HP IR Camera"));
    }

    #[test]
    fn name_matches_trailing_wildcard_anchors_start_only() {
        assert!(name_matches("(?i)hp.* ir.*", "HP IR Camera 5MP"));
        // Vendor token must still be the literal start of the name.
        assert!(!name_matches("(?i)hp.* ir.*", "New HP IR Camera"));
        assert!(!name_matches("(?i)dell.* ir.*", "Logitech Webcam"));
    }

    #[test]
    fn name_matches_case_sensitive() {
        assert!(name_matches("IR Camera", "IR Camera"));
        assert!(!name_matches("IR Camera", "ir camera"));
        assert!(!name_matches("IR Camera", "My IR Camera"));
    }

    #[test]
    fn name_matches_anchoring_rejects_substring_false_positive() {
        // #99 regression: the unmodified, unanchored pattern must no longer
        // match an unrelated RGB webcam whose name merely contains the "ir"
        // substring ("Sirius") or ("AIR-Cam") ahead of "camera" elsewhere.
        assert!(!name_matches("(?i)ir.*camera", "Sirius Camera"));
        assert!(!name_matches("(?i)ir.*camera", "AIR-Cam"));
        // A real anchored pattern for the same intent still matches its
        // actual device.
        assert!(name_matches("(?i)ir camera.*", "IR Camera 720p"));
        assert!(name_matches("(?i)ir camera.*", "IR Camera"));
    }

    #[test]
    fn name_matches_word_boundary_within_wildcard_span() {
        // A trailing wildcard after a vendor prefix must not let "ir" match
        // via an unrelated word that merely contains the letters "ir"
        // (e.g. "Air") — the pattern's " ir" requires a literal space
        // immediately before "ir".
        assert!(!name_matches("(?i)hp.* ir.*", "HP Air Camera"));
        assert!(!name_matches("(?i)surface.* ir.*", "Surface Air Camera"));
    }

    #[test]
    fn quirk_deserialization() {
        let toml = r#"
[[quirk]]
vendor_id = "8086"
product_id = "0b07"
force_ir = true
warmup_frames = 10
notes = "Test camera"
"#;
        let file: QuirksFile = toml::from_str(toml).unwrap();
        assert_eq!(file.quirk.len(), 1);
        assert_eq!(file.quirk[0].vendor_id.as_deref(), Some("8086"));
        assert_eq!(file.quirk[0].force_ir, Some(true));
        assert_eq!(file.quirk[0].warmup_frames, Some(10));
    }

    #[test]
    fn quirks_db_find_by_name() {
        let mut db = QuirksDb::default();
        db.quirks.push(Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)hp.* ir.*".into()),
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: Some(8),
            format_preference: None,
            rotation: None,
            notes: Some("HP IR".into()),
        });

        let device = make_device("HP IR Camera 5MP");
        let quirk = db.find_match(&device);
        assert!(quirk.is_some());
        assert_eq!(quirk.unwrap().force_ir, Some(true));
    }

    #[test]
    fn quirks_db_no_match() {
        let db = QuirksDb::default();
        let device = make_device("Some Random Camera");
        assert!(db.find_match(&device).is_none());
    }

    #[test]
    fn quirks_db_usb_id_matching() {
        let mut db = QuirksDb::default();
        db.quirks.push(Quirk {
            vendor_id: Some("8086".into()),
            product_id: Some("0b07".into()),
            name_pattern: None,
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: Some(10),
            format_preference: Some("Y16 ".into()),
            rotation: None,
            notes: Some("Intel RealSense".into()),
        });
        // Add a name-pattern quirk that would also match
        db.quirks.push(Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i).*realsense.*".into()),
            force_ir: Some(false), // Different value to test priority
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: None,
        });

        // USB ID matching not testable without sysfs, but we can verify
        // name pattern is the fallback when USB IDs don't match
        let device = make_device("Intel RealSense D435");
        let quirk = db.find_match(&device);
        assert!(quirk.is_some());
        // Should match by name pattern since we can't read sysfs in tests
        // The force_ir from name match quirk (false) or USB match (true)
        // depends on whether sysfs IDs are readable
    }

    #[test]
    fn quirks_db_case_insensitive_usb_id() {
        // USB IDs should match case-insensitively
        let mut db = QuirksDb::default();
        db.quirks.push(Quirk {
            vendor_id: Some("046D".into()),  // uppercase D
            product_id: Some("085E".into()), // uppercase E
            name_pattern: None,
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: Some("Logitech".into()),
        });

        // Can only test name fallback in tests (no sysfs)
        let device = make_device("Some other camera");
        assert!(db.find_match(&device).is_none());
    }

    #[test]
    fn quirks_db_multiple_name_patterns() {
        let mut db = QuirksDb::default();
        db.quirks.push(Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)first.*camera".into()),
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: Some("first pattern".into()),
        });
        db.quirks.push(Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)second.*camera.*".into()),
            force_ir: Some(false),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: Some("second pattern".into()),
        });

        // "first.*camera" (no trailing wildcard) anchors to the end too —
        // still matches because the device name happens to end in "Camera".
        let dev1 = make_device("First IR Camera");
        let q1 = db.find_match(&dev1);
        assert!(q1.is_some());
        assert_eq!(q1.unwrap().force_ir, Some(true));

        let dev2 = make_device("Second Camera Module");
        let q2 = db.find_match(&dev2);
        assert!(q2.is_some());
        assert_eq!(q2.unwrap().force_ir, Some(false));

        let dev3 = make_device("Third Webcam");
        assert!(db.find_match(&dev3).is_none());
    }

    #[test]
    fn name_matches_multiple_wildcards_anchored() {
        // Anchored: the final part must now match at the very end of the name.
        assert!(name_matches("(?i)a.*b.*c", "Alpha Beta Attic"));
        assert!(!name_matches("(?i)a.*b.*c", "Alpha Delta"));
        assert!(!name_matches("(?i)a.*b.*c", "Alpha Beta Camera"));
        assert!(name_matches("(?i)a.*b.*c.*", "Alpha Beta Camera"));
    }

    #[test]
    fn name_matches_empty_pattern() {
        // Empty pattern should match anything (all parts empty after split)
        assert!(name_matches("", "Any Camera"));
        assert!(name_matches(".*", "Any Camera"));
    }

    #[test]
    fn device_fingerprint_tolerates_missing_sysfs() {
        // A path with no sysfs backing degrades to an all-None fingerprint
        // (canonical "::"), which stores as NULL and is legacy-governed.
        let fp = device_fingerprint("/dev/nonexistent_test_video");
        assert!(fp.is_unknown());
        assert!(!fp.has_serial());
        assert_eq!(fp.canonical(), "::");
        assert_eq!(fp.canonical_for_storage(), None);
    }

    #[test]
    fn device_fingerprint_rejects_non_dev_path() {
        let fp = device_fingerprint("relative/path");
        assert!(fp.is_unknown());
    }

    #[test]
    fn quirks_load_dir_nonexistent() {
        let mut db = QuirksDb::default();
        db.load_dir(Path::new("/nonexistent/quirks/dir"));
        assert!(
            db.quirks.is_empty(),
            "nonexistent dir should load zero quirks"
        );
    }

    #[test]
    fn quirk_with_all_optional_fields() {
        let toml = r#"
[[quirk]]
vendor_id = "1234"
product_id = "5678"
name_pattern = "(?i)test"
force_ir = true
emitter_xu_guid = "abcd-1234"
emitter_xu_selector = 3
warmup_frames = 15
format_preference = "GREY"
rotation = 90
notes = "Full test quirk"
"#;
        let file: QuirksFile = toml::from_str(toml).unwrap();
        let q = &file.quirk[0];
        assert_eq!(q.emitter_xu_guid.as_deref(), Some("abcd-1234"));
        assert_eq!(q.emitter_xu_selector, Some(3));
        assert_eq!(q.warmup_frames, Some(15));
        assert_eq!(q.format_preference.as_deref(), Some("GREY"));
        assert_eq!(q.rotation, Some(90));
    }

    #[test]
    fn load_defaults_file() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config/quirks.d/00-defaults.toml");
        if path.exists() {
            let quirks = QuirksDb::load_file(&path).unwrap();
            assert!(!quirks.is_empty(), "defaults file should have quirks");
        }
    }

    /// Table-driven regression for #99: every shipped `name_pattern` quirk
    /// in `config/quirks.d/00-defaults.toml` must still match a plausible
    /// real device name after anchoring, and none of them may match an
    /// ordinary RGB webcam name — including the specific decoys ("Sirius
    /// Camera", "AIR-Cam") that the pre-anchoring substring matcher was
    /// fooled by. This mirrors `device::tests::ir_classification_corpus`'s
    /// decoy corpus.
    #[test]
    fn shipped_quirk_name_patterns_match_intended_devices_and_reject_decoys() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
            .join("config/quirks.d/00-defaults.toml");
        if !path.exists() {
            return;
        }
        let quirks = QuirksDb::load_file(&path).expect("defaults file parses");

        // (substring identifying which pattern this is, a representative
        // real device name it must still match)
        let cases: &[(&str, &str)] = &[
            ("ir camera", "IR Camera"),
            ("surface", "Surface Pro IR Camera"),
            ("hp", "HP IR Camera 5MP"),
            ("dell", "Dell IR Camera"),
        ];

        let decoys = [
            "Integrated Webcam",
            "USB2.0 HD UVC WebCam",
            "AIR-Cam",
            "Sirius Camera",
            "Chicony USB2.0 Camera",
        ];

        let mut exercised = 0;
        for quirk in &quirks {
            let Some(pattern) = &quirk.name_pattern else {
                continue;
            };
            let lower = pattern.to_lowercase();
            let (_, expected_name) = cases
                .iter()
                .find(|(needle, _)| lower.contains(needle))
                .unwrap_or_else(|| {
                    panic!("no test case wired up for shipped pattern {pattern:?} — add one")
                });
            assert!(
                name_matches(pattern, expected_name),
                "pattern {pattern:?} should still match {expected_name:?} after anchoring"
            );
            for decoy in decoys {
                assert!(
                    !name_matches(pattern, decoy),
                    "pattern {pattern:?} must NOT match decoy {decoy:?}"
                );
            }
            exercised += 1;
        }
        assert_eq!(
            exercised,
            cases.len(),
            "every expected shipped name_pattern quirk was exercised"
        );
    }
}
