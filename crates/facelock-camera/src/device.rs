use facelock_core::error::{FacelockError, Result};
use v4l::Device;
use v4l::capability::Flags;
use v4l::framesize::FrameSizeEnum;
use v4l::video::Capture;

/// Information about a V4L2 video device.
#[derive(Debug, Clone)]
pub struct DeviceInfo {
    pub path: String,
    pub name: String,
    pub driver: String,
    pub capabilities: Vec<String>,
    pub formats: Vec<FormatInfo>,
}

/// A supported pixel format with its available sizes.
#[derive(Debug, Clone)]
pub struct FormatInfo {
    pub fourcc: String,
    pub description: String,
    pub sizes: Vec<(u32, u32)>,
}

/// List all V4L2 video capture devices.
/// Returns an empty vec if no devices are found (does not error).
pub fn list_devices() -> Result<Vec<DeviceInfo>> {
    let mut devices = Vec::new();

    for i in 0..64 {
        let path = format!("/dev/video{i}");
        if !std::path::Path::new(&path).exists() {
            continue;
        }
        match query_device(&path) {
            Ok(info) => devices.push(info),
            Err(e) => {
                tracing::debug!("skipping {path}: {e}");
                continue;
            }
        }
    }

    Ok(devices)
}

/// Validate that a specific device path is a usable video capture device.
pub fn validate_device(path: &str) -> Result<DeviceInfo> {
    query_device(path)
}

/// Provenance of an IR classification decision, for logging and honesty.
///
/// Ordered by authoritativeness: a `Quirk` hit is definitive; `Format` means a
/// native IR capture format (GREY/Y16) corroborated by an IR name token; `Name`
/// means an IR name token alone; `None` means not classified as IR.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IrSource {
    /// Hardware quirks DB `force_ir = true` — authoritative.
    Quirk,
    /// Native IR format (GREY/Y16) corroborated by an IR name token.
    Format,
    /// IR name token ("ir"/"infrared") present, no IR capture format.
    Name,
    /// Not classified as IR.
    None,
}

/// True if the device name contains a whole `ir` or `infrared` token.
///
/// Tokenizes on non-alphanumeric boundaries so that substrings like the "ir" in
/// "Sirius" or "AIR-Cam" do NOT falsely match — only a standalone token counts.
fn has_ir_name_token(name: &str) -> bool {
    name.split(|c: char| !c.is_ascii_alphanumeric())
        .any(|tok| tok.eq_ignore_ascii_case("ir") || tok.eq_ignore_ascii_case("infrared"))
}

/// Heuristic: is this likely an IR camera?
///
/// See [`ir_source_with_quirks`] for the decision rules; this is the boolean form.
pub fn is_ir_camera(device: &DeviceInfo) -> bool {
    ir_source(device) != IrSource::None
}

/// Like [`is_ir_camera`] but accepts a quirks database for device-specific overrides.
pub fn is_ir_camera_with_quirks(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
) -> bool {
    ir_source_with_quirks(device, quirks) != IrSource::None
}

/// Classify a device's IR provenance without a quirks database.
pub fn ir_source(device: &DeviceInfo) -> IrSource {
    ir_source_with_quirks(device, None)
}

/// True if the device natively exposes an IR-like capture format (GREY/Y16).
fn has_native_ir_format(device: &DeviceInfo) -> bool {
    device
        .formats
        .iter()
        .any(|f| matches!(f.fourcc.as_str(), "GREY" | "Y16 "))
}

/// The quirk-free heuristic classification (name token / format corroboration).
fn heuristic_ir_source(device: &DeviceInfo) -> IrSource {
    match (
        has_ir_name_token(&device.name),
        has_native_ir_format(device),
    ) {
        // Native IR format corroborated by the name token — strongest heuristic.
        (true, true) => IrSource::Format,
        // Name token alone is sufficient (e.g. "Infrared Camera").
        (true, false) => IrSource::Name,
        // Format alone (or nothing) is NOT sufficient — this is the H1 bypass fix.
        (false, _) => IrSource::None,
    }
}

/// Classify a device's IR provenance, honoring the quirks DB as authoritative.
///
/// Decision rules (H1 fix — mere *availability* of GREY/Y16 is NOT proof of IR):
/// 1. A quirks DB `force_ir` value is authoritative in both directions.
/// 2. A native IR capture format (GREY/Y16) counts only when corroborated by an
///    IR name token → [`IrSource::Format`].
/// 3. An IR name token alone → [`IrSource::Name`].
/// 4. Otherwise → [`IrSource::None`] (a plain RGB webcam that merely enumerates
///    GREY is not treated as IR).
///
/// CAVEAT (multi-node USB devices): one physical USB camera can expose several
/// V4L2 capture nodes sharing the same VID:PID (e.g. the Logitech BRIO's RGB
/// node and IR node). Per-node this function classifies ALL of them by the
/// quirk. Use [`classify_ir_sources`] (list) or [`ir_source_resolved`] (single
/// device, enumerates siblings) to disambiguate the actual IR sensor node.
pub fn ir_source_with_quirks(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
) -> IrSource {
    ir_source_with_quirks_and_ids(
        device,
        quirks,
        crate::quirks::read_usb_ids(&device.path).as_ref(),
    )
}

/// Per-node classification with the USB IDs supplied by the caller (keeps the
/// sysfs read at the call boundary for testability).
fn ir_source_with_quirks_and_ids(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
    usb_ids: Option<&(String, String)>,
) -> IrSource {
    // 1. Quirks database is authoritative (both true and false).
    if let Some(db) = quirks {
        if let Some(quirk) = db.find_match_with_ids(device, usb_ids) {
            if let Some(force_ir) = quirk.force_ir {
                return if force_ir {
                    IrSource::Quirk
                } else {
                    IrSource::None
                };
            }
        }
    }
    heuristic_ir_source(device)
}

/// Classify IR provenance for a whole set of enumerated capture nodes,
/// disambiguating multi-node USB devices.
///
/// A quirks `force_ir` entry means "this USB **device** has an IR sensor", not
/// "every capture node of it is IR". One physical camera can expose several
/// V4L2 nodes sharing the same VID:PID — e.g. the Logitech BRIO (046d:085e) has
/// an RGB node (YUYV/MJPG) *and* an IR node (native GREY). When multiple nodes
/// share one quirk-matched USB identity AND at least one of them exposes an
/// IR-like format (GREY/Y16, or the quirk's `format_preference`), only the
/// node(s) with that format are IR; siblings without it fall back to the
/// quirk-free heuristic. If NO node has an IR-like format there is no evidence
/// to disambiguate with, so `force_ir` is trusted for all nodes (some quirk
/// entries exist precisely because the camera advertises no IR-like format).
pub fn classify_ir_sources(
    devices: &[DeviceInfo],
    quirks: Option<&crate::quirks::QuirksDb>,
) -> Vec<IrSource> {
    let usb_ids: Vec<Option<(String, String)>> = devices
        .iter()
        .map(|d| crate::quirks::read_usb_ids(&d.path))
        .collect();
    classify_ir_sources_with_ids(devices, quirks, &usb_ids)
}

fn classify_ir_sources_with_ids(
    devices: &[DeviceInfo],
    quirks: Option<&crate::quirks::QuirksDb>,
    usb_ids: &[Option<(String, String)>],
) -> Vec<IrSource> {
    let mut sources: Vec<IrSource> = devices
        .iter()
        .zip(usb_ids)
        .map(|(d, ids)| ir_source_with_quirks_and_ids(d, quirks, ids.as_ref()))
        .collect();

    // Node-level disambiguation for multi-node USB devices.
    let mut seen: Vec<&(String, String)> = Vec::new();
    for i in 0..devices.len() {
        if sources[i] != IrSource::Quirk {
            continue;
        }
        // Sibling grouping requires a readable USB identity.
        let Some(ids) = usb_ids[i].as_ref() else {
            continue;
        };
        if seen.contains(&ids) {
            continue;
        }
        seen.push(ids);

        let group: Vec<usize> = (0..devices.len())
            .filter(|&j| sources[j] == IrSource::Quirk && usb_ids[j].as_ref() == Some(ids))
            .collect();
        if group.len() < 2 {
            continue;
        }

        // IR-like formats: GREY/Y16 plus the quirk's format_preference, if any.
        let pref = quirks
            .and_then(|db| db.find_match_with_ids(&devices[i], Some(ids)))
            .and_then(|q| q.format_preference.clone());
        let node_has_ir_format = |j: usize| {
            has_native_ir_format(&devices[j])
                || pref.as_deref().is_some_and(|p| {
                    devices[j]
                        .formats
                        .iter()
                        .any(|f| f.fourcc.trim() == p.trim())
                })
        };

        // Only demote when format evidence exists within the group; otherwise
        // trust force_ir for every node.
        if group.iter().any(|&j| node_has_ir_format(j)) {
            for &j in &group {
                if !node_has_ir_format(j) {
                    let demoted = heuristic_ir_source(&devices[j]);
                    tracing::debug!(
                        device = %devices[j].path,
                        vid = %ids.0,
                        pid = %ids.1,
                        reclassified = ?demoted,
                        "multi-node quirk device: node lacks IR-like format, \
                         sibling node has it — not the IR sensor node"
                    );
                    sources[j] = demoted;
                }
            }
        }
    }

    sources
}

/// Sibling-aware IR classification for a single device.
///
/// Enumerates the host's other V4L2 nodes so that multi-node USB devices are
/// disambiguated exactly as in [`classify_ir_sources`]. Use this instead of
/// [`ir_source_with_quirks`] whenever the answer gates `require_ir`.
pub fn ir_source_resolved(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
) -> IrSource {
    // Siblings only add context; the caller's DeviceInfo is authoritative for
    // its own path (replace any enumerated entry at the same path with it).
    let mut devices = list_devices().unwrap_or_default();
    devices.retain(|d| d.path != device.path);
    devices.push(device.clone());
    let sources = classify_ir_sources(&devices, quirks);
    // The device was appended last above.
    sources.last().copied().unwrap_or(IrSource::None)
}

/// Boolean form of [`ir_source_resolved`].
pub fn is_ir_camera_resolved(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
) -> bool {
    ir_source_resolved(device, quirks) != IrSource::None
}

/// Auto-detect the best available video capture device.
///
/// Classifies all nodes with [`classify_ir_sources`] (so multi-node USB devices
/// resolve to their actual IR sensor node), then prefers: a quirks-confirmed IR
/// node with a native IR format, then any quirks-confirmed IR node, then a
/// heuristically-IR node (name token), then the first enumerated device. It
/// never auto-selects an unknown camera *just because* it self-reports a
/// GREY/Y16 format (H1).
///
/// NOTE (seam for Plan 02): device selection here is by capability/heuristic, not
/// by stable device identity. Plan 02 will pin the enrolled camera by identity.
pub fn auto_detect_device() -> Result<DeviceInfo> {
    let devices = list_devices()?;
    let quirks = crate::quirks::QuirksDb::load();
    let sources = classify_ir_sources(&devices, Some(&quirks));
    pick_auto_device(&devices, &sources)
        .cloned()
        .ok_or_else(|| FacelockError::Camera("no video devices found".into()))
}

/// Selection order for auto-detection, over pre-classified nodes.
/// Prefers the format-corroborated IR node so a multi-node camera's RGB
/// sibling is never picked over its IR sensor.
fn pick_auto_device<'a>(devices: &'a [DeviceInfo], sources: &[IrSource]) -> Option<&'a DeviceInfo> {
    let nodes = || devices.iter().zip(sources);
    nodes()
        .find(|(d, s)| **s == IrSource::Quirk && has_native_ir_format(d))
        .or_else(|| nodes().find(|(_, s)| **s == IrSource::Quirk))
        .or_else(|| nodes().find(|(_, s)| **s != IrSource::None))
        .map(|(d, _)| d)
        .or_else(|| devices.first())
}

fn query_device(path: &str) -> Result<DeviceInfo> {
    let dev = Device::with_path(path).map_err(|e| FacelockError::Camera(format!("{path}: {e}")))?;

    let caps = dev
        .query_caps()
        .map_err(|e| FacelockError::Camera(format!("{path}: failed to query caps: {e}")))?;

    if !caps.capabilities.contains(Flags::VIDEO_CAPTURE) {
        return Err(FacelockError::Camera(format!(
            "{path}: not a video capture device"
        )));
    }

    let mut cap_strings = Vec::new();
    if caps.capabilities.contains(Flags::VIDEO_CAPTURE) {
        cap_strings.push("VIDEO_CAPTURE".to_string());
    }
    if caps.capabilities.contains(Flags::STREAMING) {
        cap_strings.push("STREAMING".to_string());
    }

    let mut formats = Vec::new();
    if let Ok(fmt_list) = dev.enum_formats() {
        for fmt in fmt_list {
            let fourcc = fmt.fourcc.to_string();
            let description = fmt.description.clone();
            let mut sizes = Vec::new();
            if let Ok(size_list) = dev.enum_framesizes(fmt.fourcc) {
                for fs in size_list {
                    match fs.size {
                        FrameSizeEnum::Discrete(d) => {
                            sizes.push((d.width, d.height));
                        }
                        FrameSizeEnum::Stepwise(s) => {
                            sizes.push((s.min_width, s.min_height));
                            sizes.push((s.max_width, s.max_height));
                        }
                    }
                }
            }
            formats.push(FormatInfo {
                fourcc,
                description,
                sizes,
            });
        }
    }

    Ok(DeviceInfo {
        path: path.to_string(),
        name: caps.card.clone(),
        driver: caps.driver.clone(),
        capabilities: cap_strings,
        formats,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn device_with(name: &str, fourccs: &[&str]) -> DeviceInfo {
        DeviceInfo {
            path: "/dev/nonexistent_test_video".into(),
            name: name.into(),
            driver: "uvcvideo".into(),
            capabilities: vec![],
            formats: fourccs
                .iter()
                .map(|f| FormatInfo {
                    fourcc: (*f).into(),
                    description: "test".into(),
                    sizes: vec![(640, 480)],
                })
                .collect(),
        }
    }

    #[test]
    fn is_ir_camera_grey_format_alone_is_not_ir() {
        // H1 fix: merely enumerating GREY is NOT proof of IR. An RGB webcam that
        // advertises a GREY format with no IR name token / quirk is not-IR.
        let device = device_with("USB Camera", &["GREY"]);
        assert!(!is_ir_camera(&device));
        assert_eq!(ir_source(&device), IrSource::None);
    }

    #[test]
    fn ir_classification_corpus() {
        // Real RGB camera name strings must classify not-IR, even the ones
        // whose names contain the substring "ir" but not the token "ir".
        for name in [
            "Integrated Webcam",
            "USB2.0 HD UVC WebCam",
            "AIR-Cam",
            "Sirius",
            "Chicony USB2.0 Camera",
        ] {
            let dev = device_with(name, &["YUYV", "MJPG"]);
            assert!(!is_ir_camera(&dev), "{name} should be not-IR");
        }
        // A GREY-only RGB cam is still not-IR without corroboration.
        assert!(!is_ir_camera(&device_with("Generic Cam", &["GREY"])));
        // A name IR token classifies IR.
        assert_eq!(
            ir_source(&device_with("Integrated IR Camera", &["YUYV"])),
            IrSource::Name
        );
        assert_eq!(
            ir_source(&device_with("Infrared Camera", &["MJPG"])),
            IrSource::Name
        );
    }

    #[test]
    fn is_ir_camera_mjpg_only() {
        let device = device_with("USB Camera", &["MJPG"]);
        assert!(!is_ir_camera(&device));
    }

    #[test]
    fn is_ir_camera_infrared_name() {
        // Name token "infrared" is sufficient on its own.
        let device = device_with("Infrared Camera", &["MJPG"]);
        assert!(is_ir_camera(&device));
        assert_eq!(ir_source(&device), IrSource::Name);
    }

    #[test]
    fn is_ir_camera_y16_name_token_corroborated_is_format() {
        // Y16 native format corroborated by an IR name token → Format provenance.
        let device = device_with("Integrated IR Camera", &["Y16 "]);
        assert!(is_ir_camera(&device));
        assert_eq!(ir_source(&device), IrSource::Format);
    }

    #[test]
    fn is_ir_camera_y16_without_name_is_not_ir() {
        // Y16 alone (no IR name token, no quirk) is no longer proof of IR.
        let device = device_with("Depth Camera", &["Y16 "]);
        assert!(!is_ir_camera(&device));
    }

    #[test]
    fn quirk_force_ir_is_authoritative() {
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(crate::quirks::Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)generic".into()),
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: Some("test force_ir".into()),
        });
        // No IR name token, no IR format — quirk alone makes it IR.
        let device = device_with("Generic Camera", &["YUYV"]);
        assert!(is_ir_camera_with_quirks(&device, Some(&db)));
        assert_eq!(ir_source_with_quirks(&device, Some(&db)), IrSource::Quirk);

        // A quirk with force_ir = false is authoritative "not IR" even if the
        // name has an IR token.
        let mut db_off = crate::quirks::QuirksDb::default();
        db_off.push_quirk_for_test(crate::quirks::Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)ir".into()),
            force_ir: Some(false),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: None,
        });
        let ir_named = device_with("Integrated IR Camera", &["GREY"]);
        assert!(!is_ir_camera_with_quirks(&ir_named, Some(&db_off)));
    }

    fn device_at(path: &str, name: &str, fourccs: &[&str]) -> DeviceInfo {
        DeviceInfo {
            path: path.into(),
            ..device_with(name, fourccs)
        }
    }

    fn brio_quirk(format_preference: Option<&str>) -> crate::quirks::Quirk {
        crate::quirks::Quirk {
            vendor_id: Some("046d".into()),
            product_id: Some("085e".into()),
            name_pattern: None,
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: Some(1),
            format_preference: format_preference.map(Into::into),
            rotation: None,
            notes: Some("Logitech BRIO 4K with IR sensor".into()),
        }
    }

    fn brio_ids() -> Option<(String, String)> {
        Some(("046d".into(), "085e".into()))
    }

    #[test]
    fn brio_multi_node_only_grey_node_classifies_ir() {
        // Regression (hardware-verified, Logitech BRIO 046d:085e): one physical
        // USB camera exposes TWO capture nodes sharing the same VID:PID —
        // /dev/video0 (RGB sensor, YUYV/MJPG) and /dev/video2 (IR sensor, native
        // GREY). A force_ir quirk means "this USB device has an IR sensor", NOT
        // "every capture node of it is IR": only the GREY-native node is IR.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(Some("GREY")));

        let rgb = device_at("/dev/video0", "Logitech BRIO", &["YUYV", "MJPG"]);
        let ir = device_at("/dev/video2", "Logitech BRIO", &["GREY"]);
        let devices = [rgb, ir];
        let ids = vec![brio_ids(), brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(
            sources[0],
            IrSource::None,
            "RGB sibling node must NOT classify IR"
        );
        assert_eq!(
            sources[1],
            IrSource::Quirk,
            "GREY-native node keeps quirk-IR classification"
        );

        // Auto-detect-equivalent selection must pick the IR (GREY) node, not
        // the first enumerated node (the RGB sensor with the white LED).
        let picked = pick_auto_device(&devices, &sources).expect("a device is picked");
        assert_eq!(picked.path, "/dev/video2");
    }

    #[test]
    fn brio_multi_node_disambiguates_without_format_preference() {
        // Even without format_preference on the quirk, the native GREY format
        // alone disambiguates the sibling nodes.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(None));

        let devices = [
            device_at("/dev/video0", "Logitech BRIO", &["YUYV", "MJPG"]),
            device_at("/dev/video2", "Logitech BRIO", &["GREY"]),
        ];
        let ids = vec![brio_ids(), brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(sources[0], IrSource::None);
        assert_eq!(sources[1], IrSource::Quirk);
    }

    #[test]
    fn quirk_multi_node_without_any_ir_format_trusts_force_ir_for_all() {
        // Edge case: some force_ir quirks exist precisely BECAUSE the camera
        // does not advertise an IR-like format. If no sibling node has one,
        // there is no format evidence to disambiguate — trust force_ir for all.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(None));

        let devices = [
            device_at("/dev/video0", "Some IR Module", &["YUYV"]),
            device_at("/dev/video2", "Some IR Module", &["MJPG"]),
        ];
        let ids = vec![brio_ids(), brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(sources[0], IrSource::Quirk);
        assert_eq!(sources[1], IrSource::Quirk);
        // With no format evidence, selection preserves enumeration order.
        let picked = pick_auto_device(&devices, &sources).expect("a device is picked");
        assert_eq!(picked.path, "/dev/video0");
    }

    #[test]
    fn quirk_single_node_without_ir_format_stays_ir() {
        // A single quirk-matched node with no IR-like format is the whole point
        // of force_ir — it must remain IR.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(None));

        let devices = [device_at("/dev/video0", "Oddball IR Module", &["YUYV"])];
        let ids = vec![brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(sources[0], IrSource::Quirk);
    }

    #[test]
    fn multi_node_demoted_sibling_keeps_name_heuristic() {
        // A demoted sibling falls back to the (quirk-free) heuristic: an IR
        // name token still classifies it, honestly, as Name.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(None));

        let devices = [
            device_at("/dev/video0", "Vendor IR Camera", &["YUYV"]),
            device_at("/dev/video2", "Vendor IR Camera", &["GREY"]),
        ];
        let ids = vec![brio_ids(), brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(sources[0], IrSource::Name);
        assert_eq!(sources[1], IrSource::Quirk);
        // Selection still prefers the format-corroborated quirk node.
        let picked = pick_auto_device(&devices, &sources).expect("a device is picked");
        assert_eq!(picked.path, "/dev/video2");
    }

    #[test]
    fn classify_without_usb_ids_leaves_quirk_nodes_alone() {
        // Nodes whose USB identity is unreadable cannot be grouped as siblings;
        // a name-pattern quirk match stays authoritative (current behavior).
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(crate::quirks::Quirk {
            vendor_id: None,
            product_id: None,
            name_pattern: Some("(?i)generic".into()),
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: None,
        });

        let devices = [
            device_at("/dev/video0", "Generic Camera", &["YUYV"]),
            device_at("/dev/video2", "Generic Camera", &["GREY"]),
        ];
        let ids = vec![None, None];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        assert_eq!(sources[0], IrSource::Quirk);
        assert_eq!(sources[1], IrSource::Quirk);
    }

    #[test]
    fn classify_mixed_identities_only_groups_same_usb_device() {
        // Two DIFFERENT USB cameras (different VID:PID) both quirk-matched:
        // no cross-device demotion may happen.
        let mut db = crate::quirks::QuirksDb::default();
        db.push_quirk_for_test(brio_quirk(None));
        db.push_quirk_for_test(crate::quirks::Quirk {
            vendor_id: Some("8086".into()),
            product_id: Some("0b07".into()),
            name_pattern: None,
            force_ir: Some(true),
            emitter_xu_guid: None,
            emitter_xu_selector: None,
            warmup_frames: None,
            format_preference: None,
            rotation: None,
            notes: None,
        });
        let devices = [
            device_at("/dev/video0", "RealSense", &["YUYV"]),
            device_at("/dev/video2", "Logitech BRIO", &["GREY"]),
        ];
        let ids = vec![Some(("8086".into(), "0b07".into())), brio_ids()];

        let sources = classify_ir_sources_with_ids(&devices, Some(&db), &ids);
        // Different physical devices — both keep their quirk classification.
        assert_eq!(sources[0], IrSource::Quirk);
        assert_eq!(sources[1], IrSource::Quirk);
    }

    #[test]
    fn list_devices_does_not_crash() {
        // Should return Ok even if no devices exist
        let result = list_devices();
        assert!(result.is_ok());
    }
}
