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

/// Classify a device's IR provenance, honoring the quirks DB as authoritative.
///
/// Decision rules (H1 fix — mere *availability* of GREY/Y16 is NOT proof of IR):
/// 1. A quirks DB `force_ir` value is authoritative in both directions.
/// 2. A native IR capture format (GREY/Y16) counts only when corroborated by an
///    IR name token → [`IrSource::Format`].
/// 3. An IR name token alone → [`IrSource::Name`].
/// 4. Otherwise → [`IrSource::None`] (a plain RGB webcam that merely enumerates
///    GREY is not treated as IR).
pub fn ir_source_with_quirks(
    device: &DeviceInfo,
    quirks: Option<&crate::quirks::QuirksDb>,
) -> IrSource {
    // 1. Quirks database is authoritative (both true and false).
    if let Some(db) = quirks {
        if let Some(quirk) = db.find_match(device) {
            if let Some(force_ir) = quirk.force_ir {
                return if force_ir {
                    IrSource::Quirk
                } else {
                    IrSource::None
                };
            }
        }
    }

    let has_ir_name = has_ir_name_token(&device.name);
    let has_ir_format = device
        .formats
        .iter()
        .any(|f| matches!(f.fourcc.as_str(), "GREY" | "Y16 "));

    match (has_ir_name, has_ir_format) {
        // Native IR format corroborated by the name token — strongest heuristic.
        (true, true) => IrSource::Format,
        // Name token alone is sufficient (e.g. "Infrared Camera").
        (true, false) => IrSource::Name,
        // Format alone (or nothing) is NOT sufficient — this is the H1 bypass fix.
        (false, _) => IrSource::None,
    }
}

/// Auto-detect the best available video capture device.
///
/// Prefers a quirks-confirmed IR device, then a heuristically-IR device (name
/// token), then falls back to the first enumerated device. It never auto-selects
/// an unknown camera *just because* it self-reports a GREY/Y16 format (H1).
///
/// NOTE (seam for Plan 02): device selection here is by capability/heuristic, not
/// by stable device identity. Plan 02 will pin the enrolled camera by identity.
pub fn auto_detect_device() -> Result<DeviceInfo> {
    let devices = list_devices()?;
    let quirks = crate::quirks::QuirksDb::load();
    devices
        .iter()
        .find(|d| ir_source_with_quirks(d, Some(&quirks)) == IrSource::Quirk)
        .or_else(|| {
            devices
                .iter()
                .find(|d| ir_source_with_quirks(d, Some(&quirks)) != IrSource::None)
        })
        .or_else(|| devices.first())
        .cloned()
        .ok_or_else(|| FacelockError::Camera("no video devices found".into()))
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

    #[test]
    fn list_devices_does_not_crash() {
        // Should return Ok even if no devices exist
        let result = list_devices();
        assert!(result.is_ok());
    }
}
