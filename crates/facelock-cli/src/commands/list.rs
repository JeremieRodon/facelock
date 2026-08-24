use chrono::{Local, TimeZone};

use facelock_core::Config;
use facelock_core::types::FaceModelInfo;

use crate::backend::Backend;
use crate::ipc_client;

pub fn run(config: &Config, user: Option<String>, json: bool) -> anyhow::Result<()> {
    // DEC-6/N4: `ListModels` is root-only now (was facelock-group) — the
    // direct fallback needs read access to the 0600 root:root database.
    // Root is established by `main`'s `require_root_for` gate, ahead of the
    // config parse (C6, issue #191), so escalation — or refusal — has
    // already happened by the time this runs.
    let user = ipc_client::resolve_user(user.as_deref());

    // One selection, one list operation (D1). The seam's direct read opens
    // the existing store — a fresh install lists as empty without an empty
    // database materializing at the path as a side effect.
    let backend = Backend::select(config);
    let models = backend.list_models(&user)?;

    if json {
        print_json(&models);
    } else {
        print_table(&user, &models);
    }

    Ok(())
}

fn print_table(user: &str, models: &[FaceModelInfo]) {
    if models.is_empty() {
        println!("No face models enrolled for user '{user}'.");
        return;
    }

    println!("Face models for user '{user}':\n");
    println!(
        "  {:<6} {:<20} {:<24} {:<22} Camera",
        "ID", "Label", "Created", "Model"
    );
    println!("  {}", "-".repeat(92));

    for model in models {
        let created = format_timestamp(model.created_at);
        let model_name = if model.embedder_model.is_empty() {
            "(legacy)".to_string()
        } else {
            model.embedder_model.clone()
        };
        // Device fingerprint of the enrolling camera (Plan 02). "(any)" means a
        // legacy/uncoupled template that authenticates on any camera.
        let camera = match model.device_id.as_deref() {
            Some(id) if !id.is_empty() => id.to_string(),
            _ => "(any)".to_string(),
        };
        println!(
            "  {:<6} {:<20} {:<24} {:<22} {}",
            model.id, model.label, created, model_name, camera
        );
    }

    println!("\n  Total: {} model(s)", models.len());
}

/// The `--json` payload, through the seam's machine sink: never localized,
/// and silenced by `--quiet` like every other payload (before #140 this
/// command ignored the flag outright).
fn print_json(models: &[FaceModelInfo]) {
    crate::message::payload(&list_json(models));
}

/// `[{"id", "label", "user", "created_at", "embedder_model", "device_id"}, ...]`.
///
/// Built through `serde_json::json!` (same pattern as
/// `commands::is_enrolled::enrolled_json`) rather than interpolating fields
/// into a `format!` string: `label`, `user`, and `embedder_model` are not
/// trusted to be free of `"` or `\` (E10) — a `format!` version emits invalid
/// JSON for a label like `my "favorite" face`, which `json!` escapes
/// correctly. `device_id` renders as `""` rather than `null` for a legacy
/// row, matching the pre-existing output contract.
fn list_json(models: &[FaceModelInfo]) -> String {
    let values: Vec<serde_json::Value> = models
        .iter()
        .map(|model| {
            let device_id = model.device_id.as_deref().unwrap_or("");
            serde_json::json!({
                "id": model.id,
                "label": model.label,
                "user": model.user,
                "created_at": model.created_at,
                "embedder_model": model.embedder_model,
                "device_id": device_id,
            })
        })
        .collect();
    serde_json::Value::Array(values).to_string()
}

fn format_timestamp(unix_ts: u64) -> String {
    match Local.timestamp_opt(unix_ts as i64, 0) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        _ => unix_ts.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_timestamp_valid() {
        let formatted = format_timestamp(1700000000);
        assert!(formatted.contains("2023"), "expected 2023 in {formatted}");
    }

    #[test]
    fn format_timestamp_zero() {
        let formatted = format_timestamp(0);
        assert!(
            formatted.contains("1970") || formatted.contains("1969"),
            "expected 1970 or 1969 (timezone-dependent) in {formatted}"
        );
    }

    fn model(label: &str, device_id: Option<&str>) -> FaceModelInfo {
        FaceModelInfo {
            id: 1,
            user: "alice".to_string(),
            label: label.to_string(),
            created_at: 1700000000,
            embedder_model: "w600k_r50.onnx".to_string(),
            device_id: device_id.map(str::to_string),
        }
    }

    /// The regression this fixes (E10): the old `format!`-based `print_json`
    /// interpolated `label` directly into a JSON string literal, so a label
    /// containing `"` produced invalid JSON. `list_json` must still parse and
    /// must preserve the label's exact text.
    #[test]
    fn json_escapes_a_label_containing_a_quote() {
        let models = vec![model(r#"my "favorite" face"#, None)];
        let rendered = list_json(&models);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("must be valid JSON");
        assert_eq!(parsed[0]["label"], r#"my "favorite" face"#);
    }

    #[test]
    fn json_escapes_a_label_containing_a_backslash() {
        let models = vec![model(r"back\slash", None)];
        let rendered = list_json(&models);
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("must be valid JSON");
        assert_eq!(parsed[0]["label"], r"back\slash");
    }

    #[test]
    fn json_output_matches_the_documented_shape() {
        let models = vec![model("front", Some("046d:085e:abc123"))];
        let rendered = list_json(&models);
        assert_eq!(
            rendered,
            r#"[{"created_at":1700000000,"device_id":"046d:085e:abc123","embedder_model":"w600k_r50.onnx","id":1,"label":"front","user":"alice"}]"#
        );
    }

    #[test]
    fn json_renders_a_legacy_null_device_id_as_empty_string() {
        let models = vec![model("front", None)];
        let rendered = list_json(&models);
        let parsed: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(parsed[0]["device_id"], "");
    }

    #[test]
    fn json_output_is_an_empty_array_when_no_models() {
        assert_eq!(list_json(&[]), "[]");
    }
}
