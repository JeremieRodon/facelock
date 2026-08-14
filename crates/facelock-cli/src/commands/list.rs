use anyhow::Context;
use chrono::{Local, TimeZone};

use facelock_core::Config;
use facelock_core::ipc::{DaemonRequest, DaemonResponse};
use facelock_core::types::FaceModelInfo;

use crate::ipc_client;

pub fn run(user: Option<String>, json: bool) -> anyhow::Result<()> {
    // DEC-6/N4: `ListModels` is root-only now (was facelock-group). The
    // direct-mode fallback in `fetch_models` already required root when the
    // 0600 root:root database wasn't readable; checking up front here gives
    // the same interactive escalation prompt on the D-Bus path too, instead
    // of a bare AccessDenied.
    ipc_client::require_root("sudo facelock list")?;

    let config = Config::load().context("failed to load config")?;
    let user = ipc_client::resolve_user(user.as_deref());

    let models = fetch_models(&config, &user)?;

    if json {
        print_json(&models);
    } else {
        print_table(&user, &models);
    }

    Ok(())
}

fn fetch_models(config: &Config, user: &str) -> anyhow::Result<Vec<FaceModelInfo>> {
    // Try D-Bus first — `run` already required root above.
    if !ipc_client::should_use_direct(config) {
        let request = DaemonRequest::ListModels {
            user: user.to_string(),
        };
        let response = ipc_client::send_request(&request)?;
        return match response {
            DaemonResponse::Models(models) => Ok(models),
            other => anyhow::bail!("unexpected response from daemon: {other:?}"),
        };
    }

    // Direct mode: needs read access to the 0600 root:root database.
    let store = crate::direct::open_store(config)?;
    store.list_models(user).map_err(|e| anyhow::anyhow!("{e}"))
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

fn print_json(models: &[FaceModelInfo]) {
    println!("[");
    for (i, model) in models.iter().enumerate() {
        let comma = if i + 1 < models.len() { "," } else { "" };
        let device_id = model.device_id.as_deref().unwrap_or("");
        println!(
            "  {{\"id\": {}, \"label\": \"{}\", \"user\": \"{}\", \"created_at\": {}, \"embedder_model\": \"{}\", \"device_id\": \"{}\"}}{}",
            model.id,
            model.label,
            model.user,
            model.created_at,
            model.embedder_model,
            device_id,
            comma
        );
    }
    println!("]");
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
}
