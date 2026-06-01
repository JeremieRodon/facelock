use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, bail};
use clap::Subcommand;

const FACE_ICON: &str = "\u{f0100}";
const FP_ICON: &str = "\u{f0237}";
const BACKUP_SUFFIX: &str = ".facelock-backup";
const PAM_HYPRLOCK_PATH: &str = "/etc/pam.d/hyprlock";

#[derive(Subcommand)]
pub enum HyprlockCommand {
    /// Add face icon and enable empty-Enter submission in hyprlock.conf
    Enable,
    /// Remove face icon and (if no fingerprint coexists) restore ignore_empty_input
    Disable,
    /// Show current hyprlock integration state
    Status,
}

pub fn run(command: HyprlockCommand) -> anyhow::Result<()> {
    if nix::unistd::Uid::current().is_root() {
        bail!(
            "facelock hyprlock must run as your normal user (it edits files under $HOME).\n\
             If invoked via sudo, re-run without sudo."
        );
    }

    let conf_path = locate_hyprlock_conf()?;

    match command {
        HyprlockCommand::Enable => enable(&conf_path),
        HyprlockCommand::Disable => disable(&conf_path),
        HyprlockCommand::Status => status(&conf_path),
    }
}

fn locate_hyprlock_conf() -> anyhow::Result<PathBuf> {
    let config_home = env::var_os("XDG_CONFIG_HOME")
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .context("could not determine XDG_CONFIG_HOME or HOME")?;
    let path = config_home.join("hypr").join("hyprlock.conf");
    if !path.exists() {
        bail!(
            "hyprlock config not found at {}.\n\
             Install hyprlock and create the config first.",
            path.display()
        );
    }
    Ok(path)
}

fn enable(path: &Path) -> anyhow::Result<()> {
    let original = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let backup_path = backup_path(path);
    if !backup_path.exists() {
        fs::copy(path, &backup_path)
            .with_context(|| format!("failed to back up {}", path.display()))?;
        println!("Backed up {} -> {}", path.display(), backup_path.display());
    }

    let (after_placeholder, placeholder_changed, already_face) = add_face_icon(&original);
    let (after_general, general_changed) = set_ignore_empty_input(&after_placeholder, false);

    if !placeholder_changed && !general_changed && already_face {
        println!("Face icon already present and ignore_empty_input already false.");
        return Ok(());
    }

    fs::write(path, &after_general)
        .with_context(|| format!("failed to write {}", path.display()))?;

    if already_face {
        println!("Face icon already present in placeholder_text.");
    } else if placeholder_changed {
        println!("Added face icon to placeholder_text.");
    }
    if general_changed {
        println!("Set general.ignore_empty_input = false.");
    } else {
        println!("general.ignore_empty_input already false.");
    }

    Ok(())
}

fn disable(path: &Path) -> anyhow::Result<()> {
    let original = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let (after_placeholder, placeholder_changed) = remove_face_icon(&original);

    let fp_in_pam = pam_has_fingerprint(Path::new(PAM_HYPRLOCK_PATH));
    let fp_in_conf = conf_has_fingerprint_enabled(&after_placeholder);
    let fingerprint_present = fp_in_pam || fp_in_conf;

    let (final_content, general_changed) = if fingerprint_present {
        (after_placeholder, false)
    } else {
        set_ignore_empty_input(&after_placeholder, true)
    };

    if !placeholder_changed && !general_changed {
        println!("Face icon not present and ignore_empty_input unchanged. Nothing to do.");
        return Ok(());
    }

    fs::write(path, &final_content)
        .with_context(|| format!("failed to write {}", path.display()))?;

    if placeholder_changed {
        println!("Removed face icon from placeholder_text.");
    }
    if general_changed {
        println!("Restored general.ignore_empty_input = true.");
    } else if fingerprint_present {
        // Coexistence note: hyprlock needs ignore_empty_input=false to dispatch empty
        // Enter to PAM, which is what triggers pam_fprintd / pam_facelock without a
        // typed password.
        println!(
            "Fingerprint integration detected — leaving ignore_empty_input alone so fingerprint still works."
        );
    }

    let backup = backup_path(path);
    if backup.exists() {
        println!(
            "Backup left in place at {} (delete manually if no longer needed).",
            backup.display()
        );
    }

    Ok(())
}

fn status(path: &Path) -> anyhow::Result<()> {
    let content = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let placeholder = extract_placeholder_text(&content);
    let face_present = placeholder
        .as_deref()
        .is_some_and(|p| p.contains(FACE_ICON));
    let fp_present = placeholder
        .as_deref()
        .is_some_and(|p| p.contains(FP_ICON));
    let ignore_empty = extract_ignore_empty_input(&content);
    let pam_face = pam_contains(Path::new(PAM_HYPRLOCK_PATH), "pam_facelock.so");
    let pam_fp = pam_contains(Path::new(PAM_HYPRLOCK_PATH), "pam_fprintd.so");

    println!("hyprlock.conf:        {}", path.display());
    println!(
        "placeholder_text:     {}",
        placeholder.as_deref().unwrap_or("<missing>")
    );
    println!(
        "  face icon ({}): {}",
        FACE_ICON,
        if face_present { "yes" } else { "no" }
    );
    println!(
        "  fingerprint icon ({}): {}",
        FP_ICON,
        if fp_present { "yes" } else { "no" }
    );
    println!(
        "ignore_empty_input:   {}",
        match ignore_empty {
            Some(true) => "true",
            Some(false) => "false",
            None => "<not set>",
        }
    );
    println!("PAM /etc/pam.d/hyprlock:");
    println!(
        "  pam_facelock.so:    {}",
        if pam_face { "yes" } else { "no" }
    );
    println!(
        "  pam_fprintd.so:     {}",
        if pam_fp { "yes" } else { "no" }
    );

    let backup = backup_path(path);
    if backup.exists() {
        println!("backup file:          {}", backup.display());
    }

    Ok(())
}

fn backup_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(BACKUP_SUFFIX);
    PathBuf::from(s)
}

fn add_face_icon(input: &str) -> (String, bool, bool) {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;
    let mut already = false;
    let mut found_any = false;

    for line in input.lines() {
        let trimmed = line.trim_start();
        if !found_any && trimmed.starts_with("placeholder_text") && trimmed.contains('=') {
            found_any = true;
            if trimmed.contains(FACE_ICON) {
                already = true;
                out.push_str(line);
                out.push('\n');
                continue;
            }
            let has_fp = trimmed.contains(FP_ICON);
            let indent = &line[..line.len() - trimmed.len()];
            let new_value = if has_fp {
                format!("<span> Enter Password {FACE_ICON} {FP_ICON} </span>")
            } else {
                format!("<span> Enter Password {FACE_ICON} </span>")
            };
            out.push_str(indent);
            out.push_str(&format!("placeholder_text = {new_value}\n"));
            changed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    preserve_trailing_newline(input, &mut out);
    (out, changed, already)
}

fn remove_face_icon(input: &str) -> (String, bool) {
    let mut out = String::with_capacity(input.len());
    let mut changed = false;

    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("placeholder_text")
            && trimmed.contains('=')
            && trimmed.contains(FACE_ICON)
        {
            let has_fp = trimmed.contains(FP_ICON);
            let indent = &line[..line.len() - trimmed.len()];
            let new_value = if has_fp {
                format!("<span> Enter Password {FP_ICON} </span>")
            } else {
                "Enter Password".to_string()
            };
            out.push_str(indent);
            out.push_str(&format!("placeholder_text = {new_value}\n"));
            changed = true;
        } else {
            out.push_str(line);
            out.push('\n');
        }
    }

    preserve_trailing_newline(input, &mut out);
    (out, changed)
}

fn set_ignore_empty_input(input: &str, value: bool) -> (String, bool) {
    let target = if value { "true" } else { "false" };
    let current = extract_ignore_empty_input(input);
    if current == Some(value) {
        return (input.to_string(), false);
    }

    if current.is_some() {
        let mut out = String::with_capacity(input.len());
        for line in input.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("ignore_empty_input") && trimmed.contains('=') {
                let indent = &line[..line.len() - trimmed.len()];
                out.push_str(indent);
                out.push_str(&format!("ignore_empty_input = {target}\n"));
            } else {
                out.push_str(line);
                out.push('\n');
            }
        }
        preserve_trailing_newline(input, &mut out);
        return (out, true);
    }

    if let Some(injected) = inject_into_general_block(input, target) {
        return (injected, true);
    }

    let mut out = String::new();
    out.push_str("general {\n");
    out.push_str(&format!("    ignore_empty_input = {target}\n"));
    out.push_str("}\n\n");
    out.push_str(input);
    (out, true)
}

fn inject_into_general_block(input: &str, target: &str) -> Option<String> {
    let lines: Vec<&str> = input.lines().collect();
    let mut header_idx = None;
    for (i, line) in lines.iter().enumerate() {
        let t = line.trim();
        if t == "general {" || t.starts_with("general {") || t == "general{" {
            header_idx = Some(i);
            break;
        }
    }
    let header_idx = header_idx?;

    let mut close_idx = None;
    let mut depth = 1usize;
    for (i, line) in lines.iter().enumerate().skip(header_idx + 1) {
        let t = line.trim();
        if t.starts_with('}') {
            depth -= 1;
            if depth == 0 {
                close_idx = Some(i);
                break;
            }
        } else if t.ends_with('{') {
            depth += 1;
        }
    }
    let close_idx = close_idx?;

    let mut out_lines: Vec<String> = lines.iter().map(|s| s.to_string()).collect();
    out_lines.insert(
        close_idx,
        format!("    ignore_empty_input = {target}"),
    );

    let mut joined = out_lines.join("\n");
    if input.ends_with('\n') {
        joined.push('\n');
    }
    Some(joined)
}

fn preserve_trailing_newline(input: &str, out: &mut String) {
    if !input.ends_with('\n') && out.ends_with('\n') {
        out.pop();
    }
}

fn extract_placeholder_text(input: &str) -> Option<String> {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("placeholder_text")
            && let Some(idx) = rest.find('=')
        {
            return Some(rest[idx + 1..].trim().to_string());
        }
    }
    None
}

fn extract_ignore_empty_input(input: &str) -> Option<bool> {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if let Some(rest) = trimmed.strip_prefix("ignore_empty_input")
            && let Some(idx) = rest.find('=')
        {
            let val = rest[idx + 1..].trim();
            return match val {
                "true" | "1" | "yes" => Some(true),
                "false" | "0" | "no" => Some(false),
                _ => None,
            };
        }
    }
    None
}

fn conf_has_fingerprint_enabled(input: &str) -> bool {
    for line in input.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("fingerprint:enabled")
            && let Some(idx) = rest.find('=')
        {
            let val = rest[idx + 1..].trim();
            if matches!(val, "true" | "1" | "yes") {
                return true;
            }
        }
    }
    false
}

fn pam_has_fingerprint(path: &Path) -> bool {
    pam_contains(path, "pam_fprintd.so")
}

fn pam_contains(path: &Path, needle: &str) -> bool {
    let Ok(content) = fs::read_to_string(path) else {
        return false;
    };
    content
        .lines()
        .any(|l| !l.trim_start().starts_with('#') && l.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOCK_OMARCHY: &str = "general {\n    grace = 0\n    hide_cursor = true\n    ignore_empty_input = true\n}\n\ninput-field {\n    placeholder_text = Enter Password\n}\n";

    #[test]
    fn enable_stock_omarchy_adds_icon_and_flips_flag() {
        let (after, changed, already) = add_face_icon(STOCK_OMARCHY);
        assert!(changed);
        assert!(!already);
        assert!(after.contains(FACE_ICON));
        assert!(after.contains("Enter Password"));

        let (after2, flag_changed) = set_ignore_empty_input(&after, false);
        assert!(flag_changed);
        assert!(after2.contains("ignore_empty_input = false"));
        assert!(!after2.contains("ignore_empty_input = true"));
    }

    #[test]
    fn enable_preserves_fingerprint_icon() {
        let input = format!(
            "input-field {{\n    placeholder_text = <span> Enter Password {FP_ICON} </span>\n}}\n"
        );
        let (after, changed, already) = add_face_icon(&input);
        assert!(changed);
        assert!(!already);
        assert!(after.contains(FACE_ICON));
        assert!(after.contains(FP_ICON));
    }

    #[test]
    fn enable_is_idempotent() {
        let (after, _, _) = add_face_icon(STOCK_OMARCHY);
        let (after2, changed, already) = add_face_icon(&after);
        assert!(!changed);
        assert!(already);
        assert_eq!(after, after2);

        let (flag1, _) = set_ignore_empty_input(&after, false);
        let (flag2, changed) = set_ignore_empty_input(&flag1, false);
        assert!(!changed);
        assert_eq!(flag1, flag2);
    }

    #[test]
    fn disable_removes_face_icon_preserves_fingerprint() {
        let input = format!(
            "input-field {{\n    placeholder_text = <span> Enter Password {FACE_ICON} {FP_ICON} </span>\n}}\n"
        );
        let (after, changed) = remove_face_icon(&input);
        assert!(changed);
        assert!(!after.contains(FACE_ICON));
        assert!(after.contains(FP_ICON));
    }

    #[test]
    fn disable_restores_ignore_empty_when_no_fingerprint() {
        let input = format!(
            "general {{\n    ignore_empty_input = false\n}}\n\ninput-field {{\n    placeholder_text = <span> Enter Password {FACE_ICON} </span>\n}}\n"
        );
        let (after, _) = remove_face_icon(&input);
        let (after2, changed) = set_ignore_empty_input(&after, true);
        assert!(changed);
        assert!(after2.contains("ignore_empty_input = true"));
    }

    #[test]
    fn disable_preserves_ignore_empty_when_fingerprint_enabled_in_conf() {
        let input = format!(
            "general {{\n    ignore_empty_input = false\n    fingerprint:enabled = true\n}}\n\ninput-field {{\n    placeholder_text = <span> Enter Password {FACE_ICON} {FP_ICON} </span>\n}}\n"
        );
        assert!(conf_has_fingerprint_enabled(&input));
        let (after, _) = remove_face_icon(&input);
        assert!(conf_has_fingerprint_enabled(&after));
        assert_eq!(extract_ignore_empty_input(&after), Some(false));
    }

    #[test]
    fn missing_general_block_is_prepended() {
        let input = "input-field {\n    placeholder_text = Enter Password\n}\n";
        let (after, changed) = set_ignore_empty_input(input, false);
        assert!(changed);
        assert!(after.starts_with("general {"));
        assert!(after.contains("ignore_empty_input = false"));
        assert!(after.contains("input-field {"));
    }

    #[test]
    fn existing_general_with_other_keys_only_touches_target() {
        let input = "general {\n    grace = 5\n    hide_cursor = true\n}\n";
        let (after, changed) = set_ignore_empty_input(input, false);
        assert!(changed);
        assert!(after.contains("grace = 5"));
        assert!(after.contains("hide_cursor = true"));
        assert!(after.contains("ignore_empty_input = false"));
    }

    #[test]
    fn extract_placeholder_and_flag() {
        assert_eq!(
            extract_placeholder_text("    placeholder_text = Enter Password\n"),
            Some("Enter Password".to_string())
        );
        assert_eq!(
            extract_ignore_empty_input("    ignore_empty_input = false\n"),
            Some(false)
        );
        assert_eq!(
            extract_ignore_empty_input("    ignore_empty_input = true\n"),
            Some(true)
        );
        assert_eq!(extract_ignore_empty_input("nothing here"), None);
    }

    #[test]
    fn fingerprint_enabled_detection() {
        assert!(conf_has_fingerprint_enabled("fingerprint:enabled = true\n"));
        assert!(!conf_has_fingerprint_enabled(
            "fingerprint:enabled = false\n"
        ));
        assert!(!conf_has_fingerprint_enabled(
            "# fingerprint:enabled = true\n"
        ));
    }

    #[test]
    fn pam_contains_via_tempfile() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hyprlock");
        std::fs::write(&path, "auth required pam_unix.so\nauth sufficient pam_fprintd.so\n")
            .unwrap();
        assert!(pam_has_fingerprint(&path));
        assert!(pam_contains(&path, "pam_unix.so"));
        assert!(!pam_contains(&path, "pam_facelock.so"));
    }

    #[test]
    fn end_to_end_via_tempfile() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hyprlock.conf");
        std::fs::write(&path, STOCK_OMARCHY).unwrap();

        let content = std::fs::read_to_string(&path).unwrap();
        let (a, _, _) = add_face_icon(&content);
        let (b, _) = set_ignore_empty_input(&a, false);
        std::fs::write(&path, &b).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains(FACE_ICON));
        assert!(after.contains("ignore_empty_input = false"));

        let (c, _) = remove_face_icon(&after);
        let (d, _) = set_ignore_empty_input(&c, true);
        std::fs::write(&path, &d).unwrap();

        let final_content = std::fs::read_to_string(&path).unwrap();
        assert!(!final_content.contains(FACE_ICON));
        assert!(final_content.contains("ignore_empty_input = true"));
    }
}
