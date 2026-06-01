use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, bail};
use clap::Subcommand;

const FACE_ICON: &str = "\u{f0100}";
const FP_ICON: &str = "\u{f0237}";
const BACKUP_SUFFIX: &str = ".facelock-backup";
const PAM_HYPRLOCK_PATH: &str = "/etc/pam.d/hyprlock";
/// Hyprlock's stock font and the most common Hyprland/Omarchy default.
const DEFAULT_HYPRLOCK_FONT: &str = "JetBrainsMono Nerd Font";

#[derive(Subcommand)]
pub enum HyprlockCommand {
    /// Add face icon and enable empty-Enter submission in hyprlock.conf
    Enable {
        /// Skip the cosmetic face icon; only set ignore_empty_input = false.
        /// Useful when your hyprlock font isn't a Nerd Font.
        #[arg(long)]
        no_icon: bool,
    },
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
        HyprlockCommand::Enable { no_icon } => enable(&conf_path, no_icon),
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

fn enable(path: &Path, no_icon: bool) -> anyhow::Result<()> {
    let original = fs::read_to_string(path)
        .with_context(|| format!("failed to read {}", path.display()))?;

    let backup_path = backup_path(path);
    if !backup_path.exists() {
        fs::copy(path, &backup_path)
            .with_context(|| format!("failed to back up {}", path.display()))?;
        println!("Backed up {} -> {}", path.display(), backup_path.display());
    }

    // When --no-icon is passed, leave placeholder_text alone entirely. An existing
    // face icon stays put (use `disable` to remove it); we only flip the functional
    // flag. The font check is skipped because no glyph will be rendered by us.
    let (after_placeholder, placeholder_changed, already_face) = if no_icon {
        (original.clone(), false, false)
    } else {
        add_face_icon(&original)
    };
    let (after_general, general_changed) = set_ignore_empty_input(&after_placeholder, false);

    if !placeholder_changed && !general_changed && (no_icon || already_face) {
        if no_icon {
            println!("Skipping icon (--no-icon). ignore_empty_input already false.");
        } else {
            println!("Face icon already present and ignore_empty_input already false.");
        }
        return Ok(());
    }

    fs::write(path, &after_general)
        .with_context(|| format!("failed to write {}", path.display()))?;

    if no_icon {
        println!("Skipping icon (--no-icon); placeholder_text untouched.");
    } else if already_face {
        println!("Face icon already present in placeholder_text.");
    } else if placeholder_changed {
        println!("Added face icon to placeholder_text.");
    }
    if general_changed {
        println!("Set general.ignore_empty_input = false.");
    } else {
        println!("general.ignore_empty_input already false.");
    }

    // Font check only makes sense if we're adding/expecting an icon to render.
    if !no_icon {
        let font = extract_font_family(&original)
            .unwrap_or_else(|| DEFAULT_HYPRLOCK_FONT.to_string());
        report_font_status(&font, check_font(&font));
    }

    Ok(())
}

fn report_font_status(font: &str, status: FontStatus) {
    match status {
        FontStatus::Installed => {}
        FontStatus::Substituted { resolved_to } => {
            println!();
            println!(
                "Note: hyprlock font '{font}' is not installed (fontconfig substituted '{resolved_to}')."
            );
            println!(
                "      The face icon will render as a missing-glyph box until you install a Nerd Font."
            );
            println!("      Arch:   sudo pacman -S ttf-jetbrains-mono-nerd");
            println!("      Debian: sudo apt install fonts-jetbrains-mono");
            println!("      The functional integration still works; this is cosmetic.");
            println!("      Re-run with `--no-icon` to skip the icon entirely.");
        }
        FontStatus::FcMatchMissing => {
            println!();
            println!(
                "Note: fontconfig (`fc-match`) not found — cannot verify Nerd Font availability."
            );
            println!(
                "      If the face icon renders as a box, install a Nerd Font for your hyprlock font."
            );
        }
    }
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

    let font = extract_font_family(&content).unwrap_or_else(|| DEFAULT_HYPRLOCK_FONT.to_string());
    match check_font(&font) {
        FontStatus::Installed => {
            println!("font ({font}):        installed");
        }
        FontStatus::Substituted { resolved_to } => {
            println!(
                "font ({font}):        NOT installed (substituted '{resolved_to}'); icon may render as box"
            );
        }
        FontStatus::FcMatchMissing => {
            println!("font ({font}):        fc-match not available");
        }
    }

    let backup = backup_path(path);
    if backup.exists() {
        println!("backup file:          {}", backup.display());
    }

    Ok(())
}

/// Resolved state of the hyprlock font, as reported by fontconfig.
#[derive(Debug, PartialEq, Eq)]
enum FontStatus {
    /// fontconfig returned a family that matches the requested name.
    Installed,
    /// fontconfig substituted a different family — the icon will likely render
    /// as a missing-glyph box unless that fallback is itself a Nerd Font.
    Substituted { resolved_to: String },
    /// `fc-match` not on PATH (fontconfig not installed).
    FcMatchMissing,
}

/// Look up the requested font family via `fc-match` and report whether it
/// actually resolves to itself (installed) or to a different family
/// (substituted). Tests don't shell out — see `font_resolves_to_match` for
/// the comparison logic.
fn check_font(requested: &str) -> FontStatus {
    let output = match Command::new("fc-match")
        .args(["-f", "%{family}\n", requested])
        .output()
    {
        Ok(o) => o,
        Err(_) => return FontStatus::FcMatchMissing,
    };
    if !output.status.success() {
        return FontStatus::FcMatchMissing;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let resolved = stdout.lines().next().unwrap_or("").trim().to_string();
    if font_resolves_to_match(requested, &resolved) {
        FontStatus::Installed
    } else {
        FontStatus::Substituted {
            resolved_to: resolved,
        }
    }
}

/// fontconfig may return a comma-separated alias list (e.g.
/// `"JetBrainsMono Nerd Font,JetBrainsMono NF"`). The font is considered
/// installed if the requested name matches (case-insensitively) any alias by
/// word-prefix in either direction. "Word-prefix" means one name is a
/// prefix of the other at a word boundary (space or end of string). This
/// handles the common cases:
///   requested "JetBrains Mono"  resolved "JetBrains Mono NL"             -> match (req prefix of alias)
///   requested "JetBrains Mono Nerd Font" resolved "JetBrains Mono"       -> match (alias prefix of req)
///   requested "JetBrainsMono Nerd Font" resolved "JetBrainsMono Nerd Font" -> match (exact)
///   requested "Sans"            resolved "Liberation Sans"               -> no match
///   requested "DefinitelyNotAFont"      resolved "Liberation Sans"       -> no match
fn font_resolves_to_match(requested: &str, resolved: &str) -> bool {
    if resolved.trim().is_empty() {
        return false;
    }
    let req = requested.trim().to_ascii_lowercase();
    if req.is_empty() {
        return false;
    }
    resolved
        .split(',')
        .map(|s| s.trim().to_ascii_lowercase())
        .any(|alias| {
            if alias.is_empty() {
                return false;
            }
            // Exact match
            if alias == req {
                return true;
            }
            // alias is a word-boundary prefix of req: req starts with alias
            // followed by a space (e.g. req="JetBrains Mono Nerd Font", alias="JetBrains Mono")
            if req.starts_with(&alias)
                && req[alias.len()..].starts_with(' ')
            {
                return true;
            }
            // req is a word-boundary prefix of alias: alias starts with req
            // followed by a space (e.g. alias="JetBrains Mono NL", req="JetBrains Mono")
            if alias.starts_with(&req)
                && alias[req.len()..].starts_with(' ')
            {
                return true;
            }
            false
        })
}

/// Parse `font_family = X` from hyprlock.conf, preserving any quoting in the
/// value. Looks inside the first `input-field { ... }` block; ignores
/// `font_family` keys in other blocks (e.g. `label`). Returns None when no
/// override is set — callers should default to `DEFAULT_HYPRLOCK_FONT`.
fn extract_font_family(input: &str) -> Option<String> {
    let mut in_input_field = false;
    let mut depth = 0i32;
    for line in input.lines() {
        let trimmed = line.trim();
        if !in_input_field {
            if trimmed.starts_with("input-field") && trimmed.contains('{') {
                in_input_field = true;
                depth = 1;
            }
            continue;
        }
        // Track nested braces so we don't leave the block prematurely.
        for ch in trimmed.chars() {
            if ch == '{' {
                depth += 1;
            } else if ch == '}' {
                depth -= 1;
            }
        }
        if depth <= 0 {
            return None;
        }
        if let Some(rest) = trimmed.strip_prefix("font_family")
            && let Some(idx) = rest.find('=')
        {
            return Some(rest[idx + 1..].trim().to_string());
        }
    }
    None
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

    #[test]
    fn extract_font_family_absent_on_stock_omarchy() {
        assert_eq!(extract_font_family(STOCK_OMARCHY), None);
    }

    #[test]
    fn extract_font_family_with_spaces() {
        let input = "input-field {\n    font_family = JetBrainsMono Nerd Font\n}\n";
        assert_eq!(
            extract_font_family(input),
            Some("JetBrainsMono Nerd Font".to_string())
        );
    }

    #[test]
    fn extract_font_family_with_quotes_preserved() {
        let input = "input-field {\n    font_family = \"JetBrainsMono Nerd Font\"\n}\n";
        assert_eq!(
            extract_font_family(input),
            Some("\"JetBrainsMono Nerd Font\"".to_string())
        );
    }

    #[test]
    fn extract_font_family_ignores_other_blocks() {
        // font_family in a label block should not be returned; input-field has none.
        let input = "label {\n    font_family = Comic Sans\n    text = hi\n}\n\
                     input-field {\n    placeholder_text = Enter Password\n}\n";
        assert_eq!(extract_font_family(input), None);
    }

    #[test]
    fn extract_font_family_prefers_input_field_block() {
        let input = "label {\n    font_family = Comic Sans\n}\n\
                     input-field {\n    font_family = JetBrainsMono Nerd Font\n}\n";
        assert_eq!(
            extract_font_family(input),
            Some("JetBrainsMono Nerd Font".to_string())
        );
    }

    #[test]
    fn extract_font_family_no_input_field_block() {
        let input = "general {\n    grace = 0\n}\n";
        assert_eq!(extract_font_family(input), None);
    }

    #[test]
    fn font_match_exact_case_insensitive() {
        assert!(font_resolves_to_match(
            "JetBrainsMono Nerd Font",
            "JetBrainsMono Nerd Font"
        ));
        assert!(font_resolves_to_match(
            "jetbrainsmono nerd font",
            "JetBrainsMono Nerd Font"
        ));
    }

    #[test]
    fn font_match_alias_list() {
        // Real fc-match output for installed Nerd Font.
        assert!(font_resolves_to_match(
            "JetBrainsMono Nerd Font",
            "JetBrainsMono Nerd Font,JetBrainsMono NF"
        ));
    }

    #[test]
    fn font_match_substring_either_direction() {
        // Requested name contains resolved alias.
        assert!(font_resolves_to_match(
            "JetBrains Mono Nerd Font",
            "JetBrains Mono"
        ));
        // Resolved alias contains requested.
        assert!(font_resolves_to_match("JetBrains Mono", "JetBrains Mono NL"));
    }

    #[test]
    fn font_no_match_when_substituted() {
        // Typical "font missing" case: requested random name, fontconfig falls back.
        assert!(!font_resolves_to_match("Sans", "Liberation Sans"));
        assert!(!font_resolves_to_match(
            "JetBrainsMono Nerd Font",
            "DejaVu Sans"
        ));
        assert!(!font_resolves_to_match("DefinitelyNotAFont", "Liberation Sans"));
    }

    #[test]
    fn font_no_match_when_empty() {
        assert!(!font_resolves_to_match("Sans", ""));
        assert!(!font_resolves_to_match("", "Liberation Sans"));
    }

    #[test]
    fn enable_with_no_icon_skips_placeholder_flips_flag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hyprlock.conf");
        std::fs::write(&path, STOCK_OMARCHY).unwrap();

        enable(&path, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(!after.contains(FACE_ICON), "no icon expected with --no-icon");
        assert!(
            after.contains("placeholder_text = Enter Password"),
            "placeholder text should be untouched"
        );
        assert!(after.contains("ignore_empty_input = false"));
        assert!(!after.contains("ignore_empty_input = true"));
    }

    #[test]
    fn enable_with_no_icon_is_idempotent_and_preserves_existing_icon() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hyprlock.conf");
        // Start with face icon already present and ignore_empty_input = false.
        let preexisting = format!(
            "general {{\n    ignore_empty_input = false\n}}\n\n\
             input-field {{\n    placeholder_text = <span> Enter Password {FACE_ICON} </span>\n}}\n"
        );
        std::fs::write(&path, &preexisting).unwrap();

        // --no-icon should NOT remove the existing icon (that's disable's job).
        enable(&path, true).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(
            after.contains(FACE_ICON),
            "existing face icon must be preserved under --no-icon"
        );
        assert!(after.contains("ignore_empty_input = false"));
    }

    #[test]
    fn enable_without_no_icon_adds_icon_and_flips_flag() {
        let tmp = tempfile::TempDir::new().unwrap();
        let path = tmp.path().join("hyprlock.conf");
        std::fs::write(&path, STOCK_OMARCHY).unwrap();

        enable(&path, false).unwrap();

        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains(FACE_ICON));
        assert!(after.contains("ignore_empty_input = false"));
    }
}
