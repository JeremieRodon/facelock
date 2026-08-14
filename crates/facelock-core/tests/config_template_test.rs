//! Conformance test for gap E2: the shipped config template must parse to
//! exactly `Config::default()`, and every commented-out example value in it
//! must round-trip to the same default it documents. The template is not
//! just documentation — `%config(noreplace)` packaging ships this exact file
//! as `/etc/facelock/config.toml` on every fresh install, so drift here is a
//! drift in what a real installation actually does.
//!
//! `Config` derives neither `PartialEq` nor `Default` (and adding either is
//! outside this crate's test-only edit scope for this change), so this test
//! gets its "default" reference from `Config::parse("")` instead — every one
//! of `Config`'s 11 fields is `#[serde(default)]`, so an empty TOML document
//! parses to exactly what a `Config::default()` would produce if one
//! existed — and compares via `Debug` formatting, which is derived
//! everywhere `Config` nests.

use facelock_core::config::Config;

const TEMPLATE: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../config/facelock.toml"
));

fn debug_eq(a: &Config, b: &Config) -> bool {
    format!("{a:?}") == format!("{b:?}")
}

fn debug_diff(a: &Config, b: &Config) -> String {
    format!("parsed:\n{a:#?}\n\ndefault:\n{b:#?}")
}

/// What `Config::default()` would produce, obtained without one: every field
/// is `#[serde(default)]`, so an empty document is equivalent by construction.
fn expected_default() -> Config {
    Config::parse("").expect("an empty config document must always parse")
}

/// Three example lines in the template are deliberately **not** defaults:
/// `device.path` shows syntax for an explicit camera path (the real default
/// is "auto-detect", i.e. absent), and `recognition.detector_sha256` /
/// `embedder_sha256` ship the placeholder `"..."`, which is not valid hex and
/// must not be blindly uncommented. Skip these three by (section, key) while
/// building the "uncomment every example" variant of the template.
const NOT_DEFAULT_EXAMPLES: &[(&str, &str)] = &[
    ("device", "path"),
    ("recognition", "detector_sha256"),
    ("recognition", "embedder_sha256"),
];

/// A line's `#`-stripped remainder is a candidate to uncomment only if it is
/// exactly `[section.path]` or `key = value` with a bare, whitespace-free key
/// AND a syntactically plausible TOML value — otherwise it is prose. This
/// template has doc comments that legitimately contain `=` with a
/// key-shaped left side, e.g. "encryption.method = \"none\". Default
/// FALSE: ..." (bad value: trailing prose after the closing quote) or
/// "pcr_binding = true is ENFORCED: ..." (bad value: trailing prose after
/// `true`) — the value check is what rejects those.
fn assignment_key(rest: &str) -> Option<&str> {
    let (key, value) = rest.split_once('=')?;
    let key = key.trim();
    if key.is_empty() || key.split_whitespace().count() != 1 {
        return None;
    }
    if !key
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')
    {
        return None;
    }
    if !looks_like_toml_value(value) {
        return None;
    }
    Some(key)
}

/// Best-effort check that `value` is *just* a TOML scalar or array, with at
/// most a trailing `# comment` — not a scalar followed by run-on prose. Good
/// enough for this template's actual value shapes (quoted strings, bools,
/// numbers, string arrays); not a general TOML value parser.
fn looks_like_toml_value(raw_value: &str) -> bool {
    let value = raw_value.trim();
    if let Some(after_quote) = value.strip_prefix('"') {
        return match after_quote.find('"') {
            Some(idx) => {
                let trailing = after_quote[idx + 1..].trim();
                trailing.is_empty() || trailing.starts_with('#')
            }
            None => false,
        };
    }
    let value = match value.split_once('#') {
        Some((v, _)) => v.trim(),
        None => value,
    };
    value == "true"
        || value == "false"
        || (value.starts_with('[') && value.ends_with(']'))
        || value.parse::<f64>().is_ok()
}

/// Uncomment every commented-out example in the template except the
/// deliberately-non-default placeholders in [`NOT_DEFAULT_EXAMPLES`],
/// tracking the current `[section]` so keys reused across sections (e.g.
/// `path` under both `[device]` and `[audit]`) are only skipped where
/// documented as non-default.
fn uncomment_all_examples(template: &str) -> String {
    let mut current_section = String::new();
    let mut out = String::with_capacity(template.len());
    for line in template.lines() {
        let trimmed = line.trim_start();
        let indent = &line[..line.len() - trimmed.len()];
        let Some(rest) = trimmed.strip_prefix('#') else {
            // Already-active line (e.g. a bare `[section]` header) — track it too.
            if let Some(section) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                current_section = section.to_string();
            }
            out.push_str(line);
            out.push('\n');
            continue;
        };
        let rest = rest.strip_prefix(' ').unwrap_or(rest);

        if let Some(section) = rest.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            current_section = section.to_string();
            out.push_str(indent);
            out.push_str(rest);
            out.push('\n');
            continue;
        }

        if let Some(key) = assignment_key(rest) {
            if NOT_DEFAULT_EXAMPLES.contains(&(current_section.as_str(), key)) {
                out.push_str(line);
            } else {
                out.push_str(indent);
                out.push_str(rest);
            }
            out.push('\n');
            continue;
        }

        out.push_str(line);
        out.push('\n');
    }
    out
}

#[test]
fn shipped_template_parses_to_config_default() {
    // Byte-for-byte what a fresh install gets at /etc/facelock/config.toml.
    let parsed = Config::parse(TEMPLATE).expect("shipped template must parse");
    let default = expected_default();
    assert!(
        debug_eq(&parsed, &default),
        "shipped config/facelock.toml drifted from Config::default():\n{}",
        debug_diff(&parsed, &default)
    );
}

#[test]
fn every_documented_example_default_round_trips() {
    let expanded = uncomment_all_examples(TEMPLATE);
    let parsed = Config::parse(&expanded).unwrap_or_else(|e| {
        panic!(
            "uncommenting every documented example must still parse: {e}\n\n\
             --- expanded template ---\n{expanded}"
        )
    });
    let default = expected_default();
    assert!(
        debug_eq(&parsed, &default),
        "a commented-out example in config/facelock.toml documents a value \
         that is not actually Config::default() once uncommented:\n{}",
        debug_diff(&parsed, &default)
    );
}

#[test]
fn security_pam_policy_is_documented_but_owned_by_pam_facelock_not_core() {
    // `[security.pam_policy]` is real syntax (pam-facelock's own PamConfig
    // parses it — see the `shipped_config_template_parses_as_pam_config`
    // test in crates/pam-facelock/src/lib.rs) but facelock-core's `Config`
    // has no such field. `every_documented_example_default_round_trips`
    // above already proves core parses the section without error; this test
    // pins that it has zero effect on core's parsed result, which is the
    // load-bearing half of the contract (core must never reject a key that
    // belongs to PAM's schema).
    let with_pam_policy = r#"
[security.pam_policy]
allowed_services = ["sudo"]
denied_services = ["sshd"]
"#;
    let parsed =
        Config::parse(with_pam_policy).expect("unknown keys must be ignored, not rejected");
    assert!(debug_eq(&parsed, &expected_default()));
}

#[test]
fn placeholder_examples_are_intentionally_not_config_defaults() {
    // Documents *why* the three (section, key) pairs above are excluded from
    // every_documented_example_default_round_trips, as a live assertion
    // rather than just a comment: if either fact stops being true, this test
    // fails and the exclusion list needs to be revisited.
    let default = expected_default();
    assert!(
        default.device.path.is_none(),
        "device.path's real default is auto-detect (None); the template's \
         `path = \"/dev/video2\"` is a syntax example, not the default"
    );
    assert!(
        !is_sha256_hex("..."),
        "recognition.{{detector,embedder}}_sha256 examples ship the literal \
         placeholder \"...\", which Config::validate() rejects as not-hex — \
         it must stay commented, never blindly uncommented"
    );
}

fn is_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.chars().all(|c| c.is_ascii_hexdigit())
}
