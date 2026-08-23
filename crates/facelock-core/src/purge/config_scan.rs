//! Classification of configured paths against the compiled purge roots.
//!
//! Pure functions only; the descriptor-anchored read of
//! `/etc/facelock/config.toml` lives in the engine. Deviation from the Perl
//! reference: the maintainer script hand-parses TOML line by line because it
//! must run with no dependencies, and reports exotic-but-valid syntax as
//! unclassifiable. Here the real `toml` parser classifies every valid
//! document; only an unreadable or invalid document is unclassifiable.

/// The six configuration fields whose values may point outside the compiled
/// roots (`docs/contracts.md`, "Fixed-root purge boundary"). Each is
/// `(section, key)`; the reported field name is `section.key`.
const EXTERNAL_PATH_FIELDS: [(&str, &str); 6] = [
    ("daemon", "model_dir"),
    ("storage", "db_path"),
    ("encryption", "key_path"),
    ("encryption", "sealed_key_path"),
    ("audit", "path"),
    ("snapshots", "dir"),
];

/// One classification pass over a parsed configuration document.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ConfigFindings {
    /// `(field, raw path)` for every configured value outside the roots.
    pub external: Vec<(String, String)>,
    /// Reasons the document could not be fully classified.
    pub notes: Vec<String>,
}

/// Classify the raw bytes of `config.toml`.
pub(crate) fn classify_config(raw: &[u8]) -> ConfigFindings {
    let mut findings = ConfigFindings::default();
    let Ok(text) = std::str::from_utf8(raw) else {
        findings
            .notes
            .push("configuration is not valid UTF-8".to_string());
        return findings;
    };
    let table: toml::Table = match toml::from_str(text) {
        Ok(table) => table,
        Err(_) => {
            findings
                .notes
                .push("configuration is not valid TOML".to_string());
            return findings;
        }
    };
    for (section, key) in EXTERNAL_PATH_FIELDS {
        let field = format!("{section}.{key}");
        let Some(section_value) = table.get(section) else {
            continue;
        };
        let Some(section_table) = section_value.as_table() else {
            findings.notes.push(format!("unsupported {section} table"));
            continue;
        };
        let Some(value) = section_table.get(key) else {
            continue;
        };
        let Some(path) = value.as_str() else {
            findings.notes.push(format!("unsupported {field} value"));
            continue;
        };
        if !is_compiled_path(path) {
            findings.external.push((field, path.to_string()));
        }
    }
    findings
}

/// Lexically normalize an absolute path: collapse repeated separators, drop
/// `.`, and resolve `..` upward without touching the filesystem. Returns
/// `None` for a relative path.
pub(crate) fn normalize_absolute(path: &str) -> Option<String> {
    if !path.starts_with('/') {
        return None;
    }
    let mut parts: Vec<&str> = Vec::new();
    for part in path.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop();
            }
            other => parts.push(other),
        }
    }
    Some(format!("/{}", parts.join("/")))
}

/// Whether a configured path lies inside one of the compiled purge roots.
/// Classification is lexical only — the engine never resolves a configured
/// path on disk, so a symlink cannot drag classification outside the roots.
pub(crate) fn is_compiled_path(path: &str) -> bool {
    let Some(normalized) = normalize_absolute(path) else {
        return false;
    };
    super::PURGE_ROOTS.iter().any(|root| {
        normalized == *root
            || normalized
                .strip_prefix(root)
                .is_some_and(|rest| rest.starts_with('/'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_dot_and_dotdot() {
        assert_eq!(
            normalize_absolute("/var/lib/facelock/./db").as_deref(),
            Some("/var/lib/facelock/db")
        );
        assert_eq!(
            normalize_absolute("/var/lib/facelock/../../etc/shadow").as_deref(),
            Some("/var/etc/shadow")
        );
        assert_eq!(
            normalize_absolute("/var/lib/facelock/../../../etc/shadow").as_deref(),
            Some("/etc/shadow")
        );
        assert_eq!(
            normalize_absolute("//etc///facelock/").as_deref(),
            Some("/etc/facelock")
        );
        assert_eq!(normalize_absolute("/../..").as_deref(), Some("/"));
        assert_eq!(normalize_absolute("relative/path"), None);
    }

    #[test]
    fn compiled_path_requires_component_boundary() {
        assert!(is_compiled_path("/var/lib/facelock"));
        assert!(is_compiled_path("/var/lib/facelock/facelock.db"));
        assert!(is_compiled_path("/etc/facelock/sub/../key"));
        // Escapes and lookalike prefixes are external.
        assert!(!is_compiled_path("/var/lib/facelock/../../etc/shadow"));
        assert!(!is_compiled_path("/var/lib/facelock-evil/db"));
        assert!(!is_compiled_path("/srv/facelock/db"));
        assert!(!is_compiled_path("relative"));
    }

    #[test]
    fn classifies_external_and_internal_paths() {
        let findings = classify_config(
            br#"
[daemon]
model_dir = "/srv/models"

[storage]
db_path = "/var/lib/facelock/facelock.db"

[encryption]
key_path = "/var/lib/facelock/../../root/key"
sealed_key_path = "/etc/facelock/sealed.key"

[audit]
path = "relative/audit.jsonl"
"#,
        );
        assert!(findings.notes.is_empty());
        assert_eq!(
            findings.external,
            vec![
                ("daemon.model_dir".to_string(), "/srv/models".to_string()),
                (
                    "encryption.key_path".to_string(),
                    "/var/lib/facelock/../../root/key".to_string()
                ),
                ("audit.path".to_string(), "relative/audit.jsonl".to_string()),
            ]
        );
    }

    #[test]
    fn missing_sections_and_keys_are_silent() {
        let findings = classify_config(b"[camera]\ndevice = \"auto\"\n");
        assert!(findings.external.is_empty());
        assert!(findings.notes.is_empty());
    }

    #[test]
    fn dotted_and_inline_syntax_is_classified_by_the_real_parser() {
        // The Perl reference reports these as unclassifiable; the real parser
        // handles them, which is a strictly stronger guarantee.
        let findings = classify_config(b"storage.db_path = \"/srv/db\"\n");
        assert_eq!(
            findings.external,
            vec![("storage.db_path".to_string(), "/srv/db".to_string())]
        );
        let findings = classify_config(b"storage = { db_path = \"/srv/db2\" }\n");
        assert_eq!(
            findings.external,
            vec![("storage.db_path".to_string(), "/srv/db2".to_string())]
        );
    }

    #[test]
    fn invalid_documents_are_unclassifiable() {
        let findings = classify_config(b"\xff\xfe not utf8");
        assert_eq!(findings.notes, vec!["configuration is not valid UTF-8"]);
        let findings = classify_config(b"[unterminated\n");
        assert_eq!(findings.notes, vec!["configuration is not valid TOML"]);
    }

    #[test]
    fn wrong_typed_fields_are_noted() {
        let findings = classify_config(b"[storage]\ndb_path = 5\n");
        assert_eq!(findings.notes, vec!["unsupported storage.db_path value"]);
        let findings = classify_config(b"audit = 5\n");
        assert_eq!(findings.notes, vec!["unsupported audit table"]);
    }
}
