//! `man/pam_facelock.8` describes the module that shipped (#211).
//!
//! `man/facelock.1` has been pinned since #172. Its sibling never was: nothing
//! in the tree embedded `pam_facelock.8`, read it, or asserted anything about
//! it, so it drifted for as long as it has existed. By the time this suite was
//! written it documented a `[pam]` configuration table the module has never
//! read, three keys under it that do not exist, a `facelock` group that ADR
//! 010 retired, and three of the four exit codes the module can return.
//!
//! Every check here resolves against something that decides behaviour rather
//! than against prose:
//!
//! - the return codes, the configuration schema, the config path and the
//!   one-shot binary come from `crates/pam-facelock/src/lib.rs`, which is the
//!   only reader of any of them;
//! - the module's install locations come from [`PAM_MODULE_PATHS`], the one
//!   list `setup` and `health` already share;
//! - the D-Bus grants come from `dbus/org.facelock.Daemon.conf`, the policy
//!   the bus actually enforces;
//! - the shipped file locations come from `dist/PKGBUILD`, which writes them;
//! - the defaults quoted in prose come from `facelock_core`'s `Config`.
//!
//! The PAM module is `crate-type = ["cdylib"]` and forbidden from depending on
//! `facelock-core`, so this crate cannot `use` its constants: it reads the
//! source text instead. Every extractor here therefore carries a floor
//! assertion — an extractor that stops finding anything must fail loudly
//! rather than approve a page it never read.

use std::collections::BTreeSet;

use clap::Parser;

use facelock_cli::commands::pam::PAM_MODULE_PATHS;
use facelock_core::config::{RateLimitConfig, SecurityConfig};
use facelock_core::dbus_interface::BUS_NAME;
use facelock_core::paths::{DEFAULT_CONFIG_PATH, DEFAULT_DB_PATH};

use super::unescape_roff;
use crate::Cli;

/// The page under test.
const MAN_PAGE: &str = include_str!("../../../../man/pam_facelock.8");

/// The module the page describes. Read as text, not linked: the PAM crate is a
/// `cdylib` with a hard dependency ceiling, so its constants cannot be
/// imported from here.
const PAM_SOURCE: &str = include_str!("../../../../crates/pam-facelock/src/lib.rs");

/// The bus policy the daemon ships. What it grants is what the page may claim.
const DBUS_POLICY: &str = include_str!("../../../../dbus/org.facelock.Daemon.conf");

/// The Arch package recipe, used only as the authority on where a shipped file
/// lands. Any of the three packaging manifests would do; this is the one that
/// spells absolute paths rather than macros.
const PKGBUILD: &str = include_str!("../../../../dist/PKGBUILD");

/// The body of one `.SH` section, ending at the next one.
fn man_section(heading: &str) -> String {
    let page = unescape_roff(MAN_PAGE);
    let start = page
        .find(heading)
        .unwrap_or_else(|| panic!("man/pam_facelock.8 has no `{heading}` section"));
    let body = &page[start + heading.len()..];
    match body.find("\n.SH ") {
        Some(end) => body[..end].to_string(),
        None => body.to_string(),
    }
}

/// Every `.I` or `.B` argument in a section, one per line, unwrapped from its
/// roff macro.
fn macro_arguments(section: &str, macros: &[&str]) -> Vec<String> {
    section
        .lines()
        .filter_map(|line| {
            macros
                .iter()
                .find_map(|name| line.strip_prefix(&format!("{name} ")))
                .map(|rest| rest.trim().to_string())
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Return values
// ---------------------------------------------------------------------------

/// The PAM result codes the module can hand back to libpam.
///
/// Two filters, and the second is the point. Every `PAM_*` constant is
/// declared the same way, but `PAM_TEXT_INFO` is a conversation message style
/// and `PAM_CONV` is an item type — documenting those under RETURN VALUES
/// would be wrong. A constant counts as a result code when the source
/// *returns* it: named in a `return`, or standing alone as a tail expression.
fn pam_return_codes() -> BTreeSet<String> {
    let declared: Vec<&str> = PAM_SOURCE
        .lines()
        .filter_map(|line| {
            let rest = line.strip_prefix("const PAM_")?;
            let name = rest.split(':').next()?;
            rest.contains("libc::c_int").then_some(name)
        })
        .collect();

    assert!(
        declared.len() >= 4,
        "found only {} top-level `const PAM_*: libc::c_int` declarations in \
         crates/pam-facelock/src/lib.rs — the extractor is broken, not the module",
        declared.len()
    );

    let returned: BTreeSet<String> = declared
        .into_iter()
        .map(|name| format!("PAM_{name}"))
        .filter(|name| {
            PAM_SOURCE.contains(&format!("return {name};"))
                || PAM_SOURCE.lines().any(|line| line.trim() == name.as_str())
        })
        .collect();

    for required in ["PAM_SUCCESS", "PAM_AUTH_ERR", "PAM_IGNORE"] {
        assert!(
            returned.contains(required),
            "`{required}` is a result code the module certainly returns; the \
             return-position filter no longer recognises it"
        );
    }
    returned
}

/// Every result code the module can return is documented.
///
/// `PAM_AUTHINFO_UNAVAIL` was the one that was not. It is what the module
/// returns when the daemon answered but could not decide — the code that tells
/// a stack to fall through to the next module — and an administrator writing a
/// `[success=… default=…]` control field was reading a page that said it could
/// not happen.
#[test]
fn pam_man_documents_every_return_code() {
    let section = man_section("\n.SH RETURN VALUES\n");
    for code in pam_return_codes() {
        assert!(
            macro_arguments(&section, &[".B", ".BR"]).contains(&code),
            "`pam_facelock.so` can return `{code}` but the RETURN VALUES \
             section of man/pam_facelock.8 never names it"
        );
    }
}

/// Nothing is documented as a result code that the module cannot return.
#[test]
fn pam_man_invents_no_return_code() {
    let section = man_section("\n.SH RETURN VALUES\n");
    let codes = pam_return_codes();
    for documented in macro_arguments(&section, &[".B", ".BR"]) {
        if !documented.starts_with("PAM_") {
            continue;
        }
        assert!(
            codes.contains(&documented),
            "man/pam_facelock.8 documents `{documented}` as a return value, \
             but crates/pam-facelock/src/lib.rs never returns it"
        );
    }
}

/// The OPTIONS section matches the module arguments the module parses.
///
/// It parses none: `pam_sm_authenticate` binds its argument vector as `_argv`
/// and never reads it. That is worth saying, because every neighbouring module
/// in a stack takes arguments — an administrator who writes
/// `pam_facelock.so timeout=10` gets no error and no effect, and the timeout
/// they wanted is a configuration key.
///
/// Two-way, so the section cannot quietly become wrong in either direction: if
/// the module starts parsing `argv`, an OPTIONS section that documents nothing
/// fails.
#[test]
fn pam_man_options_match_the_arguments_the_module_parses() {
    let parses_arguments = PAM_SOURCE.contains("\n    argv:");
    let documented = macro_arguments(&man_section("\n.SH OPTIONS\n"), &[".B", ".BR"]);

    assert_eq!(
        parses_arguments,
        !documented.is_empty(),
        "crates/pam-facelock/src/lib.rs {} a module argument vector, but the \
         OPTIONS section of man/pam_facelock.8 documents {documented:?}",
        if parses_arguments {
            "parses"
        } else {
            "ignores"
        }
    );
}

// ---------------------------------------------------------------------------
// Configuration schema
// ---------------------------------------------------------------------------

/// Every `(table, key)` the module deserializes, tables dotted.
///
/// Walks `PamConfig` the way serde does: a field whose type is another
/// `Pam…Config` struct is a nested table *and* a key of its parent, and
/// anything else is a leaf key. `Option<…>` is unwrapped, since an optional
/// table is still a table.
fn pam_config_schema() -> BTreeSet<(String, String)> {
    let mut schema = BTreeSet::new();
    walk_config_struct("PamConfig", "", &mut schema);
    assert!(
        schema.len() >= 10,
        "extracted only {} configuration keys from PamConfig — the struct \
         parser is broken, not the module",
        schema.len()
    );
    schema
}

fn walk_config_struct(type_name: &str, table: &str, out: &mut BTreeSet<(String, String)>) {
    for (field, field_type) in struct_fields(type_name) {
        if !table.is_empty() {
            out.insert((table.to_string(), field.clone()));
        }
        let inner = field_type
            .trim_start_matches("Option<")
            .trim_end_matches('>')
            .to_string();
        let nested = inner.starts_with("Pam") && inner.ends_with("Config");
        if !nested {
            continue;
        }
        let child = if table.is_empty() {
            field.clone()
        } else {
            format!("{table}.{field}")
        };
        walk_config_struct(&inner, &child, out);
    }
}

/// `(name, type)` for every field of one struct in the PAM module's source.
///
/// Field lines are exactly four spaces of indentation, an identifier, a colon
/// and a type; attribute, comment and nested-brace lines are not. The struct
/// ends at the first `}` in column zero.
fn struct_fields(type_name: &str) -> Vec<(String, String)> {
    let opening = format!("\nstruct {type_name} {{\n");
    let start = PAM_SOURCE
        .find(&opening)
        .unwrap_or_else(|| panic!("crates/pam-facelock/src/lib.rs has no `struct {type_name}`"))
        + opening.len();
    let body = &PAM_SOURCE[start..];
    let end = body.find("\n}").unwrap_or(body.len());

    body[..end]
        .lines()
        .filter_map(|line| {
            let field = line.strip_prefix("    ")?;
            if field.starts_with([' ', '#', '/', '}']) {
                return None;
            }
            let (name, rest) = field.split_once(": ")?;
            if !name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
            {
                return None;
            }
            Some((
                name.to_string(),
                rest.trim().trim_end_matches(',').to_string(),
            ))
        })
        .collect()
}

/// The `(table, key)` pairs the CONFIGURATION section documents.
///
/// The section's shape is the contract: a `.B [table]` opens a table and the
/// `.BR key` lines under it are its keys, until the next table. Nothing else
/// in the section is either, which is why `FACELOCK_CONFIG` — uppercase, and
/// on a `.B` line of its own — is not mistaken for a key.
fn documented_config_schema() -> BTreeSet<(String, String)> {
    let section = man_section("\n.SH CONFIGURATION\n");
    let mut schema = BTreeSet::new();
    let mut table: Option<String> = None;

    for argument in macro_arguments(&section, &[".B", ".BR"]) {
        for token in argument.split(',') {
            let token = token.trim();
            if let Some(name) = token.strip_prefix('[').and_then(|t| t.strip_suffix(']')) {
                table = Some(name.to_string());
                continue;
            }
            let is_key = !token.is_empty()
                && token
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_');
            if let (true, Some(current)) = (is_key, table.as_ref()) {
                schema.insert((current.clone(), token.to_string()));
            }
        }
    }
    schema
}

/// The documented configuration schema is the one the module reads — exactly.
///
/// Both directions, because both had failed. The page listed a `[pam]` table
/// with `timeout_secs`, `notification_mode` and `skip_for_ssh` under it: one
/// table that does not exist and three keys that were never spelled that way,
/// while the four tables the module does read went unmentioned. An
/// administrator following the page got a config file the module silently
/// ignored, which is the worst failure mode a security control has.
#[test]
fn pam_man_configuration_matches_what_the_module_reads() {
    let actual = pam_config_schema();
    let documented = documented_config_schema();

    for (table, key) in &actual {
        assert!(
            documented.contains(&(table.clone(), key.clone())),
            "`pam_facelock.so` reads `{table}.{key}` but the CONFIGURATION \
             section of man/pam_facelock.8 never documents it"
        );
    }
    for (table, key) in &documented {
        assert!(
            actual.contains(&(table.clone(), key.clone())),
            "man/pam_facelock.8 documents `{table}.{key}`, but \
             crates/pam-facelock/src/lib.rs does not read it — a reader who \
             sets it gets no error and no effect"
        );
    }
}

// ---------------------------------------------------------------------------
// Files
// ---------------------------------------------------------------------------

/// A `&str` constant's value from the PAM module's source.
fn pam_source_constant(name: &str) -> String {
    let needle = format!("const {name}: &str = \"");
    let start = PAM_SOURCE
        .find(&needle)
        .unwrap_or_else(|| panic!("crates/pam-facelock/src/lib.rs has no `{name}`"))
        + needle.len();
    let rest = &PAM_SOURCE[start..];
    rest[..rest.find('"').expect("an unterminated string literal")].to_string()
}

/// Every absolute path the FILES section lists is a path something in this
/// tree actually places, and every place the module can be installed is
/// listed.
///
/// The page named one module location out of the three the code probes, which
/// is the one a Fedora reader does not have: RPM installs into
/// `/usr/lib64/security`, and a page that names only `/usr/lib/security` reads
/// as "your install is broken".
#[test]
fn pam_man_files_are_places_the_tree_writes() {
    let section = man_section("\n.SH FILES\n");
    let listed: Vec<String> = macro_arguments(&section, &[".I"]);
    assert!(
        listed.len() >= 4,
        "the FILES section lists only {} paths — the extractor is broken",
        listed.len()
    );

    for path in &listed {
        let justified = path == DEFAULT_CONFIG_PATH
            || path == DEFAULT_DB_PATH
            || PAM_MODULE_PATHS.contains(&path.as_str())
            || PKGBUILD.contains(path.as_str());
        assert!(
            justified,
            "man/pam_facelock.8 lists `{path}` under FILES, but nothing in \
             this tree writes it: it is not a facelock-core path, not a \
             PAM_MODULE_PATHS entry, and dist/PKGBUILD never installs it"
        );
    }

    for module_path in PAM_MODULE_PATHS {
        assert!(
            listed.iter().any(|path| path == module_path),
            "`{module_path}` is probed by PAM_MODULE_PATHS but the FILES \
             section of man/pam_facelock.8 never names it"
        );
    }

    assert!(
        listed.iter().any(|path| path == DEFAULT_CONFIG_PATH),
        "the FILES section must name the configuration file, `{DEFAULT_CONFIG_PATH}`"
    );
}

/// The configuration path and one-shot binary the page names are the ones the
/// module compiles in.
///
/// `AUTH_BIN` is deliberately not configurable — a config-selected binary in a
/// root PAM context is the whole reason it is a constant — so the page naming
/// a different one would send an administrator looking for a file that is
/// never executed.
#[test]
fn pam_man_names_the_paths_the_module_compiles_in() {
    let page = unescape_roff(MAN_PAGE);

    let module_config = pam_source_constant("DEFAULT_CONFIG_PATH");
    assert_eq!(
        module_config, DEFAULT_CONFIG_PATH,
        "the PAM module and facelock-core disagree about the config path"
    );
    assert!(
        page.contains(&module_config),
        "man/pam_facelock.8 must name the config path the module reads, \
         `{module_config}`"
    );

    let auth_bin = pam_source_constant("AUTH_BIN");
    assert!(
        page.contains(&auth_bin),
        "man/pam_facelock.8 describes the one-shot fallback but never names \
         the binary it spawns, `{auth_bin}`"
    );

    // The module reads `DEFAULT_CONFIG_PATH` and nothing else: it never looks
    // at `FACELOCK_CONFIG`, and `facelock_core::paths::config_path` ignores it
    // for privileged processes for the same reason. The page said otherwise,
    // which is worse than a plain inaccuracy — it advertised an
    // environment-controlled input to a root PAM context that does not exist.
    //
    // Scoped to CONFIGURATION rather than the whole page: that section
    // enumerates what the module reads, which is where a reader looking to
    // point it at another file goes. SECURITY may still explain that the
    // variable is deliberately ignored here.
    let env_var = "FACELOCK_CONFIG";
    assert_eq!(
        PAM_SOURCE.contains(env_var),
        man_section("\n.SH CONFIGURATION\n").contains(env_var),
        "the CONFIGURATION section and the module disagree about whether \
         `{env_var}` selects the config path the module reads"
    );
}

// ---------------------------------------------------------------------------
// D-Bus grants
// ---------------------------------------------------------------------------

/// Methods the default (non-root) policy context is allowed to send.
fn user_grantable_methods() -> BTreeSet<String> {
    DBUS_POLICY
        .lines()
        .filter_map(|line| {
            let rest = line.trim().strip_prefix("send_member=\"")?;
            Some(rest[..rest.find('"')?].to_string())
        })
        .collect()
}

/// The page describes the access the shipped policy actually grants.
///
/// It described the policy that was retired: "deny-all default, restricting
/// access to root and members of the `facelock` group". ADR 010 removed the
/// group entirely and opened exactly one method to every local user, which is
/// what lets a screen locker unlock without a group membership. A reader of
/// the old page would add users to a group that does not exist and conclude
/// face unlock does not work for them.
#[test]
fn pam_man_dbus_section_matches_the_shipped_policy() {
    let page = unescape_roff(MAN_PAGE);
    let section = man_section("\n.SH SECURITY\n");

    assert!(
        page.contains(BUS_NAME),
        "man/pam_facelock.8 must name the bus the module connects to, `{BUS_NAME}`"
    );

    let policy_grants_a_group = DBUS_POLICY.contains("<policy group=");
    assert_eq!(
        policy_grants_a_group,
        section.contains("group"),
        "dbus/org.facelock.Daemon.conf grants nothing to a group (ADR 010 \
         retired the `facelock` group), so the SECURITY section of \
         man/pam_facelock.8 must not describe one"
    );

    let methods = user_grantable_methods();
    assert!(
        !methods.is_empty(),
        "no `send_member` grant parsed out of dbus/org.facelock.Daemon.conf — \
         the extractor is broken, not the policy"
    );
    for method in methods {
        assert!(
            section.contains(&method),
            "the shipped policy lets any local user send `{method}`, but the \
             SECURITY section of man/pam_facelock.8 never says so"
        );
    }
}

/// The defaults quoted in prose are the defaults that ship.
///
/// Numbers in a security section are the part a reader plans around, and they
/// are also the part nobody revisits when a default moves.
#[test]
fn pam_man_quotes_the_defaults_that_ship() {
    let section = man_section("\n.SH SECURITY\n");
    let rate_limit = RateLimitConfig::default();

    assert!(
        section.contains(&rate_limit.max_attempts.to_string()),
        "the SECURITY section quotes a rate limit but not the shipped default \
         of {} attempts",
        rate_limit.max_attempts
    );
    assert!(
        section.contains(&rate_limit.window_secs.to_string()),
        "the SECURITY section quotes a rate-limit window but not the shipped \
         default of {} seconds",
        rate_limit.window_secs
    );

    let require_ir = SecurityConfig::default().require_ir;
    assert!(
        section.contains(&format!("security.require_ir={require_ir}")),
        "the SECURITY section must state the shipped `security.require_ir` \
         default, which is `{require_ir}`"
    );
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

/// Every `facelock …` line in a `.nf` block, as argv.
fn documented_invocations() -> Vec<Vec<String>> {
    let page = unescape_roff(MAN_PAGE);
    let mut invocations = Vec::new();
    let mut in_block = false;

    for line in page.lines() {
        match line.trim() {
            ".nf" => in_block = true,
            ".fi" => in_block = false,
            command if in_block => {
                let command = command.strip_prefix("sudo ").unwrap_or(command).trim();
                if command == "facelock" || command.starts_with("facelock ") {
                    invocations.push(command.split_whitespace().map(str::to_string).collect());
                }
            }
            _ => {}
        }
    }
    invocations
}

/// The page's own examples parse, and none of them installs into a service
/// that would refuse them.
///
/// The same promise `docs_cli_examples_all_parse` makes for the markdown
/// references, made for the page an administrator reaches with `man 8
/// pam_facelock`. Both halves matter: `docs/cli.md` once documented
/// `setup --pam --service login`, which parses and then fails at run time on
/// the sensitive-service gate.
#[test]
fn pam_man_examples_parse_and_are_not_gated() {
    use facelock_cli::commands::pam::SENSITIVE_SERVICES;
    use facelock_cli::commands::setup::{PamPref, SetupArgs, resolve_setup_plan};

    use crate::Commands;

    let invocations = documented_invocations();
    assert!(
        !invocations.is_empty(),
        "no `facelock` example extracted from man/pam_facelock.8 — the \
         extractor is broken, not the page"
    );

    for argv in invocations {
        let rendered = argv.join(" ");
        let cli = Cli::try_parse_from(&argv)
            .unwrap_or_else(|e| panic!("`{rendered}` in man/pam_facelock.8 must parse: {e}"));

        let Commands::Setup(setup) = cli.command else {
            continue;
        };
        let plan = resolve_setup_plan(SetupArgs::from(setup));
        if plan.allow_sensitive {
            continue;
        }
        let PamPref::Install {
            service: Some(service),
            ..
        } = &plan.pam
        else {
            continue;
        };
        assert!(
            !SENSITIVE_SERVICES.contains(&service.as_str()),
            "`{rendered}` in man/pam_facelock.8 installs into the gated \
             service `{service}` without --allow-sensitive, so it fails as \
             written"
        );
    }
}
