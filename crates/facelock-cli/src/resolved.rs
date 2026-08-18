//! Parsed vs resolved configuration (D7).
//!
//! Two different questions, two types:
//!
//! - [`ConfigLoad`] — **what the file says.** `main` performs the one read and
//!   parse for the process and hands every command a `&Config`. Commands do
//!   not re-read the file mid-flow; the deliberate exceptions each carry a
//!   comment at their load site (`daemon` reloads on mtime change, `auth` is
//!   its own one-shot process, `setup` bootstraps and edits the file,
//!   `config` displays/edits the file itself, `is-enrolled` tolerates a
//!   missing config on its unprivileged path, and `pam` — dispatched ahead of
//!   this read — takes the default `[pam] config_dirs` when the file is
//!   missing or broken, so an unrelated config mistake cannot stop an
//!   operator repairing an auth stack).
//!
//! - [`Fact`] — **what is actually true.** A config value like
//!   `execution_provider = "cuda"` or `device.path = "/dev/video2"` is a
//!   *claim*; whether CUDA exists in the installed ONNX Runtime or the device
//!   node is present is discovered by an explicit probe ([`ModelFiles`],
//!   [`CameraPresence`], [`ExecutionProviderFact`]) instead of being
//!   re-derived ad hoc at each use site. Each probe here is infallible and
//!   returns its value plainly; commands call the one whose answer they
//!   consume, and `status` gathers all of them into `health::Health`, where
//!   each is lifted into a [`Fact`] — the type that can also say *unknown*.
//!
//! # `is-enrolled` never comes here
//!
//! `is-enrolled` is dispatched in `main` *before* [`ConfigLoad::read`] runs
//! and must never construct any resolution machinery: no bus, no camera, no
//! store, no probes. See the module docs in `commands/is_enrolled.rs`; a
//! source-level pin lives in this module's tests.

use std::path::{Path, PathBuf};

use facelock_core::Config;
use facelock_core::config::ConfigError;
use facelock_face::ProviderKind;

/// The outcome of the process's single config read.
///
/// Carries the failure instead of unwrapping it so `status` can render a
/// broken config file as a finding; every other command goes through
/// [`ConfigLoad::require`], which is the one place load errors are worded.
pub struct ConfigLoad {
    /// The path that was read (after any `--config` override).
    pub path: PathBuf,
    pub result: Result<Config, ConfigError>,
}

impl ConfigLoad {
    /// Read and parse the config file once, from the process's resolved path.
    pub fn read() -> Self {
        Self::read_from(facelock_core::paths::config_path())
    }

    fn read_from(path: PathBuf) -> Self {
        let result = Config::load_from(&path);
        ConfigLoad { path, result }
    }

    /// The parsed config, or the unified load error (D7 item 4): missing file
    /// points at `facelock setup`; a broken file names the path and the parse
    /// error. Every command that needs a config fails through here, so the
    /// wording cannot drift per command. The error's Display terminates on
    /// stderr, so it renders through the message seam (D10).
    pub fn require(self) -> anyhow::Result<Config> {
        use crate::message::{AccessMessage, fail};
        match self.result {
            Ok(config) => Ok(config),
            Err(ConfigError::NotFound(_)) => Err(fail(AccessMessage::NoConfigFile {
                path: self.path.display().to_string(),
            })),
            Err(e) => Err(fail(AccessMessage::InvalidConfig {
                path: self.path.display().to_string(),
                error: e.to_string(),
            })),
        }
    }

    /// Borrow the config when it parsed; `None` otherwise. For renderers
    /// (`status`) that degrade instead of failing.
    pub fn config(&self) -> Option<&Config> {
        self.result.as_ref().ok()
    }
}

// ---------------------------------------------------------------------------
// Facts — what is actually true
// ---------------------------------------------------------------------------

/// A fact as `status` reports it: known — with a note on whether it was
/// verified — or honestly unknown (H8).
///
/// One type, one level of nesting. The arm a plain value cannot express is
/// [`Fact::Unknown`]: *the probe could not determine the answer*. The domain
/// map (§5) sketched `Unavailable { needs: Privilege }`; DEC-6 collapsed the
/// privilege tiers (`status` is root, `is-enrolled` never comes here), so what
/// is left of N4 is probe failure — an unreadable database, a config that did
/// not parse — and the honest payload is the reason, not a privilege level.
///
/// The discipline it enforces sits in the renderer: a [`Fact::Unknown`] value
/// must never render as a guessed answer. "The database could not be read" is
/// a distinct value from "this user has no models".
///
/// [`Probed`](Fact::Probed) vs [`Claimed`](Fact::Claimed) is a note, not a
/// branch. No renderer distinguishes them and no control flow turns on them;
/// the one machine-facing reader is `backend`'s `backend selected` trace,
/// which prints the fact's `Debug`. It is a variant name rather than a
/// separate `Provenance` field precisely so it stays free to carry and cannot
/// grow back into a second level of nesting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Fact<T> {
    /// Verified against the live system by this process (file stat, ORT
    /// query, D-Bus round trip).
    Probed(T),
    /// Taken from the config without verification — a claim, not a checked
    /// fact.
    Claimed(T),
    /// Not an error and NOT a false answer: the probe could not determine
    /// the value. `why` says what stood in the way.
    Unknown { why: String },
}

impl<T> Fact<T> {
    /// A fact verified against the live system.
    ///
    /// Spelled lower-case beside [`Fact::unknown`], which has to be a
    /// function because its variant holds an owned `String`; construction
    /// sites then read alike whichever arm they build.
    pub fn probed(value: T) -> Self {
        Fact::Probed(value)
    }

    /// A fact taken from configuration without verification.
    pub fn claimed(value: T) -> Self {
        Fact::Claimed(value)
    }

    pub fn unknown(why: impl Into<String>) -> Self {
        Fact::Unknown { why: why.into() }
    }

    /// The value, when it is known.
    ///
    /// Deliberately `Option`: callers that need an answer either handle the
    /// `None` or say "unknown". Folding it into a `bool` with a default —
    /// `fact.known().is_some_and(..)` — is how an unestablished fact turns
    /// into a confident false, which is the one thing this type exists to
    /// prevent.
    pub fn known(&self) -> Option<&T> {
        match self {
            Fact::Probed(value) | Fact::Claimed(value) => Some(value),
            Fact::Unknown { .. } => None,
        }
    }
}

/// One file the config names, and whether it is on disk.
#[derive(Debug, Clone)]
pub struct ProbedFile {
    pub path: PathBuf,
    pub present: bool,
}

impl ProbedFile {
    fn probe(path: PathBuf) -> Self {
        let present = path.is_file();
        ProbedFile { path, present }
    }
}

/// Presence of the configured detector/embedder ONNX files.
///
/// Presence only, by design: content integrity stays where it already lives —
/// `FaceEngine` verifies SHA256 at load time, and setup's download flow
/// checks hashes as part of its repair loop.
#[derive(Debug, Clone)]
pub struct ModelFiles {
    pub dir: PathBuf,
    pub dir_present: bool,
    pub detector: ProbedFile,
    pub embedder: ProbedFile,
}

impl ModelFiles {
    pub fn probe(config: &Config) -> ModelFiles {
        let dir = PathBuf::from(&config.daemon.model_dir);
        ModelFiles {
            dir_present: dir.is_dir(),
            detector: ProbedFile::probe(dir.join(&config.recognition.detector_model)),
            embedder: ProbedFile::probe(dir.join(&config.recognition.embedder_model)),
            dir,
        }
    }

    pub fn all_present(&self) -> bool {
        self.detector.present && self.embedder.present
    }

    /// Paths of the configured model files that are not on disk.
    pub fn missing(&self) -> Vec<&Path> {
        [&self.detector, &self.embedder]
            .into_iter()
            .filter(|f| !f.present)
            .map(|f| f.path.as_path())
            .collect()
    }
}

/// What the config claims about the camera, resolved as far as a presence
/// check can take it.
///
/// Only "does the configured node exist" — which is what `status` and setup
/// were each re-deriving. Full device interrogation (formats, IR
/// classification, quirks, siblings) is the camera domain's job (D8,
/// `direct::resolve_camera_device` and friends) and is *not* duplicated here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CameraPresence {
    /// No path configured: there is no node to stat, so detection is deferred
    /// to open time.
    AutoDetect,
    Configured {
        path: String,
        present: bool,
    },
}

impl CameraPresence {
    pub fn probe(config: &Config) -> CameraPresence {
        match config.device.path.as_deref() {
            None => CameraPresence::AutoDetect,
            Some(path) => CameraPresence::Configured {
                path: path.to_string(),
                present: Path::new(path).exists(),
            },
        }
    }
}

/// The configured execution provider, resolved against the ONNX Runtime that
/// is actually installed — availability is a property of the ORT *build*, not
/// the hardware (see `facelock_face::detect_execution_provider`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionProviderFact {
    pub configured: String,
    pub status: EpStatus,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpStatus {
    /// Not a name the provider registry knows; engine load will fail with the
    /// registry's error naming the valid values.
    UnknownName,
    /// The installed ONNX Runtime can use it (CPU is available by
    /// construction).
    Available,
    /// A valid name, but the installed ORT was not built with it — ORT falls
    /// back to CPU silently at session creation, which is exactly the
    /// misconfiguration this fact exists to surface.
    NotBuiltIn,
    /// The ONNX Runtime shared library could not be loaded or queried.
    Unqueryable(String),
}

impl ExecutionProviderFact {
    /// Probe the installed ONNX Runtime. Loads the ORT shared library unless
    /// the configured provider is `cpu` (or unknown), so call this only on
    /// paths that will load the engine anyway or exist to diagnose (status).
    pub fn probe(config: &Config) -> ExecutionProviderFact {
        Self::status_of(&config.recognition.execution_provider, || {
            facelock_face::detect_execution_provider().map(|d| d.available)
        })
    }

    /// The decision rule, split from the ORT query so it is testable without
    /// a GPU-enabled runtime (same shape as `select_by_priority` upstream).
    fn status_of(
        configured: &str,
        detect: impl FnOnce() -> Result<Vec<ProviderKind>, String>,
    ) -> ExecutionProviderFact {
        let status = match ProviderKind::parse(configured) {
            None => EpStatus::UnknownName,
            Some(ProviderKind::Cpu) => EpStatus::Available,
            Some(kind) => match detect() {
                Ok(available) if available.contains(&kind) => EpStatus::Available,
                Ok(_) => EpStatus::NotBuiltIn,
                Err(e) => EpStatus::Unqueryable(e),
            },
        };
        ExecutionProviderFact {
            configured: configured.to_string(),
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;

    #[test]
    fn require_on_missing_file_points_at_setup() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("no config file"), "{msg}");
        assert!(msg.contains("facelock setup"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    #[test]
    fn require_on_broken_file_names_path_and_error() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[device\npath=").unwrap();

        let err = ConfigLoad::read_from(path.clone()).require().unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("invalid config"), "{msg}");
        assert!(msg.contains(&path.display().to_string()), "{msg}");
    }

    /// The ownership contract: after the one read, the `Config` value is the
    /// source of truth — commands hold `&Config` and keep working even if the
    /// file disappears, because nothing on their path re-reads it.
    #[test]
    fn parsed_config_outlives_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.toml");
        fs::write(&path, "[storage]\ndb_path = \"/srv/faces/facelock.db\"\n").unwrap();

        let config = ConfigLoad::read_from(path.clone()).require().unwrap();
        fs::remove_file(&path).unwrap();

        assert_eq!(config.storage.db_path, "/srv/faces/facelock.db");
        // A hypothetical re-read would now fail — which is exactly why
        // commands must not perform one.
        assert!(matches!(
            ConfigLoad::read_from(path).result,
            Err(ConfigError::NotFound(_))
        ));
    }

    // -----------------------------------------------------------------------
    // Facts
    // -----------------------------------------------------------------------

    fn config_with(toml: &str) -> Config {
        Config::parse(toml).expect("test config parses")
    }

    #[test]
    fn model_probe_reports_each_file_and_the_missing_set() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("det.onnx"), b"x").unwrap();

        let config = config_with(&format!(
            "[daemon]\nmodel_dir = \"{}\"\n\n[recognition]\n\
             detector_model = \"det.onnx\"\nembedder_model = \"emb.onnx\"\n",
            dir.path().display()
        ));
        let models = ModelFiles::probe(&config);

        assert!(models.dir_present);
        assert!(models.detector.present);
        assert!(!models.embedder.present);
        assert!(!models.all_present());
        assert_eq!(
            models.missing(),
            vec![dir.path().join("emb.onnx").as_path()]
        );

        fs::write(dir.path().join("emb.onnx"), b"x").unwrap();
        let models = ModelFiles::probe(&config);
        assert!(models.all_present());
        assert!(models.missing().is_empty());
    }

    #[test]
    fn model_probe_on_missing_directory_is_all_absent() {
        let config = config_with("[daemon]\nmodel_dir = \"/nonexistent/facelock-test-models\"\n");
        let models = ModelFiles::probe(&config);
        assert!(!models.dir_present);
        assert!(!models.all_present());
        assert_eq!(models.missing().len(), 2);
    }

    #[test]
    fn camera_probe_reports_auto_detect_and_node_presence() {
        // No path: nothing to stat — detection is deferred to open time.
        assert_eq!(
            CameraPresence::probe(&config_with("")),
            CameraPresence::AutoDetect
        );

        // Configured and present.
        let dir = tempfile::tempdir().unwrap();
        let node = dir.path().join("video9");
        fs::write(&node, b"").unwrap();
        assert_eq!(
            CameraPresence::probe(&config_with(&format!(
                "[device]\npath = \"{}\"\n",
                node.display()
            ))),
            CameraPresence::Configured {
                path: node.display().to_string(),
                present: true
            }
        );

        // Configured and absent.
        assert_eq!(
            CameraPresence::probe(&config_with(
                "[device]\npath = \"/dev/facelock-no-such-video\"\n",
            )),
            CameraPresence::Configured {
                path: "/dev/facelock-no-such-video".into(),
                present: false
            }
        );
    }

    #[test]
    fn ep_status_unknown_name_never_queries_ort() {
        let fact = ExecutionProviderFact::status_of("tensorrt", || {
            panic!("an unknown name must not trigger an ORT query")
        });
        assert_eq!(fact.status, EpStatus::UnknownName);
    }

    #[test]
    fn ep_status_cpu_is_available_without_querying_ort() {
        let fact =
            ExecutionProviderFact::status_of("cpu", || panic!("cpu must not trigger an ORT query"));
        assert_eq!(fact.status, EpStatus::Available);
    }

    #[test]
    fn ep_status_gpu_resolves_against_the_ort_build() {
        let cuda_in = ExecutionProviderFact::status_of("cuda", || Ok(vec![ProviderKind::Cuda]));
        assert_eq!(cuda_in.status, EpStatus::Available);

        let cuda_out = ExecutionProviderFact::status_of("cuda", || Ok(vec![]));
        assert_eq!(cuda_out.status, EpStatus::NotBuiltIn);

        let rocm_elsewhere =
            ExecutionProviderFact::status_of("rocm", || Ok(vec![ProviderKind::Cuda]));
        assert_eq!(rocm_elsewhere.status, EpStatus::NotBuiltIn);

        let broken = ExecutionProviderFact::status_of("cuda", || Err("no dylib".into()));
        assert_eq!(broken.status, EpStatus::Unqueryable("no dylib".into()));
    }

    // -----------------------------------------------------------------------
    // Structural pins (source scan)
    // -----------------------------------------------------------------------
    //
    // These read the crate's own sources at test time. They are blunt — a
    // token count cannot prove call-graph properties — but they turn "parse
    // once" and "is-enrolled probes nothing" from conventions into failures
    // with a file name attached. Comment lines are ignored so prose may
    // mention the tokens.

    fn source_files() -> Vec<(PathBuf, String)> {
        fn walk(dir: &std::path::Path, out: &mut Vec<(PathBuf, String)>) {
            for entry in fs::read_dir(dir).unwrap().flatten() {
                let path = entry.path();
                if path.is_dir() {
                    walk(&path, out);
                } else if path.extension().is_some_and(|e| e == "rs") {
                    let content = fs::read_to_string(&path).unwrap();
                    out.push((path, content));
                }
            }
        }
        let mut out = Vec::new();
        walk(
            &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
            &mut out,
        );
        out
    }

    fn count_code_occurrences(content: &str, needle: &str) -> usize {
        content
            .lines()
            .filter(|l| !l.trim_start().starts_with("//"))
            .map(|l| l.matches(needle).count())
            .sum()
    }

    /// Parse-once pin. `Config::load()` (the global-path read) is allowed only
    /// at the sites below, each of which documents why it re-reads. Adding one
    /// anywhere else re-introduces the 29-call-site sprawl D7 removed — route
    /// the command through the `&Config` that `main` already parsed.
    #[test]
    fn config_load_call_sites_are_pinned() {
        let allowed: &[(&str, usize)] = &[
            // One-shot auth process: its own top-of-process parse.
            ("commands/auth.rs", 1),
            // Daemon startup + mtime-triggered reload both go through
            // build_handler.
            ("commands/daemon.rs", 1),
            // is-enrolled's tolerant read: must answer even with no config.
            ("commands/enrollment_marker.rs", 1),
            // Bootstrap: load-or-create-default, in both wizard and
            // non-interactive entry points (2 sites x 2 calls).
            ("commands/setup.rs", 4),
        ];

        // Assembled at runtime so this test's own literals don't count.
        let needle = format!("Config::load{}", "()");
        for (path, content) in source_files() {
            let rel = path
                .to_string_lossy()
                .split("/src/")
                .last()
                .unwrap()
                .to_string();
            let count = count_code_occurrences(&content, &needle);
            let expected = allowed
                .iter()
                .find(|(p, _)| *p == rel)
                .map(|(_, n)| *n)
                .unwrap_or(0);
            assert_eq!(
                count, expected,
                "{rel}: found {count} global-path config read(s) ({needle}), \
                 expected {expected}. Commands receive &Config from main (see \
                 resolved::ConfigLoad); a mid-command re-read is a D7 regression."
            );
        }
    }

    /// The same pin, for the spelling that walks around it. `Config::load()`
    /// is not the only way to re-read the global config file: `Config::
    /// load_from(paths::config_path())` does exactly the same thing, and it
    /// is the *natural* thing to write, since `ConfigLoad::read_from` models
    /// that shape. Two pins, because the bypass has two shapes:
    ///
    /// 1. Composed on one line — allowed nowhere. `ConfigLoad::read` is the
    ///    one canonical global read, and it spells the two halves separately.
    /// 2. Named at all — allowed only in the files below. This is per-file
    ///    rather than per-count so that setup's config *writes* can come and
    ///    go freely, while a brand-new file that starts reaching for the
    ///    global path still has to be a decision someone makes here.
    #[test]
    fn global_config_path_reads_are_pinned() {
        // Files that may legitimately name the global config path.
        let allowed_to_name_global_path: &[&str] = &[
            // The canonical read itself.
            "resolved.rs",
            // `facelock config` edits the file, so it must address it.
            "commands/config.rs",
            // Reload trigger: stats the file's mtime (does not parse it).
            "commands/daemon.rs",
            // Bootstrap writes the file into existence, plus its tests.
            "commands/setup.rs",
        ];

        // Assembled at runtime so this test's own prose does not count.
        let global_path = format!("config_path{}", "()");
        let load_from = format!("load_from{}", "(");

        for (path, content) in source_files() {
            let rel = path
                .to_string_lossy()
                .split("/src/")
                .last()
                .unwrap()
                .to_string();

            for line in content
                .lines()
                .filter(|l| !l.trim_start().starts_with("//"))
            {
                assert!(
                    !(line.contains(&global_path) && line.contains(&load_from)),
                    "{rel}: `load_from` applied directly to the global config \
                     path re-reads what main already parsed — the D7 \
                     regression under a different spelling. Take the &Config \
                     the command is given.\n  {}",
                    line.trim()
                );
            }

            if count_code_occurrences(&content, &global_path) > 0 {
                assert!(
                    allowed_to_name_global_path.contains(&rel.as_str()),
                    "{rel}: names the global config path ({global_path}), which \
                     only the files that read or write the file itself may do. \
                     Commands receive &Config from main (see \
                     resolved::ConfigLoad)."
                );
            }
        }
    }

    /// The third spelling of the same question: [`ConfigLoad::read`] itself.
    ///
    /// `Config::load()` and `load_from(config_path())` are pinned above, and
    /// neither matches the canonical read — so a command that reaches for
    /// `ConfigLoad::read()` passes both pins silently, which is exactly what
    /// happened when `pam` grew a config read of its own. Per file, with the
    /// reason beside it, so the next one is a decision someone makes here.
    #[test]
    fn canonical_config_reads_are_pinned() {
        let allowed: &[(&str, &str)] = &[
            // The one read for the process (D7).
            ("main.rs", "the parse every other command consumes"),
            // Dispatched ahead of main's parse and must survive a missing or
            // broken file: `[pam] config_dirs` decides where a service name
            // resolves, and the default list is the answer when the read
            // fails. See `commands::pam::PamDirs::system`.
            ("commands/pam.rs", "the PAM search path, best-effort"),
        ];

        // Assembled at runtime so this test's own prose does not count.
        let needle = format!("ConfigLoad::read{}", "(");
        for (path, content) in source_files() {
            let rel = path
                .to_string_lossy()
                .split("/src/")
                .last()
                .unwrap()
                .to_string();
            if count_code_occurrences(&content, &needle) == 0 {
                continue;
            }
            assert!(
                allowed.iter().any(|(p, _)| *p == rel),
                "{rel}: reads the config through {needle}), which only the \
                 files listed in this test may do. Commands receive &Config \
                 from main (see resolved::ConfigLoad); a second read is a D7 \
                 exception and belongs in that list with its reason."
            );
        }
    }

    /// `is-enrolled` isolation pin: its module must not name the resolution
    /// machinery or any transport/store entry point. This guarantees only that
    /// the module itself stays clean — indirect calls would need a reviewer —
    /// but every past regression started with one of these tokens appearing
    /// here.
    #[test]
    fn is_enrolled_module_stays_probe_free() {
        let forbidden = [
            "ConfigLoad",
            "resolved::",
            "send_request(",
            "Backend::select(",
            "backend::",
            "open_store",
            "Camera",
        ];
        let (_, content) = source_files()
            .into_iter()
            .find(|(p, _)| p.ends_with("commands/is_enrolled.rs"))
            .expect("is_enrolled.rs must exist");
        for token in forbidden {
            assert_eq!(
                count_code_occurrences(&content, token),
                0,
                "is_enrolled.rs must not reference {token:?} — it is dispatched \
                 before all resolution machinery and probes nothing (domain map §5)"
            );
        }
    }
}
